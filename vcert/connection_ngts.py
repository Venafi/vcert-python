#
# Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import requests

from .common import (ZoneConfig, CertField, CertificateRequest, KeyType, get_ip_address, MIME_JSON, MIME_ANY,
                     CSR_ORIGIN_SERVICE)
from .connection_cloud import CloudConnection, URLS, APPLICATION_SERVER_TYPE_ID
from .errors import (VenafiConnectionError, ServerUnexptedBehavior, ClientBadData, CertificateRequestError,
                     CertificateRenewError, VenafiError)
from .http_status import HTTPStatus
from .logger import get_child
from .policy.pm_cloud import build_policy_spec, build_cit_request, validate_policy_spec
from .policy.policy_spec import DEFAULT_CA

# OAuth2 access tokens issued by Strata Cloud Manager live ~15 minutes. Refresh a little
# ahead of expiry so in-flight calls never race the boundary (mirrors Go's
# tokenBufferToExpiryWindow).
TOKEN_EXPIRY_BUFFER_SECONDS = 120
OAUTH_TOKEN_TYPE = "Bearer"  # nosec B105
DEFAULT_TOKEN_LIFESPAN_SECONDS = 900

# Palo Alto Networks NGTS production API base URL. Matches Go's normalizeURL fallback behavior
# (vcert/pkg/venafi/ngts/connector.go), but uses the current production host: Go's apiURL constant
# is the stale "api.sase..." host; production is "api.strata..." - do NOT "fix" this back to sase.
DEFAULT_API_URL = "https://api.strata.paloaltonetworks.com/ngts"

# Palo Alto Networks NGTS production OAuth2 token endpoint. Defaulted (like DEFAULT_API_URL) so the
# production path needs no token URL. Non-production environments (e.g. dev) use a different FQDN and
# must override it. NOTE: Go does not default the token URL yet (validateTokenUrl requires it); this
# default is a planned-but-not-yet-upstreamed divergence we add deliberately, accepting that pointing
# the credential exchange at a fixed endpoint is a known security trade-off.
DEFAULT_TOKEN_URL = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"  # nosec B105

# Service-account credentials (client_id/client_secret) are sent to token_url via HTTP Basic auth, so
# its host is a credential sink. Every known NGTS token/API host - production and the documented
# non-production (dev) endpoints alike - lives under paloaltonetworks.com. We warn (not block) when a
# supplied token_url falls outside this suffix: it surfaces typo'd or hostile overrides that would
# leak the service-account secrets, without breaking a future legitimate host on another domain.
TRUSTED_TOKEN_HOST_SUFFIX = ".paloaltonetworks.com"  # nosec B105

# Service-account scope format. Palo Alto TSG IDs are 10-digit integers, so the scope must be
# exactly "tsg_id:<10 digits>" (mirrors Go's validateScope regex; https://pan.dev/scm/docs/scope/).
# Matched with fullmatch so the whole scope must conform - no extra digits, prefixes, or trailing
# garbage.
SCOPE_PATTERN = re.compile(r"tsg_id:[0-9]{10}")

log = get_child("connection-ngts")


def _ensure_https(url):
    """
    Force an HTTPS scheme on the OAuth token endpoint. Service-account credentials are sent to
    this URL via HTTP Basic auth, so they must never travel over cleartext: an ``http://`` URL is
    upgraded to ``https://`` (with a warning) and a scheme-less URL is assumed to be ``https://``.

    :param str url:
    :rtype: str
    """
    if url.startswith("http://"):
        log.warning("token_url uses http://; upgrading to https:// to protect service-account credentials")
        url = f"https://{url[7:]}"
    elif not url.startswith("https://"):
        url = f"https://{url}"
    _warn_if_untrusted_token_host(url)
    return url


def _warn_if_untrusted_token_host(url):
    """
    Warn when ``token_url`` points outside the trusted Palo Alto domain. ``token_url`` is where the
    service-account ``client_id``/``client_secret`` are exchanged via HTTP Basic auth, so a host
    outside :data:`TRUSTED_TOKEN_HOST_SUFFIX` (a typo'd or hostile override) would leak those
    credentials. This warns rather than blocks so a future legitimate host on another domain still
    works; the warning makes the credential sink auditable.

    :param str url:
    """
    host = (urlsplit(url).hostname or "").lower()
    if not host.endswith(TRUSTED_TOKEN_HOST_SUFFIX):
        log.warning("token_url host [%s] is outside [%s]; service-account credentials will be sent "
                    "there - verify this endpoint is trusted", host, TRUSTED_TOKEN_HOST_SUFFIX)


def _parse_ngts_zone(zone):
    """
    NGTS zones are a Certificate Issuing Template alias only - the entire zone string is the
    template name. Unlike Cloud/VaaS there is no ``Application\\CIT`` split and no Applications API.

    :param str zone:
    :rtype: str
    """
    if not zone:
        log.error("Invalid Zone. It is empty")
        raise ClientBadData("You need to specify a zone")
    return zone.strip()


class NGTSConnection(CloudConnection):
    """
    Connector for Palo Alto Networks Next-Gen Trust Security (NGTS).

    NGTS is VaaS-derived: it reuses the same ``outagedetection/v1/*`` REST endpoints as
    :class:`CloudConnection`. Only authentication and zone format differ:

    - Auth is Strata Cloud Manager OAuth2 client-credentials via a service account
      (Client ID, Client Secret, TSG ID). Resource calls carry ``Authorization: Bearer <token>``
      instead of the ``tppl-api-key`` header.
    - Zones are a Certificate Issuing Template alias only (no ``Application\\CIT`` split), and
      request payloads omit ``applicationId``.

    ``url`` is optional: when omitted it defaults to the published Palo Alto production API
    endpoint (:data:`DEFAULT_API_URL`), matching Go's ``normalizeURL`` fallback. ``token_url`` is
    likewise optional and defaults to the production OAuth2 token endpoint
    (:data:`DEFAULT_TOKEN_URL`); non-production environments must supply their own. (Go still
    requires the token URL - this default is a deliberate planned divergence.)

    Because ``token_url`` is the credential sink (service-account ``client_id``/``client_secret``
    are exchanged there via HTTP Basic auth), two safeguards guard misconfiguration without giving
    up the default: falling back to the production ``token_url`` is logged at WARNING (so a non-prod
    tenant with an unset ``token_url`` doesn't silently leak its credentials to production), and a
    ``token_url`` whose host falls outside :data:`TRUSTED_TOKEN_HOST_SUFFIX` is flagged at WARNING
    (typo'd or hostile override). Both warn rather than block.
    """

    def __init__(self, client_id, client_secret, token_url=None, scope=None, tsg_id=None, access_token=None, url=None,
                 http_request_kwargs=None):
        # url defaults to the published Palo Alto production endpoint (Go defaults the base URL
        # too); it must be defaulted before the super().__init__ call, which normalizes whatever
        # base URL it receives. token_url likewise defaults to the production OAuth2 endpoint;
        # non-production environments must override it. (Go requires the token URL - defaulting it
        # is a deliberate planned divergence.)
        url = url or DEFAULT_API_URL
        # Service-account credentials are exchanged at token_url via HTTP Basic auth, so force
        # HTTPS - never let a misconfigured http:// endpoint leak them in cleartext. Falling back to
        # the production default is logged: an unset/typo'd token_url against a non-prod tenant would
        # otherwise silently send that tenant's credentials to the production endpoint.
        if not token_url:
            log.warning("token_url not supplied; defaulting to the production endpoint [%s]. Set "
                        "token_url explicitly for non-production environments", DEFAULT_TOKEN_URL)
        token_url = _ensure_https(token_url or DEFAULT_TOKEN_URL)

        if not scope:
            if not tsg_id:
                raise ClientBadData("NGTS requires either a scope or a tsg_id")
            scope = f"tsg_id:{tsg_id}"
        # Validate the scope format (mirrors Go's validateScope); also covers tsg_id, since the
        # scope is derived from it above.
        if not SCOPE_PATTERN.fullmatch(scope):
            raise ClientBadData('scope should be in the format "tsg_id:<TSG_ID>" '
                                "(TSG IDs are 10-digit integers)")

        # CloudConnection.__init__ normalizes/verifies the base URL and sets up
        # self._http_request_kwargs. The Bearer token replaces the api-key token entirely.
        super().__init__(token=None, url=url, http_request_kwargs=http_request_kwargs)

        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._scope = scope
        self._tsg_id = tsg_id
        self._access_token = access_token
        self._token_expires = None

    def __str__(self):
        return f"[NGTS] {self._base_url}"

    def _normalize_and_verify_base_url(self):
        # Unlike Cloud (host-only), NGTS base URLs carry an environment-specific path
        # (e.g. https://api.strata.paloaltonetworks.com/ngts), so path segments must be allowed.
        u = self._base_url
        if u.startswith('http://'):
            u = f"https://{u[7:]}"
        elif not u.startswith('https://'):
            u = f"https://{u}"
        if not u.endswith("/"):
            u += "/"
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*(/[-a-zA-Z\d._~]+)*/$", u):
            raise ClientBadData
        self._base_url = u

    # -- Authentication --------------------------------------------------------------------------

    def _get_access_token(self):
        """
        Fetch an OAuth2 access token via the client-credentials grant. ``client_id``/
        ``client_secret`` are sent through HTTP Basic auth; the body carries only ``grant_type``
        and the structured ``scope`` (``tsg_id:<TSG_ID>``).

        :rtype: str
        """
        if not self._client_id or not self._client_secret:
            raise ClientBadData("client_id and client_secret are required to fetch an access token")

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'grant_type': 'client_credentials',
            'scope': self._scope,
        }
        r = requests.post(self._token_url, data=data, auth=(self._client_id, self._client_secret),
                          headers=headers, **self._http_request_kwargs)  # nosec B113
        if r.status_code != HTTPStatus.OK:
            log.error(f"Failed to obtain access token. Server status: {r.status_code}")
            raise VenafiConnectionError(f"Failed to obtain access token. Server status: {r.status_code}")

        response = r.json()
        token_type = response.get('token_type')
        if token_type != OAUTH_TOKEN_TYPE:
            log.error(f"Unexpected token type: {token_type}")
            raise ServerUnexptedBehavior(f"Unexpected token type: {token_type}")

        self._access_token = response.get('access_token')
        if not self._access_token:
            raise ServerUnexptedBehavior("Access token missing from token response")

        expires_in = response.get('expires_in', DEFAULT_TOKEN_LIFESPAN_SECONDS)
        self._token_expires = datetime.now() + timedelta(seconds=expires_in - TOKEN_EXPIRY_BUFFER_SECONDS)
        return self._access_token

    def auth(self):
        """
        Use a valid supplied access token, otherwise fetch a new one.
        """
        if not (self._access_token and self._token_is_valid()):
            self._get_access_token()
        return self._access_token

    def _token_is_valid(self):
        """
        :rtype: bool
        """
        if not self._access_token:
            return False
        # A supplied token without a known expiry is taken at face value.
        if self._token_expires is None:
            return True
        return datetime.now() < self._token_expires

    def _ensure_token(self):
        """
        Lazily (re-)fetch the access token when it is missing or near expiry and client
        credentials are available. Simpler than Go's background renewal goroutine and adequate
        for an SDK that authenticates at call time.
        """
        if self._token_is_valid():
            return
        if self._client_id and self._client_secret:
            self._get_access_token()
        elif not self._access_token:
            raise ClientBadData("No valid access token and no client credentials to obtain one")

    def _auth_headers(self, accept):
        """
        :param str accept:
        :rtype: dict[str, str]
        """
        return {
            'Authorization': f"Bearer {self._access_token}",
            'accept': accept,
            'cache-control': "no-cache",
        }

    # -- HTTP verbs (Bearer auth instead of tppl-api-key) --------------------------------------

    def _get(self, url, params=None):
        self._ensure_token()
        headers = self._auth_headers(MIME_ANY)
        r = requests.get(self._base_url + url, params=params, headers=headers,
                         **self._http_request_kwargs)  # nosec B113
        return self.process_server_response(r)

    def _post(self, url, data=None):
        self._ensure_token()
        headers = self._auth_headers(MIME_JSON)
        if isinstance(data, dict):
            r = requests.post(self._base_url + url, json=data, headers=headers,
                              **self._http_request_kwargs)  # nosec B113
        else:
            log.error(f"Unexpected client data type: {type(data)} for {url}")
            raise ClientBadData
        return self.process_server_response(r)

    def _put(self, url, data=None):
        self._ensure_token()
        headers = self._auth_headers(MIME_JSON)
        if isinstance(data, dict):
            r = requests.put(self._base_url + url, json=data, headers=headers,
                             **self._http_request_kwargs)  # nosec B113
        else:
            log.error(f"Unexpected client data type: {type(data)} for {url}")
            raise ClientBadData
        return self.process_server_response(r)

    # -- Certificate lifecycle (deltas vs Cloud) ----------------------------------------------

    def _get_cit_or_fail(self, zone):
        """
        Resolve the Certificate Issuing Template for an NGTS (CIT-only) zone via the global
        template list.

        :param str zone:
        :rtype: dict
        """
        cit = self._get_cit(_parse_ngts_zone(zone))
        if not cit:
            log.error(f"Certificate issuing template not found for zone [{zone}]")
            raise VenafiError(f"Certificate issuing template not found for zone [{zone}]")
        return cit

    def request_cert(self, request, zone):
        cit = self._get_cit_or_fail(zone)
        cit_id = cit['id']

        ip_address = get_ip_address()
        request_data = {
            'certificateIssuingTemplateId': cit_id,
            'apiClientInformation': {
                'type': request.origin,
                'identifier': ip_address
            }
        }
        zone_config = self.read_zone_conf(zone)
        request.update_from_zone_config(zone_config)

        if request.csr_origin != CSR_ORIGIN_SERVICE:
            if not request.csr:
                request.build_csr()
            request_data['certificateSigningRequest'] = request.csr
        else:
            request_data['isVaaSGenerated'] = True
            request_data['applicationServerTypeId'] = APPLICATION_SERVER_TYPE_ID
            request_data['csrAttributes'] = self._get_service_generated_csr_attr(request, zone)

        if request.validity_hours is not None:
            request_data['validityPeriod'] = f"PT{request.validity_hours}H"

        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data=request_data)
        if status == HTTPStatus.CREATED:
            request.id = data['certificateRequests'][0]['id']
            if 'certificateIds' in data['certificateRequests'][0] \
                    and len(data['certificateRequests'][0]['certificateIds']) > 0:
                request.cert_guid = data['certificateRequests'][0]['certificateIds'][0]
            return True
        else:
            log.error(f"unexpected server response {status}: {data}")
            raise CertificateRequestError

    def renew_cert(self, request, reuse_key=False):
        cert_request_id = None
        if not request.id and not request.thumbprint:
            log.error("prev_cert_id or thumbprint or manage_id must be specified for renewing certificate")
            raise ClientBadData

        if request.thumbprint:
            response = self.search_by_thumbprint(request.thumbprint)
            cert_request_id = response.csrId

        if request.id:
            cert_request_id = request.id

        prev_request = self._get_cert_status(CertificateRequest(cert_id=cert_request_id))
        certificate_id = prev_request.certificateIds[0]
        cit_id = prev_request.citId

        if not certificate_id or not cit_id:
            log.error("Can't find certificate_id")
            raise ClientBadData

        status, data = self._get(URLS.CERTIFICATE_BY_ID.format(certificate_id))
        if status == HTTPStatus.OK:
            request.id = data['certificateRequestId']
        else:
            raise ServerUnexptedBehavior

        ip_address = get_ip_address()
        d = {'existingCertificateId': certificate_id,
             'certificateIssuingTemplateId': cit_id,
             'apiClientInformation': {
                 'type': request.origin,
                 'identifier': ip_address
             }}

        if reuse_key:
            if request.csr:
                d['certificateSigningRequest'] = request.csr
                d['reuseCSR'] = False
            else:
                log.error("Certificate renew by reusing the CSR is not supported right now. "
                          "Set [reuse_key] to False or just remove it")
                raise VenafiError
        else:
            c = data
            if c.get('subjectCN'):
                request.common_name = c['subjectCN'][0]
            if c.get('subjectC'):
                request.country = c['subjectC']
            if c.get('subjectO'):
                request.organization = c['subjectO']
            if c.get('subjectOU'):
                request.organizational_unit = c['subjectOU']
            if c.get('subjectL'):
                request.locality = c['subjectL']
            if c.get('subjectAlternativeNameDns'):
                request.san_dns = c['subjectAlternativeNameDns']
            request.key_type = KeyType(KeyType.RSA, c['keyStrength'])
            request.build_csr()
            d['certificateSigningRequest'] = request.csr
            d['reuseCSR'] = False

        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data=d)
        if status == HTTPStatus.CREATED:
            request.id = data['certificateRequests'][0]['id']
            return True
        else:
            log.error(f"server unexpected status {status}")
            raise CertificateRenewError

    def read_zone_conf(self, zone):
        cit = self._get_cit_or_fail(zone)
        policy = self._parse_policy_response_to_object(cit)
        rs = policy.recommended_settings
        org = CertField("")
        org_unit = CertField("")
        locality = CertField("")
        state = CertField("")
        country = CertField("")
        if rs:
            org = CertField(rs.subjectOValue)
            org_unit = CertField(rs.subjectOUValue)
            locality = CertField(rs.subjectLValue)
            state = CertField(rs.subjectSTValue)
            country = CertField(rs.subjectCValue)

        z = ZoneConfig(
            organization=org,
            organizational_unit=org_unit,
            country=country,
            province=state,
            locality=locality,
            policy=policy,
            key_type=policy.key_types[0] if policy.key_types else None,
        )
        return z

    # -- Policy management (deltas vs Cloud) --------------------------------------------------

    def get_policy(self, zone):
        """
        Build a PolicySpecification from the NGTS Certificate Issuing Template (CIT) named by
        ``zone``. Mirrors Go's NGTS ``GetPolicy`` and Cloud's ``_get_policy`` minus the
        Application-owner resolution: NGTS has no Application layer, so there are no owners/users
        to resolve and ``users``/``owners`` stay empty (parity with Go NGTS).

        :param str zone: the CIT alias (NGTS zones are a CIT alias only - no Application\\CIT split)
        :rtype: PolicySpecification
        """
        cit_data = self._get_cit_or_fail(zone)
        cit = self._parse_policy_response_to_object(cit_data)

        info = self._get_ca_info(cit.cert_authority, cit.cert_authority_account_id,
                                 cit.cert_authority_product_option_id)
        if not info:
            raise VenafiError("Certificate Authority info not found")

        ps = build_policy_spec(cit, info, subject_cn_to_str=True)
        return ps

    def set_policy(self, zone, policy_spec):
        """
        Create or update the NGTS Certificate Issuing Template (CIT) named by ``zone`` from
        ``policy_spec``. Mirrors Go's NGTS ``SetPolicy`` and Cloud's ``set_policy`` with the
        Application create/link and owner handling removed: NGTS has no Application layer, so the
        CIT is created/updated directly on the global issuing-template endpoint and
        ``policy_spec.users`` is ignored (parity with Go NGTS).

        :param str zone: the CIT alias (NGTS zones are a CIT alias only - no Application\\CIT split)
        :param PolicySpecification policy_spec:
        """
        validate_policy_spec(policy_spec)
        cit_alias = _parse_ngts_zone(zone)

        if not policy_spec.policy:
            raise VenafiError("Policy is required")
        if not policy_spec.policy.certificate_authority:
            # Default the CA exactly as Go's NGTS SetPolicy does when none is supplied.
            policy_spec.policy.certificate_authority = DEFAULT_CA

        ca_details = self._get_ca_details(policy_spec.policy.certificate_authority)
        if not ca_details:
            raise VenafiError(f"CA [{policy_spec.policy.certificate_authority}] not found in "
                              f"Strata Cloud Manager")

        request = build_cit_request(policy_spec, ca_details)
        request['name'] = cit_alias

        cit_data = self._get_cit(cit_alias)
        if cit_data:
            # Issuing Template exists. Update
            status, _ = self._put(URLS.ISSUING_TEMPLATES_UPDATE.format(cit_data['id']), request)
            if status != HTTPStatus.OK:
                raise VenafiError(f"Failed to update issuing template [{cit_data['id']}] for zone [{zone}]")
        else:
            # Issuing Template does not exist. Create one
            status, _ = self._post(URLS.ISSUING_TEMPLATES, request)
            if status != HTTPStatus.CREATED:
                raise VenafiError(f"Failed to create issuing template for zone [{zone}]")
        return

    # -- Out of scope for NGTS ----------------------------------------------------------------

    def get_version(self):
        raise NotImplementedError
