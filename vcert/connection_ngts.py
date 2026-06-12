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

import requests

from .common import (ZoneConfig, CertField, CertificateRequest, KeyType, get_ip_address, MIME_JSON, MIME_ANY,
                     CSR_ORIGIN_SERVICE)
from .connection_cloud import CloudConnection, URLS, APPLICATION_SERVER_TYPE_ID
from .errors import (VenafiConnectionError, ServerUnexptedBehavior, ClientBadData, CertificateRequestError,
                     CertificateRenewError, VenafiError)
from .http_status import HTTPStatus
from .logger import get_child

# OAuth2 access tokens issued by Strata Cloud Manager live ~15 minutes. Refresh a little
# ahead of expiry so in-flight calls never race the boundary (mirrors Go's
# tokenBufferToExpiryWindow).
TOKEN_EXPIRY_BUFFER_SECONDS = 120
OAUTH_TOKEN_TYPE = "Bearer"  # nosec B105
DEFAULT_TOKEN_LIFESPAN_SECONDS = 900

log = get_child("connection-ngts")


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
    """

    def __init__(self, client_id, client_secret, token_url, scope=None, tsg_id=None, access_token=None, url=None,
                 http_request_kwargs=None):
        # The NGTS API base URL and token URL both differ per environment (dev/prod), including the
        # path, so neither can be hardcoded - both must be supplied by the caller.
        if not url:
            raise ClientBadData("NGTS requires the API base URL (it differs per environment)")
        if not access_token and not token_url:
            raise ClientBadData("NGTS requires the token URL (it differs per environment) "
                                "when no access_token is supplied")

        if not scope:
            if not tsg_id:
                raise ClientBadData("NGTS requires either a scope or a tsg_id")
            scope = f"tsg_id:{tsg_id}"

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
        # (e.g. https://api.sase.paloaltonetworks.com/ngts), so path segments must be allowed.
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

    # -- Out of scope for NGTS ----------------------------------------------------------------

    def get_policy(self, zone):
        raise NotImplementedError

    def set_policy(self, zone, policy_spec):
        raise NotImplementedError

    def get_version(self):
        raise NotImplementedError
