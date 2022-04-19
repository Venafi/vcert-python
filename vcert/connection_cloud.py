#
# Copyright 2019 Venafi, Inc.
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
import base64
import re
import time

import requests
import six.moves.urllib.parse as urlparse
from nacl.public import SealedBox
from six import string_types

from .common import (ZoneConfig, CertificateRequest, CommonConnection, Policy, get_ip_address, log_errors, MIME_JSON,
                     MIME_TEXT, MIME_ANY, CertField, KeyType, DEFAULT_TIMEOUT,
                     CSR_ORIGIN_SERVICE, CHAIN_OPTION_FIRST, CHAIN_OPTION_LAST)
from .errors import (VenafiConnectionError, ServerUnexptedBehavior, ClientBadData, CertificateRequestError,
                     CertificateRenewError, VenafiError, RetrieveCertificateTimeoutError)
from .http_status import HTTPStatus
from .logger import get_child
from .pem import parse_pem, Certificate
from .policy import PolicySpecification
from .policy.pm_cloud import (build_policy_spec, validate_policy_spec, AccountDetails, build_cit_request, build_user,
                              UserDetails, build_company, build_apikey, build_app_update_request, get_ca_info,
                              CertificateAuthorityDetails, CertificateAuthorityInfo, build_account_details,
                              build_app_create_request)
from .vaas_utils import AppDetails, RecommendedSettings, EdgeEncryptionKey, zip_to_pem, value_matches_regex

TOKEN_HEADER_NAME = "tppl-api-key"  # nosec
APPLICATION_SERVER_TYPE_ID = "784938d1-ef0d-11eb-9461-7bb533ba575b"
MSG_VALUE_NOT_MATCH_POLICY = "Error while requesting certificate using service generated CSR on VaaS. " \
                             "Request {} does not match CIT valid {}:\n\tRequest value: {},\n\tCIT values: {}"

CSR_ATTR_CN = 'commonName'
CSR_ATTR_ORG = 'organization'
CSR_ATTR_ORG_UNIT = 'organizationalUnits'
CSR_ATTR_LOCALITY = 'locality'
CSR_ATTR_PROVINCE = 'state'
CSR_ATTR_COUNTRY = 'country'
CSR_ATTR_SANS_BY_TYPE = 'subjectAlternativeNamesByType'
CSR_ATTR_SANS_DNS = 'dnsNames'

log = get_child("connection-vaas")


class CertStatuses:

    REQUESTED = 'REQUESTED'
    PENDING = 'PENDING'
    FAILED = 'FAILED'
    ISSUED = 'ISSUED'


class URLS:
    def __init__(self):
        pass

    API_BASE_URL = "https://api.venafi.cloud/"
    API_VERSION = "v1/"
    API_BASE_PATH = f"outagedetection/{API_VERSION}"

    POLICIES_BY_ID = API_BASE_PATH + "certificatepolicies/{}"
    CERTIFICATE_REQUESTS = API_BASE_PATH + "certificaterequests"
    CERTIFICATE_STATUS = CERTIFICATE_REQUESTS + "/{}"
    CERTIFICATE_RETRIEVE = API_BASE_PATH + "certificates/{}/contents"
    CERTIFICATE_SEARCH = API_BASE_PATH + "certificatesearch"
    APPLICATIONS = API_BASE_PATH + "applications"
    APP_BY_ID = APPLICATIONS + "/{}"
    CERTIFICATE_TEMPLATE_BY_ID = APP_BY_ID + "/certificateissuingtemplates/{}"
    APP_DETAILS_BY_NAME = APPLICATIONS + "/name/{}"
    CERTIFICATE_BY_ID = API_BASE_PATH + "certificates/{}"
    CERTIFICATE_KEYSTORE_BY_ID = CERTIFICATE_BY_ID + "/keystore"
    CA_ACCOUNTS = API_VERSION + "certificateauthorities/{}/accounts"
    CA_ACCOUNT_DETAILS = CA_ACCOUNTS + "/{}"
    ISSUING_TEMPLATES = API_VERSION + "certificateissuingtemplates"
    ISSUING_TEMPLATES_UPDATE = ISSUING_TEMPLATES + "/{}"
    USER_ACCOUNTS = API_VERSION + "useraccounts"
    DEK_PUBLIC_KEY = API_VERSION + "edgeencryptionkeys/{}"


class CondorChainOptions:

    ROOT_FIRST = "ROOT_FIRST"
    ROOT_LAST = "EE_FIRST"


class CertificateStatusResponse:
    def __init__(self, d):
        self.status = d.get('status') or d.get("certificateStatus")
        self.subject = d.get('subjectDN') or d.get('subjectCN')[0]
        self.applicationId = d.get('applicationId')
        self.citId = d.get('certificateIssuingTemplateId')
        self.certificateIds = d.get('certificateIds') or [d.get('id')]
        self.csrId = d.get('certificateRequestId')


def _parse_zone(zone):
    if not zone:
        log.error("Invalid Zone. It is empty")
        raise ClientBadData("You need to specify a zone")
    segments = zone.split("\\")
    if len(segments) < 2 or len(segments) > 2:
        log.error("Invalid zone. Incorrect format")
        raise ClientBadData(f"Invalid Zone [{zone}]. The zone format is incorrect")

    app_name = segments[0]
    cit_alias = segments[1]
    return app_name, cit_alias


class CloudConnection(CommonConnection):
    def __init__(self, token, url=None, http_request_kwargs=None):
        super().__init__()
        self._base_url = url or URLS.API_BASE_URL
        self._token = token
        self._normalize_and_verify_base_url()
        if http_request_kwargs is None:
            http_request_kwargs = {'timeout': 180}
        elif 'timeout' not in http_request_kwargs:
            http_request_kwargs['timeout'] = 180
        self._http_request_kwargs = http_request_kwargs

    def __str__(self):
        return f"[Cloud] {self._base_url}"

    def _get(self, url, params=None):
        """

        :param url:
        :param params:
        :rtype: str or dict
        """
        headers = {
            TOKEN_HEADER_NAME: self._token,
            'accept': MIME_ANY,
            'cache-control': "no-cache"
        }
        r = requests.get(self._base_url + url, params=params, headers=headers, **self._http_request_kwargs)
        return self.process_server_response(r)

    def _post(self, url, data=None):
        """

        :param url:
        :param data:
        :rtype: str or dict
        """
        headers = {
            TOKEN_HEADER_NAME: self._token,
            'accept': MIME_JSON,
            'cache-control': "no-cache"
        }
        if isinstance(data, dict):
            r = requests.post(self._base_url + url, json=data, headers=headers, **self._http_request_kwargs)
        else:
            log.error(f"Unexpected client data type: {type(data)} for {url}")
            raise ClientBadData
        return self.process_server_response(r)

    def _put(self, url, data=None):
        """

        :param url:
        :param data:
        :rtype:str or dict
        """
        headers = {
            TOKEN_HEADER_NAME: self._token,
            'cache-control': "no-cache",
            'accept': MIME_JSON
        }
        if isinstance(data, dict):
            r = requests.put(self._base_url + url, json=data, headers=headers, **self._http_request_kwargs)
        else:
            log.error(f"Unexpected client data type: {type(data)} for {url}")
            raise ClientBadData
        return self.process_server_response(r)

    def _normalize_and_verify_base_url(self):
        u = self._base_url
        if u.startswith('http://'):
            u = f"https://{u[7:]}"
        elif not u.startswith('https://'):
            u = f"https://{u}"
        if not u.endswith("/"):
            u += "/"
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/$", u):
            raise ClientBadData
        self._base_url = u

    @staticmethod
    def _process_server_response(r):
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED):
            raise VenafiConnectionError(f"Server status: {r.status_code}, {r.request.url}")
        content_type = r.headers.get('content-type')
        if content_type == MIME_TEXT:
            log.debug(r.text)
            return r.status_code, r.text
        elif content_type == MIME_JSON:
            log.debug(r.content.decode())
            return r.status_code, r.json()
        else:
            log.error(f"unexpected content type: {content_type} for request {r.request.url}")
            raise ServerUnexptedBehavior

    def _get_cert_status(self, request):
        status, data = self._get(URLS.CERTIFICATE_STATUS.format(request.id))
        if status == HTTPStatus.OK:
            request_status = CertificateStatusResponse(data)
            return request_status
        else:
            raise ServerUnexptedBehavior

    @staticmethod
    def _parse_policy_response_to_object(d):
        policy = Policy(
            d['id'] if 'id' in d else None,
            d['companyId'] if 'companyId' in d else None,
            d['name'] if 'name' in d else None,
            d['systemGenerated'] if 'systemGenerated' in d else None,
            d['creationDate'] if 'creationDate' in d else None,
            d['subjectCNRegexes'] if 'subjectCNRegexes' in d else None,
            d['subjectORegexes'] if 'subjectORegexes' in d else None,
            d['subjectOURegexes'] if 'subjectOURegexes' in d else None,
            d['subjectSTRegexes'] if 'subjectSTRegexes' in d else None,
            d['subjectLRegexes'] if 'subjectLRegexes' in d else None,
            d['subjectCValues'] if 'subjectCValues' in d else None,
            d['sanRegexes'] if 'sanRegexes' in d else None,
            [],
            d['keyReuse'] if 'keyReuse' in d else None,
            d['certificateAuthority'] if 'certificateAuthority' in d else None,
            d['certificateAuthorityAccountId'] if 'certificateAuthorityAccountId' in d else None,
            d['certificateAuthorityProductOptionId'] if 'certificateAuthorityProductOptionId' in d else None,
            d['priority'] if 'priority' in d else None,
            d['modificationDate'] if 'modificationDate' in d else None,
            d['status'] if 'status' in d else None,
            d['reason'] if 'reason' in d else None,
            d['validityPeriod'] if 'validityPeriod' in d else None,
            None,
            d['csrUploadAllowed'] if 'csrUploadAllowed' in d else None,
            d['keyGeneratedByVenafiAllowed'] if 'keyGeneratedByVenafiAllowed' in d else None
        )
        for kt in d.get('keyTypes', []):
            key_type = kt['keyType'].lower()
            if key_type == KeyType.RSA:
                for s in kt['keyLengths']:
                    policy.key_types.append(KeyType(key_type, s))
            elif key_type == KeyType.ECDSA:
                for s in kt["keyCurves"]:
                    policy.key_types.append(KeyType(key_type, s))
            else:
                log.error(f"Unknown key type: {kt['keyType']}")
                raise ServerUnexptedBehavior

        rs = CloudConnection._parse_recommended_settings_to_object(d)
        if rs:
            policy.recommended_settings = rs

        return policy

    @staticmethod
    def _parse_recommended_settings_to_object(d):
        if 'recommendedSettings' in d:
            rs = d['recommendedSettings']
            settings = RecommendedSettings(
                rs['subjectOValue'] if 'subjectOValue' in rs else None,
                rs['subjectOUValue'] if 'subjectOUValue' in rs else None,
                rs['subjectLValue'] if 'subjectLValue' in rs else None,
                rs['subjectSTValue'] if 'subjectSTValue' in rs else None,
                rs['subjectCValue'] if 'subjectCValue' in rs else None,
                None,
                rs['keyReuse'] if 'keyReuse' in rs else None
            )
            if 'key' in rs:
                key = rs['key']
                k_type = key['type']
                kl = key['length'] if 'length' in key else None
                kc = key['curve'] if 'curve' in key else None
                kt = KeyType(k_type, kl or kc)
                settings.keyType = kt

            return settings

    def _get_template_by_id(self, zone):
        """
        Returns the Certificate Issuing Template details

        :rtype: Policy
        """
        app_name, cit_alias = _parse_zone(zone)
        status, data = self._get(URLS.CERTIFICATE_TEMPLATE_BY_ID.format(urlparse.quote(app_name),
                                                                        urlparse.quote(cit_alias)))
        if status != HTTPStatus.OK:
            log.error(f"Invalid status {status} while retrieving policy [{zone}]")
            return None
        return self._parse_policy_response_to_object(data)

    def auth(self):
        status, data = self._get(URLS.USER_ACCOUNTS)
        if status == HTTPStatus.OK:
            return data

    def _get_app_details_by_name(self, app_name):
        """
        :param str app_name:
        :rtype: AppDetails
        """
        if not app_name:
            raise ClientBadData("You need to specify the application name")
        try:
            status, data = self._get(URLS.APP_DETAILS_BY_NAME.format(urlparse.quote(app_name)))
        except VenafiConnectionError:
            return None

        if status == HTTPStatus.OK:
            return AppDetails(data['id'] if 'id' in data else None,
                              data['certificateIssuingTemplateAliasIdMap'] if 'certificateIssuingTemplateAliasIdMap'
                                                                              in data else None,
                              data['companyId'] if 'companyId' in data else None,
                              data['name'] if 'name' in data else None,
                              data['description'] if 'description' in data else None,
                              data['ownerIdsAndTypes'] if 'ownerIdsAndTypes' in data else None,
                              data['fqDns'] if 'fqDns' in data else None,
                              data['internalFqDns'] if 'internalFqDns' in data else None,
                              data['externalIpRanges'] if 'externalIpRanges' in data else None,
                              data['internalIpRanges'] if 'internalIpRanges' in data else None,
                              data['internalPorts'] if 'internalPorts' in data else None,
                              data['fullyQualifiedDomainNames'] if 'fullyQualifiedDomainNames' in data else None,
                              data['ipRanges'] if 'ipRanges' in data else None,
                              data['ports'] if 'ports' in data else None,
                              data['organizationalUnitId'] if 'organizationalUnitId' in data else None
                              )
        elif status in (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.PRECONDITION_FAILED):
            log_errors(data)

    def request_cert(self, request, zone):
        app_name, cit_alias = _parse_zone(zone)
        details = self._get_app_details_by_name(app_name)
        cit_id = details.cit_alias_id_map.get(cit_alias)

        ip_address = get_ip_address()
        request_data = {
            'applicationId': details.app_id,
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
            request.cert_guid = data['certificateRequests'][0]['certificateIds'][0]
            return True
        else:
            log.error(f"unexpected server response {status}: {data}")
            raise CertificateRequestError

    def retrieve_cert(self, request):
        cert_status = self._get_cert_status(request)
        if cert_status.status == CertStatuses.PENDING or cert_status.status == CertStatuses.REQUESTED:
            log.info(f"Certificate status is {cert_status.status}")
            return None
        elif cert_status.status == CertStatuses.FAILED:
            log.debug(f"Certificate status is {cert_status.status}. Returning data for debug")
            return "Certificate FAILED"
        elif cert_status.status == CertStatuses.ISSUED:
            request.cert_guid = cert_status.certificateIds[0]
            dek_info = self._get_dek_hash(request.cert_guid)
            if dek_info and dek_info.public_key:
                return self._retrieve_service_generated_cert(request, dek_info)

            url = URLS.CERTIFICATE_RETRIEVE.format(request.cert_guid)
            if request.chain_option == CHAIN_OPTION_FIRST:
                url += f"?chainOrder={CondorChainOptions.ROOT_FIRST}&format=PEM"
            elif request.chain_option == CHAIN_OPTION_LAST:
                url += f"?chainOrder={CondorChainOptions.ROOT_LAST}&format=PEM"
            else:
                log.error(f"chain option {request.chain_option} is not valid")
                raise ClientBadData

            # Time in seconds
            time_start = time.time()
            while True:
                try:
                    status, data = self._get(url)
                except VenafiError as e:
                    log.debug(f"Certificate with id {request.id} not found")
                    status = 0
                if status == HTTPStatus.OK:
                    log.debug("Certificate found, parsing response...")
                    cert_response = parse_pem(data, request.chain_option)
                    if cert_response.key is None and request.private_key is not None:
                        log.debug("Adding local private key to response...")
                        cert_response.key = request.private_key_pem
                    return cert_response
                elif (time.time() - time_start) < request.timeout:
                    log.debug("Waiting for certificate...")
                    time.sleep(2)
                else:
                    raise RetrieveCertificateTimeoutError(f"Operation timed out at {request.timeout} seconds "
                                                          f"while retrieving certificate with id {request.id}")
        else:
            raise ServerUnexptedBehavior

    def revoke_cert(self, request):
        # not supported in Venafi Cloud
        raise NotImplementedError

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
        app_id = prev_request.applicationId
        cit_id = prev_request.citId

        if not certificate_id or not app_id or not cit_id:
            log.error("Can't find certificate_id")
            raise ClientBadData

        status, data = self._get(URLS.CERTIFICATE_BY_ID.format(certificate_id))
        if status == HTTPStatus.OK:
            request.id = data['certificateRequestId']
        else:
            raise ServerUnexptedBehavior

        ip_address = get_ip_address()
        d = {'existingCertificateId': certificate_id,
             'applicationId': app_id,
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

    def search_by_thumbprint(self, thumbprint, timeout=DEFAULT_TIMEOUT):
        """
        :param str thumbprint:
        :param int timeout:
        :rtype CertificateStatusResponse
        """
        log.info("Searching certificate by thumbprint...")
        thumbprint = re.sub(r'[^\dabcdefABCDEF]', "", thumbprint)
        thumbprint = thumbprint.upper()

        time_start = time.time()
        while True:
            status, data = self._post(URLS.CERTIFICATE_SEARCH, data={
                'expression': {
                    'operands': [{
                        'field': "fingerprint",
                        'operator': "MATCH",
                        'value': thumbprint
                        }]
                }
            })
            if status != HTTPStatus.OK:
                raise ServerUnexptedBehavior
            elif not data.get('count'):
                if (time.time() - time_start) < timeout:
                    log.debug("Waiting for certificate...")
                    time.sleep(2)
                else:
                    raise RetrieveCertificateTimeoutError(f'Operation timed out at {timeout} seconds while retrieving '
                                                          f'certificate with thumbprint {thumbprint}')
            else:
                log.debug("Certificate found, returning...")
                return CertificateStatusResponse(data['certificates'][0])

    def read_zone_conf(self, zone):
        policy = self._get_template_by_id(zone)
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

    def import_cert(self, request):
        # not supported in Cloud
        raise NotImplementedError

    def get_policy(self, zone):
        return self._get_policy(zone=zone, subject_cn_to_str=True)

    def _policy_exists(self, zone):
        """
        :param str zone:
        :rtype: bool
        """
        try:
            cit = self._get_template_by_id(zone)
        except VenafiConnectionError:
            cit = None
        return False if cit is None else True

    def set_policy(self, zone, policy_spec):
        validate_policy_spec(policy_spec)
        app_name, cit_alias = _parse_zone(zone)

        if not policy_spec.policy.certificate_authority:
            raise VenafiError("Certificate Authority is required")

        ca_details = self._get_ca_details(policy_spec.policy.certificate_authority)
        if not ca_details:
            raise VenafiError(f"CA [{policy_spec.policy.certificate_authority}] not found in Venafi Cloud")

        # CA valid. Create request dictionary
        request = build_cit_request(policy_spec, ca_details)
        request['name'] = cit_alias
        cit_data = self._get_cit(cit_alias)
        resp_cit_data = None
        if cit_data:
            # Issuing Template exists. Update
            status, resp_cit_data = self._put(URLS.ISSUING_TEMPLATES_UPDATE.format(cit_data['id']), request)
            if status != HTTPStatus.OK:
                raise VenafiError(f"Failed to update issuing template [{cit_data['id']}] for zone [{zone}]")
        else:
            # Issuing Template does not exist. Create one
            status, resp_cit_data = self._post(URLS.ISSUING_TEMPLATES, request)
            if status != HTTPStatus.CREATED:
                raise VenafiError(f"Failed to create issuing template for zone [{zone}]")

        # Validate Application existence in Venafi Cloud.
        user_details = self._get_user_details()
        if not user_details:
            raise VenafiError('User Details not found')

        app_details = self._get_app_details_by_name(app_name)
        if app_details:
            # Application exists. Update with cit
            if not self._policy_exists(zone):
                # Only link cit with Application when cit is not already associated with Application
                app_req = build_app_update_request(app_details, resp_cit_data)
                status, data = self._put(URLS.APP_BY_ID.format(app_details.app_id), app_req)
                if status != HTTPStatus.OK:
                    raise VenafiError(f"Could not update Application [{app_name}] with cit [{resp_cit_data}]")
        else:
            # Application does not exist. Create one
            app_req = build_app_create_request(app_name, user_details, resp_cit_data)
            status, data = self._post(URLS.APPLICATIONS, app_req)
            if status != HTTPStatus.CREATED:
                raise VenafiError(f"Could not create application [{app_name}]")
        return

    def _get_ca_details(self, ca_name):
        """
        :param str ca_name:
        :rtype: CertificateAuthorityDetails
        """
        accounts, info = self._get_accounts(ca_name)
        for acc in accounts:
            if acc.account.key == info.ca_account_key:
                for po in acc.product_options:
                    if po.product_name == info.vendor_name:
                        return CertificateAuthorityDetails(po.product_id, po.details.product_template.organization_id,)

    def _get_accounts(self, ca_name):
        """
        :param str ca_name:
        :rtype: tuple[list[AccountDetails],CertificateAuthorityInfo]
        """
        details = get_ca_info(ca_name)
        ca_type = urlparse.quote(details.ca_type)
        url = URLS.CA_ACCOUNTS.format(ca_type)
        status, data = self._get(url)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior

        if 'accounts' not in data:
            raise VenafiError("Response error. Accounts not found")

        acc_list = []
        for d in data['accounts']:
            ad = build_account_details(d)
            acc_list.append(ad)

        return acc_list, details

    def _get_cit(self, cit_name):
        """
        :param str cit_name:
        :rtype: dict
        """
        status, data = self._get(URLS.ISSUING_TEMPLATES)
        if status != HTTPStatus.OK:
            raise VenafiError("Could not retrieve Certificate Issuing Templates")

        if 'certificateIssuingTemplates' in data:
            for cit_data in data['certificateIssuingTemplates']:
                if cit_data['name'] == cit_name:
                    return cit_data
        return None

    def _get_user_details(self):
        """
        :rtype: UserDetails
        """
        status, data = self._get(URLS.USER_ACCOUNTS)
        if status != HTTPStatus.OK:
            raise VenafiError(f"Failed to retrieve user accounts. Error {data}")

        user = build_user(data['user']) if 'user' in data else None
        company = build_company(data['company']) if 'company' in data else None
        apikey = build_apikey(data['apiKey']) if 'apiKey' in data else None

        return UserDetails(user, company, apikey)

    def _get_ca_info(self, name, account_id, product_option_id):
        """
        :param str name:
        :param str account_id:
        :param str product_option_id:
        :rtype: CertificateAuthorityInfo
        """
        ca_name = urlparse.quote(name)
        url = URLS.CA_ACCOUNT_DETAILS.format(ca_name, account_id)
        status, data = self._get(url)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior

        account_details = build_account_details(data)
        info = CertificateAuthorityInfo(account_details.account.certificate_authority, account_details.account.key)
        for po in account_details.product_options:
            if po.product_id == product_option_id:
                info.vendor_name = po.product_name

        return info

    def _get_service_generated_csr_attr(self, request, zone):
        """

        :param CertificateRequest request:
        :param str zone:
        :rtype: dict[str, Any]
        """
        ps = self._get_policy(zone=zone, subject_cn_to_str=False)
        csr_attr_map = {}

        if request.common_name:
            if ps.policy:
                policy_domains = ps.policy.domains
                valid = value_matches_regex(value=request.common_name, pattern_list=policy_domains)
                if not valid:
                    log.error(MSG_VALUE_NOT_MATCH_POLICY.format("Common Name", "domains", request.common_name,
                                                                ps.policy.domains))
                    raise ClientBadData()
            csr_attr_map[CSR_ATTR_CN] = request.common_name

        if request.organization:
            if ps.policy and ps.policy.subject:
                policy_orgs = ps.policy.subject.orgs
                valid = value_matches_regex(value=request.organization,pattern_list=policy_orgs)
                if not valid:
                    org_str = "Organization"
                    log.error(MSG_VALUE_NOT_MATCH_POLICY.format(org_str, f"{org_str}s", request.organization,
                                                                policy_orgs))
                    raise ClientBadData
            csr_attr_map[CSR_ATTR_ORG] = request.organization
        elif ps.defaults and ps.defaults.subject and ps.defaults.subject.org:
            csr_attr_map[CSR_ATTR_ORG] = ps.defaults.subject.org

        if request.organizational_unit:
            if isinstance(request.organizational_unit, string_types):
                org_units = [request.organizational_unit]
            else:
                org_units = request.organizational_unit

            if ps.policy and ps.policy.subject:
                policy_ous = ps.policy.subject.org_units
                valid = all(
                    value_matches_regex(value=ou, pattern_list=policy_ous) for ou in org_units
                )
                if not valid:
                    ou_str = "Organizational Unit"
                    log.error(MSG_VALUE_NOT_MATCH_POLICY.format(ou_str, f"{ou_str}s", request.organizational_unit,
                                                                policy_ous))
                    raise ClientBadData
            csr_attr_map[CSR_ATTR_ORG_UNIT] = request.organizational_unit
        elif ps.defaults and ps.defaults.subject and ps.defaults.subject.org_units:
            csr_attr_map[CSR_ATTR_ORG_UNIT] = ps.defaults.subject.org_units

        if request.locality:
            if ps.policy and ps.policy.subject:
                policy_localities = ps.policy.subject.localities
                valid = value_matches_regex(value=request.locality, pattern_list=policy_localities)
                if not valid:
                    locality_str = "Localit"
                    log.error(MSG_VALUE_NOT_MATCH_POLICY.format(f"{locality_str}y", f"{locality_str}ies",
                                                                request.locality, policy_localities))
                    raise ClientBadData
            csr_attr_map[CSR_ATTR_LOCALITY] = request.locality
        elif ps.defaults and ps.defaults.subject and ps.defaults.subject.locality:
            csr_attr_map[CSR_ATTR_LOCALITY] = ps.defaults.subject.locality

        if request.province:
            if ps.policy and ps.policy.subject:
                policy_provinces = ps.policy.subject.localities
                valid = value_matches_regex(value=request.province, pattern_list=policy_provinces)
                if not valid:
                    province_str = "Province"
                    log.error(MSG_VALUE_NOT_MATCH_POLICY.format(province_str, f"{province_str}s", request.province,
                                                                policy_provinces))
                    raise ClientBadData
            csr_attr_map[CSR_ATTR_PROVINCE] = request.province
        elif ps.defaults and ps.defaults.subject and ps.defaults.subject.state:
            csr_attr_map[CSR_ATTR_PROVINCE] = ps.defaults.subject.state

        if request.country:
            if ps.policy and ps.policy.subject:
                policy_countries = ps.policy.subject.countries
                valid = value_matches_regex(value=request.country, pattern_list=policy_countries)
                if not valid:
                    country_str = "Countr"
                    log.error(MSG_VALUE_NOT_MATCH_POLICY.format(f"{country_str}y", f"{country_str}ies", request.country,
                                                                policy_countries))
                    raise ClientBadData
            csr_attr_map[CSR_ATTR_COUNTRY] = request.country
        elif ps.defaults and ps.defaults.subject and ps.defaults.subject.country:
            csr_attr_map[CSR_ATTR_COUNTRY] = ps.defaults.subject.country

        if len(request.san_dns) > 0:
            sans = {
                CSR_ATTR_SANS_DNS: request.san_dns
                # TODO: Other sans should be added here
            }
            csr_attr_map[CSR_ATTR_SANS_BY_TYPE] = sans

        return csr_attr_map

    def _get_policy(self, zone, subject_cn_to_str):
        """

        :param str zone:
        :param bool subject_cn_to_str:
        :rtype: PolicySpecification
        """
        cit = self._get_template_by_id(zone)
        if not cit:
            raise VenafiError(f"Certificate issuing template not found for zone [{zone}]")

        info = self._get_ca_info(cit.cert_authority, cit.cert_authority_account_id,
                                 cit.cert_authority_product_option_id)
        if not info:
            raise VenafiError("Certificate Authority info not found")

        ps = build_policy_spec(cit, info, subject_cn_to_str)
        return ps

    def _get_dek_hash(self, cert_id):
        """

        :param str cert_id:
        :rtype: EdgeEncryptionKey
        """
        url = URLS.CERTIFICATE_BY_ID.format(cert_id)
        status, data = self._get(url)
        if status != HTTPStatus.OK:
            log.error(f"Error retrieving Certificate details for id: {cert_id}")
            raise ServerUnexptedBehavior

        dek_hash = data['dekHash'] if 'dekHash' in data else None
        if not dek_hash:
            return None

        url = URLS.DEK_PUBLIC_KEY.format(dek_hash)
        status, data = self._get(url)
        if status != HTTPStatus.OK:
            log.error(f"Error retrieving DEK public key for hash: {dek_hash}")
            raise ServerUnexptedBehavior

        dek = EdgeEncryptionKey(data)
        return dek

    def _retrieve_service_generated_cert(self, request, dek_info):
        """

        :param CertificateRequest request:
        :param EdgeEncryptionKey dek_info:
        :rtype: Certificate
        """
        box = SealedBox(dek_info.public_key)
        encrypted_key_pass = box.encrypt(request.key_password)
        body = {
            'exportFormat': 'PEM',
            'encryptedPrivateKeyPassphrase': base64.b64encode(encrypted_key_pass).decode('utf-8'),
            'encryptedKeystorePassphrase': '',
            'certificateLabel': ''
        }
        url = URLS.CERTIFICATE_KEYSTORE_BY_ID.format(request.cert_guid)
        status, data = self._post(url, data=body)
        if status not in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED):
            log.error("Some error")
            raise VenafiError

        cert, chain, private_key = zip_to_pem(data, request.chain_option)
        return Certificate(cert=cert, chain=chain, key=private_key)
