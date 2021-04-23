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

from __future__ import (absolute_import, division, generators, unicode_literals, print_function, nested_scopes,
                        with_statement)
import re
import logging as log
from pprint import pprint

import requests
import six.moves.urllib.parse as urlparse
from .common import (ZoneConfig, CertificateRequest, CommonConnection, Policy, get_ip_address, log_errors, MIME_JSON,
                     MIME_TEXT, MIME_ANY, CertField, KeyType, AppDetails, RecommendedSettings)
from .pem import parse_pem
from .errors import (VenafiConnectionError, ServerUnexptedBehavior, ClientBadData, CertificateRequestError,
                     CertificateRenewError, VenafiError)
from .http import HTTPStatus
from .policy.pm_cloud import build_policy_spec, validate_policy_spec, \
    AccountDetails, build_cit_request, build_user, UserDetails, build_company, build_apikey, build_app_update_request, \
    get_ca_info, CertificateAuthorityDetails, CertificateAuthorityInfo, build_account_details


class CertStatuses:
    def __init__(self):
        pass

    REQUESTED = 'REQUESTED'
    PENDING = 'PENDING'
    FAILED = 'FAILED'
    ISSUED = 'ISSUED'


class URLS:
    def __init__(self):
        pass

    API_BASE_URL = "https://api.venafi.cloud/"
    API_VERSION = "v1/"
    API_BASE_PATH = "outagedetection/" + API_VERSION

    POLICIES_BY_ID = API_BASE_PATH + "certificatepolicies/%s"
    CERTIFICATE_REQUESTS = API_BASE_PATH + "certificaterequests"
    CERTIFICATE_STATUS = API_BASE_PATH + CERTIFICATE_REQUESTS + "/%s"
    CERTIFICATE_RETRIEVE = API_BASE_PATH + "certificates/%s/contents"
    CERTIFICATE_SEARCH = API_BASE_PATH + "certificatesearch"
    APPLICATIONS = "applications"
    APP_BY_ID = API_BASE_PATH + APPLICATIONS + "/%s"
    CERTIFICATE_TEMPLATE_BY_ID = APP_BY_ID + "/certificateissuingtemplates/%s"
    APP_DETAILS_BY_NAME = API_BASE_PATH + APPLICATIONS + "/name/%s"
    CERTIFICATE_BY_ID = API_BASE_PATH + "certificates/%s"
    CA_ACCOUNTS = API_VERSION + "certificateauthorities/%s/accounts"
    CA_ACCOUNT_DETAILS = CA_ACCOUNTS + "/%s"
    ISSUING_TEMPLATES = API_VERSION + "certificateissuingtemplates"
    ISSUING_TEMPLATES_UPDATE = ISSUING_TEMPLATES + "/%s"
    USER_ACCOUNTS = API_VERSION + "useraccounts"


class CondorChainOptions:
    def __init__(self):
        pass

    ROOT_FIRST = "ROOT_FIRST"
    ROOT_LAST = "EE_FIRST"


TOKEN_HEADER_NAME = "tppl-api-key"  # nosec


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
        raise ClientBadData("Invalid Zone [%s]. The zone format is incorrect", zone)

    app_name = urlparse.quote(segments[0])
    cit_alias = urlparse.quote(segments[1])
    return app_name, cit_alias


class CloudConnection(CommonConnection):
    def __init__(self, token, url=None, http_request_kwargs=None):
        self._base_url = url or URLS.API_BASE_URL
        self._token = token
        self._normalize_and_verify_base_url()
        if http_request_kwargs is None:
            http_request_kwargs = {"timeout": 180}
        elif "timeout" not in http_request_kwargs:
            http_request_kwargs["timeout"] = 180
        self._http_request_kwargs = http_request_kwargs

    def __str__(self):
        return "[Cloud] %s" % self._base_url

    def _get(self, url, params=None):
        r = requests.get(self._base_url + url, params=params,
                         headers={TOKEN_HEADER_NAME: self._token, "Accept": MIME_ANY, "cache-control": "no-cache"},
                         **self._http_request_kwargs
                         )
        return self.process_server_response(r)

    def _post(self, url, data=None):
        if isinstance(data, dict):
            r = requests.post(self._base_url + url, json=data,
                              headers={TOKEN_HEADER_NAME: self._token,
                                       "cache-control": "no-cache",
                                       "Accept": MIME_JSON},
                              **self._http_request_kwargs
                              )
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(r)

    def _put(self, url, data=None):
        if isinstance(data, dict):
            r = requests.put(self._base_url + url, json=data,
                             headers={TOKEN_HEADER_NAME: self._token,
                                      "cache-control": "no-cache",
                                      "Accept": MIME_JSON},
                             **self._http_request_kwargs
                             )
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(r)

    def _normalize_and_verify_base_url(self):
        u = self._base_url
        if u.startswith("http://"):
            u = "https://" + u[7:]
        elif not u.startswith("https://"):
            u = "https://" + u
        if not u.endswith("/"):
            u += "/"
        # if not u.endswith("v1/"):
        #     u += "v1/"
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/$", u):
            raise ClientBadData
        self._base_url = u

    @staticmethod
    def _process_server_response(r):
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED):
            raise VenafiConnectionError("Server status: %s, %s", (r.status_code, r.request.url))
        content_type = r.headers.get("content-type")
        if content_type == MIME_TEXT:
            log.debug(r.text)
            return r.status_code, r.text
        elif content_type == MIME_JSON:
            log.debug(r.content.decode())
            return r.status_code, r.json()
        else:
            log.error("unexpected content type: %s for request %s" % (content_type, r.request.url))
            raise ServerUnexptedBehavior

    def _get_cert_status(self, request):
        status, data = self._get(URLS.CERTIFICATE_STATUS % request.id)
        if status == HTTPStatus.OK:
            request_status = CertificateStatusResponse(data)
            return request_status
        else:
            raise ServerUnexptedBehavior

    @staticmethod
    def _parse_policy_response_to_object(d):
        policy = Policy(
            d["id"] if 'id' in d else None,
            d["companyId"] if 'companyId' in d else None,
            d["name"] if 'name' in d else None,
            d["systemGenerated"] if 'systemGenerated' in d else None,
            d["creationDate"] if 'creationDate' in d else None,
            d["subjectCNRegexes"] if 'subjectCNRegexes' in d else None,
            d["subjectORegexes"] if 'subjectORegexes' in d else None,
            d["subjectOURegexes"] if 'subjectOURegexes' in d else None,
            d["subjectSTRegexes"] if 'subjectSTRegexes' in d else None,
            d["subjectLRegexes"] if 'subjectLRegexes' in d else None,
            d["subjectCValues"] if 'subjectCValues' in d else None,
            d["sanRegexes"] if 'sanRegexes' in d else None,
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
            None
        )
        for kt in d.get('keyTypes', []):
            key_type = kt['keyType'].lower()
            if key_type == KeyType.RSA:
                for s in kt['keyLengths']:
                    policy.key_types.append(KeyType(key_type, s))
            else:
                log.error("Unknow key type: %s" % kt['keyType'])
                raise ServerUnexptedBehavior

        rs = CloudConnection._parse_recommended_settings_to_object(d)
        if rs:
            policy.recommended_settings = rs

        return policy

    @staticmethod
    def _parse_recommended_settings_to_object(d):
        if 'recommendedSettings' in d:
            rs = d["recommendedSettings"]
            settings = RecommendedSettings(
                rs["subjectOValue"] if 'subjectOValue' in rs else None,
                rs["subjectOUValue"] if 'subjectOUValue' in rs else None,
                rs["subjectLValue"] if 'subjectLValue' in rs else None,
                rs["subjectSTValue"] if 'subjectSTValue' in rs else None,
                rs["subjectCValue"] if 'subjectCValue' in rs else None,
                None,
                rs["keyReuse"] if 'keyReuse' in rs else None
            )
            if 'key' in rs:
                kt = KeyType(rs['key']['type'], rs['key']['length'])
                settings.keyType = kt

            return settings

    def _get_template_by_id(self, zone):
        """
        Returns the Certificate Issuing Template details

        :rtype: Policy
        """
        app_name, cit_alias = _parse_zone(zone)
        status, data = self._get(URLS.CERTIFICATE_TEMPLATE_BY_ID % (app_name, cit_alias))
        if status != HTTPStatus.OK:
            log.error("Invalid status %s while retrieving policy [%s]" % (status, zone))
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
        status, data = self._get(URLS.APP_DETAILS_BY_NAME % app_name)
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
        else:
            pass

    def request_cert(self, request, zone):
        app_name, cit_alias = _parse_zone(zone)
        details = self._get_app_details_by_name(app_name)
        cit_alias_decoded = urlparse.unquote(cit_alias)
        cit_id = details.cit_alias_id_map.get(cit_alias_decoded)
        if not request.csr:
            request.build_csr()

        ip_address = get_ip_address()
        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data={
            "certificateSigningRequest": request.csr,
            "applicationId": details.app_id,
            "certificateIssuingTemplateId": cit_id,
            "apiClientInformation": {
                "type": request.origin,
                "identifier": ip_address
            }
        })
        if status == HTTPStatus.CREATED:
            request.id = data['certificateRequests'][0]['id']
            request.cert_guid = data['certificateRequests'][0]['certificateIds'][0]
            return True
        else:
            log.error("unexpected server response %s: %s", status, data)
            raise CertificateRequestError

    def retrieve_cert(self, request):
        cert_status = self._get_cert_status(request)
        if cert_status.status == CertStatuses.PENDING or cert_status.status == CertStatuses.REQUESTED:
            log.info("Certificate status is %s." % cert_status.status)
            return None
        elif cert_status.status == CertStatuses.FAILED:
            log.debug("Status is %s. Returning data for debug" % cert_status.status)
            return "Certificate FAILED"
        elif cert_status.status == CertStatuses.ISSUED:
            url = URLS.CERTIFICATE_RETRIEVE % cert_status.certificateIds[0]
            if request.chain_option == "first":
                url += "?chainOrder=%s&format=PEM" % CondorChainOptions.ROOT_FIRST
            elif request.chain_option == "last":
                url += "?chainOrder=%s&format=PEM" % CondorChainOptions.ROOT_LAST
            else:
                log.error("chain option %s is not valid" % request.chain_option)
                raise ClientBadData

            status, data = self._get(url)
            if status == HTTPStatus.OK:
                return parse_pem(data, request.chain_option)
            else:
                raise ServerUnexptedBehavior
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
            log.error("Can`t find certificate_id")
            raise ClientBadData

        status, data = self._get(URLS.CERTIFICATE_BY_ID % certificate_id)
        if status == HTTPStatus.OK:
            request.id = data['certificateRequestId']
        else:
            raise ServerUnexptedBehavior

        ip_address = get_ip_address()
        d = {"existingCertificateId": certificate_id,
             "applicationId": app_id,
             "certificateIssuingTemplateId": cit_id,
             "apiClientInformation": {
                 "type": request.origin,
                 "identifier": ip_address
             }}

        if reuse_key:
            if request.csr:
                d["certificateSigningRequest"] = request.csr
                d["reuseCSR"] = False
            else:
                log.error("Certificate renew by reusing the CSR is not supported right now."
                          "\nSet [reuse_key] to False or just remove it")
                raise VenafiError
                # d["reuseCSR"] = True
        else:
            c = data
            if c.get("subjectCN"):
                request.common_name = c['subjectCN'][0]
            if c.get("subjectC"):
                request.country = c["subjectC"]
            if c.get("subjectO"):
                request.organization = c["subjectO"]
            if c.get("subjectOU"):
                request.organizational_unit = c["subjectOU"]
            if c.get("subjectL"):
                request.locality = c["subjectL"]
            if c.get("subjectAlternativeNameDns"):
                request.san_dns = c["subjectAlternativeNameDns"]
            request.key_type = KeyType(KeyType.RSA, c["keyStrength"])
            request.build_csr()
            d["certificateSigningRequest"] = request.csr
            d["reuseCSR"] = False

        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data=d)
        if status == HTTPStatus.CREATED:
            request.id = data['certificateRequests'][0]['id']
            return True
        else:
            log.error("server unexpected status %s" % status)
            raise CertificateRenewError

    def search_by_thumbprint(self, thumbprint):
        """
        :param str thumbprint:
        :rtype CertificateStatusResponse
        """
        thumbprint = re.sub(r'[^\dabcdefABCDEF]', "", thumbprint)
        thumbprint = thumbprint.upper()
        status, data = self._post(URLS.CERTIFICATE_SEARCH, data={
            "expression": {
                "operands": [{"field": "fingerprint",
                              "operator": "MATCH",
                              "value": thumbprint
                              }]
            }
        })
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior
        if not data.get('count'):
            return None
        return CertificateStatusResponse(data['certificates'][0])

    def read_zone_conf(self, zone):
        policy = self._get_template_by_id(zone)
        z = ZoneConfig(
            organization=CertField(""),
            organizational_unit=CertField(""),
            country=CertField(""),
            province=CertField(""),
            locality=CertField(""),
            policy=policy,
            key_type=policy.key_types[0] if policy.key_types else None,
        )
        return z

    def import_cert(self, request):
        # not supported in Cloud
        raise NotImplementedError

    def get_policy_specification(self, zone):
        cit = self._get_template_by_id(zone)
        if not cit:
            raise VenafiError('Certificate issuing template not found for zone [%s]', zone)

        info = self._get_ca_info(cit.cert_authority, cit.cert_authority_account_id, cit.cert_authority_product_option_id)
        if not info:
            raise VenafiError('Certificate Authority info not found.')

        ps = build_policy_spec(cit, info)
        return ps

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
            raise VenafiError('Certificate Authority is required')

        ca_details = self._get_ca_details(policy_spec.policy.certificate_authority)
        if not ca_details:
            raise VenafiError('CA [%s] not found in Venafi Cloud', policy_spec.policy.certificate_authority)

        # CA valid. Create request dictionary
        request = build_cit_request(policy_spec, ca_details)
        request['name'] = cit_alias
        cit_data = self._get_cit(cit_alias)
        resp_cit_data = None
        if cit_data:
            # Issuing Template exists. Update
            status, resp_cit_data = self._put(URLS.ISSUING_TEMPLATES_UPDATE % cit_data['id'], request)
            if status != HTTPStatus.OK:
                raise VenafiError('Failed to update issuing template [%s] for zone [%s]' % (cit_data['id'], zone))
        else:
            # Issuing Template does not exist. Create one
            status, resp_cit_data = self._post(URLS.ISSUING_TEMPLATES, request)
            if status != HTTPStatus.OK:
                raise VenafiError('Failed to create issuing template for zone [%s]', zone)

        # Validate Application existence in Venafi Cloud.
        user_details = self._get_user_details()
        if not user_details:
            raise VenafiError('User Details not found.')

        app_details = self._get_app_details_by_name(app_name)
        if app_details:
            # Application exists. Update with cit
            if not self._policy_exists(zone):
                # Only link cit with Application when cit is not already associated with Application
                app_req = build_app_update_request(app_details, resp_cit_data)
                status, data = self._put(URLS.APP_BY_ID % app_details.app_id, app_req)
                if status != HTTPStatus.OK:
                    raise VenafiError('Could not update Application [%s] with cit [%s]' % (app_name,
                                                                                           pprint(resp_cit_data)))
        else:
            # Application does not exist. Create one
            owner_id = {
                'ownerId': user_details.user.user_id,
                'ownerType': 'USER'
            }
            app_issuing_template = {
                resp_cit_data['name']: resp_cit_data['id']
            }

            app_req = {
                'ownerIdsAndTypes': [owner_id],
                'name': app_name,
                'certificateIssuingTemplateAliasIdMap': app_issuing_template
            }

            status, data = self._post(URLS.APPLICATIONS, app_req)
            if status != HTTPStatus.CREATED:
                raise VenafiError('Could not create application [%s].', app_name)

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
        url = URLS.CA_ACCOUNTS % ca_type
        status, data = self._get(url)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior

        if 'accounts' not in data:
            raise VenafiError('Response error. Accounts not found')

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
            raise VenafiError('Could not retrieve Certificate Issuing Templates')

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
            raise VenafiError('Failed to retrieve user accounts. Error %s', pprint(data))

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
        url = URLS.CA_ACCOUNT_DETAILS % (ca_name, account_id)
        status, data = self._get(url)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior

        account_details = build_account_details(data)
        info = CertificateAuthorityInfo(account_details.account.certificate_authority, account_details.account.key)
        for po in account_details.product_options:
            if po.product_id == product_option_id:
                info.vendor_name = po.product_name

        return info
