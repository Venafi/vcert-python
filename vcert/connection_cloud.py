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
import requests
import six.moves.urllib.parse as urlparse
from .common import (ZoneConfig, CertificateRequest, CommonConnection, Policy, get_ip_address, log_errors, MIME_JSON,
                     MIME_TEXT, MIME_ANY, CertField, KeyType, AppDetails, RecommendedSettings)
from .pem import parse_pem
from .errors import (VenafiConnectionError, ServerUnexptedBehavior, ClientBadData, CertificateRequestError,
                     CertificateRenewError, VenafiError)
from .http import HTTPStatus
from .policy.pm_cloud import build_policy_spec


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

    API_BASE_URL = "https://api.venafi.cloud/outagedetection/v1/"

    USER_ACCOUNTS = "useraccounts"  # Not being used at all
    POLICIES_BY_ID = "certificatepolicies/%s"
    CERTIFICATE_REQUESTS = "certificaterequests"
    CERTIFICATE_STATUS = CERTIFICATE_REQUESTS + "/%s"
    CERTIFICATE_RETRIEVE = "certificates/%s/contents"
    CERTIFICATE_SEARCH = "certificatesearch"
    CERTIFICATE_TEMPLATE_BY_ID = "applications/%s/certificateissuingtemplates/%s"
    APP_DETAILS_BY_NAME = "applications/name/%s"
    CERTIFICATE_BY_ID = "certificates/%s"


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

    def _normalize_and_verify_base_url(self):
        u = self._base_url
        if u.startswith("http://"):
            u = "https://" + u[7:]
        elif not u.startswith("https://"):
            u = "https://" + u
        if not u.endswith("/"):
            u += "/"
        if not u.endswith("v1/"):
            u += "v1/"
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/outagedetection/v1/$", u):
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
            d["id"],
            d["companyId"],
            d["name"],
            d["systemGenerated"],
            d["creationDate"],
            d["subjectCNRegexes"],
            d["subjectORegexes"],
            d["subjectOURegexes"],
            d["subjectSTRegexes"],
            d["subjectLRegexes"],
            d["subjectCValues"],
            d["sanRegexes"],
            [],
            d['keyReuse'],
            d['certificateAuthority'],
            d['certificateAuthorityAccountId'],
            d['certificateAuthorityProductOptionId'],
            d['priority'],
            d['modificationDate'],
            d['status'],
            d['reason'],
            d['validityPeriod']
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
                rs["subjectOValue"],
                rs["subjectOUValue"],
                rs["subjectLValue"],
                rs["subjectSTValue"],
                rs["subjectCValue"],
                None,
                rs["keyReuse"]
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
            raise ServerUnexptedBehavior
        return self._parse_policy_response_to_object(data)

    def auth(self):
        status, data = self._get(URLS.USER_ACCOUNTS)
        if status == HTTPStatus.OK:
            return data

    def _get_app_details_by_name(self, app_name):
        """
        :param str app_name:
        :rtype AppDetails
        """
        if not app_name:
            raise ClientBadData("You need to specify the application name")
        status, data = self._get(URLS.APP_DETAILS_BY_NAME % app_name)
        if status == HTTPStatus.OK:
            return AppDetails(data["id"], data["certificateIssuingTemplateAliasIdMap"])
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

        ps = build_policy_spec(cit)
        return ps

    def set_policy(self, zone, policy_spec):
        pass
