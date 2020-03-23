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

from .common import (ZoneConfig, CertificateRequest, CommonConnection, Policy, log_errors, MIME_JSON, MIME_TEXT,
                     MIME_ANY, CertField, KeyType)
from .pem import parse_pem
from .errors import (VenafiConnectionError, ServerUnexptedBehavior, ClientBadData, CertificateRequestError,
                     CertificateRenewError)
from .http import HTTPStatus


class CertStatuses:
    REQUESTED = 'REQUESTED'
    PENDING = 'PENDING'
    FAILED = 'FAILED'
    ISSUED = 'ISSUED'


class URLS:
    API_BASE_URL = "https://api.venafi.cloud/v1/"

    USER_ACCOUNTS = "useraccounts"
    ZONES = "zones"
    ZONE_BY_TAG = ZONES + "/tag/%s"
    POLICIES_BY_ID = "certificatepolicies/%s"
    CERTIFICATE_REQUESTS = "certificaterequests"
    CERTIFICATE_STATUS = CERTIFICATE_REQUESTS + "/%s"
    CERTIFICATE_RETRIEVE = CERTIFICATE_REQUESTS + "/%s/certificate"
    CERTIFICATE_SEARCH = "certificatesearch"
    MANAGED_CERTIFICATES = "managedcertificates"
    MANAGED_CERTIFICATE_BY_ID = MANAGED_CERTIFICATES + "/%s"
    TEMPLATE_BY_ID = "certificateissuingtemplates/%s"


class CondorChainOptions:
    ROOT_FIRST = "ROOT_FIRST"
    ROOT_LAST = "EE_FIRST"


TOKEN_HEADER_NAME = "tppl-api-key"  # nosec


class CertificateStatusResponse:
    def __init__(self, d):
        self.status = d.get('status')
        self.subject = d.get('subjectDN') or d.get('subjectCN')[0]
        self.zoneId = d.get('zoneId')
        self.manage_id = d.get('managedCertificateId')


class CloudConnection(CommonConnection):
    def __init__(self, token, url=None, http_request_kwargs=None):
        self._base_url = url or URLS.API_BASE_URL
        self._token = token
        self._normalize_and_verify_base_url()
        if http_request_kwargs is None:
            http_request_kwargs = {"timeout": 60}
        elif "timeout" not in http_request_kwargs:
            http_request_kwargs["timeout"] = 60
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
                              headers={TOKEN_HEADER_NAME: self._token, "cache-control": "no-cache", "Accept": MIME_JSON},
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
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/v1/$", u):
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
    def _parse_policy_responce_to_object(d):
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
            d['keyReuse']
        )
        for kt in d.get('keyTypes', []):
            key_type = kt['keyType'].lower()
            if key_type == KeyType.RSA:
                for s in kt['keyLengths']:
                    policy.key_types.append(KeyType(key_type, s))
            else:
                log.error("Unknow key type: %s" % kt['keyType'])
                raise ServerUnexptedBehavior
        return policy

    def _get_policy_by_id(self, policy_id):
        status, data = self._get(URLS.TEMPLATE_BY_ID % policy_id)
        if status != HTTPStatus.OK:
            log.error("Invalid status during geting policy: %s for policy %s" % (status, policy_id))
            raise ServerUnexptedBehavior
        return self._parse_policy_responce_to_object(data)

    def auth(self):
        status, data = self._get(URLS.USER_ACCOUNTS)
        if status == HTTPStatus.OK:
            return data

    def _get_zone_id_by_tag(self, tag):
        """
        :param str tag:
        :rtype Zone
        """
        if not tag:
            raise ClientBadData("You need to specify zone tag")
        status, data = self._get(URLS.ZONE_BY_TAG % tag)
        if status == HTTPStatus.OK:
            return data['id']
        elif status in (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.PRECONDITION_FAILED):
            log_errors(data)
        else:
            pass

    def request_cert(self, request, zone):
        zone_id = self._get_zone_id_by_tag(zone)
        if not request.csr:
            request.build_csr()
        status, data = self._post(URLS.CERTIFICATE_REQUESTS,
                                  data={"certificateSigningRequest": request.csr, "zoneId": zone_id})
        if status == HTTPStatus.CREATED:
            request.id = data['certificateRequests'][0]['id']
            return True
        else:
            log.error("unexpected server response %s: %s", status, data)
            raise CertificateRequestError

    def retrieve_cert(self, request):
        url = URLS.CERTIFICATE_RETRIEVE % request.id
        if request.chain_option == "first":
            url += "?chainOrder=%s&format=PEM" % CondorChainOptions.ROOT_FIRST
        elif request.chain_option == "last":
            url += "?chainOrder=%s&format=PEM" % CondorChainOptions.ROOT_LAST
        else:
            log.error("chain option %s is not valid" % request.chain_option)
            raise ClientBadData
        status, data = self._get(URLS.CERTIFICATE_STATUS % request.id)
        if status == HTTPStatus.OK or HTTPStatus.CONFLICT:
            if data['status'] == CertStatuses.PENDING or data['status'] == CertStatuses.REQUESTED:
                log.info("Certificate status is %s." % data['status'])
                return None
            elif data['status'] == CertStatuses.FAILED:
                log.debug("Status is %s. Returning data for debug" % data['status'])
                return "Certificate FAILED"
            elif data['status'] == CertStatuses.ISSUED:
                status, data = self._get(url)
                if status == HTTPStatus.OK:
                    return parse_pem(data, request.chain_option)
                else:
                    raise ServerUnexptedBehavior
            else:
                raise ServerUnexptedBehavior
        else:
            raise ServerUnexptedBehavior

    def revoke_cert(self, request):
        # not supported in Venafi Cloud
        raise NotImplementedError

    def renew_cert(self, request, reuse_key=False):
        zone = None
        manage_id = None
        if not request.id and not request.thumbprint:
            log.error("prev_cert_id or thumbprint or manage_id must be specified for renewing certificate")
            raise ClientBadData
        if request.thumbprint:
            r = self.search_by_thumbprint(request.thumbprint)
            manage_id = r.manage_id
        if request.id:
            prev_request = self._get_cert_status(CertificateRequest(cert_id=request.id))
            manage_id = prev_request.manage_id
            zone = prev_request.zoneId
        if not manage_id:
            log.error("Can`t find manage_id")
            raise ClientBadData
        status, data = self._get(URLS.MANAGED_CERTIFICATE_BY_ID % manage_id)
        if status == HTTPStatus.OK:
            request.id = data['latestCertificateRequestId']
        else:
            raise ServerUnexptedBehavior
        if not zone:
            prev_request = self._get_cert_status(CertificateRequest(cert_id=request.id))
            zone = prev_request.zoneId
        d = {"existingManagedCertificateId": manage_id, "zoneId": zone}
        if reuse_key:
            if request.csr:
                d["certificateSigningRequest"] = request.csr
                d["reuseCSR"] = False
            else:
                d["reuseCSR"] = True
        else:
            c = data['certificates'][0]
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
            request.key_type = KeyType(KeyType.RSA, c["keyStrength"])
            request.san_dns = c["subjectAlternativeNameDns"]
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
        status, data = self._post(URLS.CERTIFICATE_SEARCH, data={"expression": {"operands": [
            {"field": "fingerprint", "operator": "MATCH", "value": thumbprint}]}})
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior
        if not data.get('count'):
            return None
        return CertificateStatusResponse(data['certificates'][0])

    def read_zone_conf(self, tag):
        status, data = self._get(URLS.ZONE_BY_TAG % tag)
        template_id = data['certificateIssuingTemplateId']
        policy = self._get_policy_by_id(template_id)
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
