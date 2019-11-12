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

import base64
import logging as log
import re
import time

import requests

from .common import CommonConnection, MIME_JSON, CertField, ZoneConfig, Policy, KeyTypes, KeyType
from .pem import parse_pem
from .errors import (ServerUnexptedBehavior, ClientBadData, CertificateRequestError, AuthenticationError,
                     CertificateRenewError)
from .http import HTTPStatus


class URLS:
    API_BASE_URL = ""

    AUTHORIZE = "authorize/"
    CERTIFICATE_REQUESTS = "certificates/request"
    CERTIFICATE_RETRIEVE = "certificates/retrieve"
    FIND_POLICY = "config/findpolicy"
    CERTIFICATE_REVOKE = "certificates/revoke"
    CERTIFICATE_RENEW = "certificates/renew"
    CERTIFICATE_SEARCH = "certificates/"
    CERTIFICATE_IMPORT = "certificates/import"
    ZONE_CONFIG = "certificates/checkpolicy"


TOKEN_HEADER_NAME = "x-venafi-api-key"


class TPPConnection(CommonConnection):
    def __init__(self, user, password, url, http_request_kwargs=None):
        """
        :param str user:
        :param str password:
        :param str url:
        :param dict[str,Any] http_request_kwargs:
        """
        self._base_url = url  # type: str
        self._user = user  # type: str
        self._password = password  # type: str
        self._token = None  # type: tuple
        if http_request_kwargs is None:
            http_request_kwargs = {"timeout": 60}
        elif "timeout" not in http_request_kwargs:
            http_request_kwargs["timeout"] = 60
        self._http_request_kwargs = http_request_kwargs or {}

    def __setattr__(self, key, value):
        if key == "_base_url":
            value = self._normalize_and_verify_base_url(value)
        self.__dict__[key] = value

    def __str__(self):
        return "[TPP] %s" % self._base_url

    def _get(self, url="", params=None):
        if not self._token or self._token[1] < time.time() + 1:
            self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        r = requests.get(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
                         MIME_JSON, 'cache-control': 'no-cache'}, params=params, **self._http_request_kwargs)
        return self.process_server_response(r)

    def _post(self, url, data=None):
        if not self._token or self._token[1] < time.time() + 1:
            self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        if isinstance(data, dict):
            r = requests.post(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
                              MIME_JSON, "cache-control": "no-cache"}, json=data,  **self._http_request_kwargs)
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(r)

    @staticmethod
    def _normalize_and_verify_base_url(u):
        if u.startswith("http://"):
            u = "https://" + u[7:]
        elif not u.startswith("https://"):
            u = "https://" + u
        if not u.endswith("/"):
            u += "/"
        if not u.endswith("vedsdk/"):
            u += "vedsdk/"
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/vedsdk/$", u):
            raise ClientBadData
        return u

    def ping(self):
        status, data = self._get()
        return status == HTTPStatus.OK and "" in data

    def auth(self):
        data = {"Username": self._user, "Password": self._password}
        r = requests.post(self._base_url + URLS.AUTHORIZE, json=data,
                          headers={'content-type': MIME_JSON, "cache-control": "no-cache"},
                          **self._http_request_kwargs)

        status, user = self.process_server_response(r)
        if status == HTTPStatus.OK:
            valid_until = int(re.sub(r"\D", "", user["ValidUntil"]))
            self._token = user["APIKey"], valid_until
            return user
        else:
            log.error("Authentication status is not %s but %s. Exiting" % (HTTPStatus.OK, status[0]))
            raise AuthenticationError

    # TODO: Need to add service genmerated CSR implementation
    def request_cert(self, request, zone):
        if not request.csr:
            request.build_csr()
        status, data = self._post(URLS.CERTIFICATE_REQUESTS,
                                  data={"PolicyDN": self._get_policy_dn(zone),
                                        "PKCS10": request.csr,
                                        "ObjectName": request.friendly_name,
                                        "DisableAutomaticRenewal": "true"})
        if status == HTTPStatus.OK:
            request.id = data['CertificateDN']
            log.debug("Certificate sucessfully requested with request id %s." % request.id)
            return True
        else:
            log.error("Request status is not %s. %s." % HTTPStatus.OK, status)
            raise CertificateRequestError

    def retrieve_cert(self, certificate_request):
        log.debug("Getting certificate status for id %s" % certificate_request.id)

        retrive_request = dict(CertificateDN=certificate_request.id, Format="base64", IncludeChain='true')

        if certificate_request.chain_option == "last":
            retrive_request['RootFirstOrder'] = 'false'
            retrive_request['IncludeChain'] = 'true'
        elif certificate_request.chain_option == "first":
            retrive_request['RootFirstOrder'] = 'true'
            retrive_request['IncludeChain'] = 'true'
        elif certificate_request.chain_option == "ignore":
            retrive_request['IncludeChain'] = 'false'
        else:
            log.error("chain option %s is not valid" % certificate_request.chain_option)
            raise ClientBadData

        status, data = self._post(URLS.CERTIFICATE_RETRIEVE, data=retrive_request)
        if status == HTTPStatus.OK:
            pem64 = data['CertificateData']
            pem = base64.b64decode(pem64)
            return parse_pem(pem.decode(), certificate_request.chain_option)
        elif status == HTTPStatus.ACCEPTED:
            log.debug(data['Status'])
            return None
        else:
            log.error("Status is not %s. %s" % HTTPStatus.OK, status)
            raise ServerUnexptedBehavior

    def revoke_cert(self, request):
        if not (request.id or request.thumbprint):
            raise ClientBadData
        d = {
            "Disable": request.disable
        }
        if request.reason:
            d["Reason"] = request.reason
        if request.id:
            d["CertificateDN"] = request.id
        elif request.thumbprint:
            d["Thumbprint"] = request.thumbprint
        if request.comments:
            d["Comments"] = request.comments
        status, data = self._post(URLS.CERTIFICATE_REVOKE, data=d)
        if status in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
            return data
        else:
            raise ServerUnexptedBehavior

    def renew_cert(self, request):
        if not request.id and not request.thumbprint:
            log.debug("Request id or thumbprint must be specified for TPP")
            raise CertificateRenewError
        if not request.id and request.thumbprint:
            request.id = self.search_by_thumbprint(request.thumbprint)
        log.debug("Trying to renew certificate %s" % request.id)
        status, data = self._post(URLS.CERTIFICATE_RENEW, data={"CertificateDN": request.id})
        if not data['Success']:
            raise CertificateRenewError

    @staticmethod
    def _parse_zone_config_to_policy(data):
        p = data["Policy"]
        # todo: parsing and cover by tests
        if p["KeyPair"]["KeyAlgorithm"]["Locked"]:
            if p["KeyPair"]["KeyAlgorithm"]["Value"] == "RSA":
                key_types = [KeyType(KeyTypes.RSA, key_sizes=p["KeyPair"]["KeySize"]["Value"])]
            elif p["KeyPair"]["KeyAlgorithm"]["Value"] == "ECC":
                key_types = [KeyType(KeyTypes.ECDSA, key_curves=p["KeyPair"]["EllipticCurve"]["Value"])]
            else:
                raise ServerUnexptedBehavior
        else:
            key_types = [KeyType(KeyTypes.RSA, key_sizes=KeyType.ALLOWED_SIZES), KeyType(KeyTypes.ECDSA, key_curves=KeyType.ALLOWED_CURVES)]
        return Policy(key_types=key_types)

    @staticmethod
    def _parse_zone_data_to_object(data):
        s = data["Policy"]["Subject"]
        ou = s['OrganizationalUnit'].get('Values')
        policy = TPPConnection._parse_zone_config_to_policy(data)
        z = ZoneConfig(
            organization=CertField(s['Organization']['Value'], locked=s['Organization']['Locked']),
            organizational_unit=CertField(ou, locked=s['OrganizationalUnit']['Locked']),
            country=CertField(s['Country']['Value'], locked=s['Country']['Locked']),
            province=CertField(s['State']['Value'], locked=s['State']['Locked']),
            locality=CertField(s['City']['Value'], locked=s['City']['Locked']),
            policy=policy,
            key_type=policy.key_types[0] if policy.key_types else None,
        )
        return z

    def read_zone_conf(self, tag):
        status, data = self._post(URLS.ZONE_CONFIG, {"PolicyDN":  self._get_policy_dn(tag)})
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on reading zone configuration." % status)
        return self._parse_zone_data_to_object(data)

    def import_cert(self, request):
        raise NotImplementedError

    @staticmethod
    def _get_policy_dn(zone):
        if zone is None:
            log.error("Bad zone: %s" % zone)
            raise ClientBadData
        if re.match(r"^\\\\VED\\\\Policy", zone):
            return zone
        else:
            if re.match(r"^\\\\", zone):
                return r"\\VED\\Policy" + zone
            else:
                return r"\\VED\\Policy\\" + zone

    def search_by_thumbprint(self, thumbprint):
        """
        :param str thumbprint:
        """
        thumbprint = re.sub(r'[^\dabcdefABCDEF]', "", thumbprint)
        thumbprint = thumbprint.upper()
        status, data = self._get(URLS.CERTIFICATE_SEARCH, params={"Thumbprint": thumbprint})
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior

        if not data['Certificates']:
            raise ClientBadData("Certificate not found by thumbprint")
        return data['Certificates'][0]['DN']
