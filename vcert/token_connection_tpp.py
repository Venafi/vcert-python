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
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509 import SignatureAlgorithmOID as algos

from .common import CommonConnection, MIME_JSON, CertField, ZoneConfig, Policy, KeyType, AcessToken
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
    NEW_TOKEN = "vedauth/authorize/oauth"
    REFRESH_TOKEN = "vedauth/authorize/token"
    CONFIG_READ_DN = "Config/ReadDn"


TOKEN_HEADER_NAME = "x-venafi-api-key"  # nosec


class TPPTokenConnection(CommonConnection):
    def __init__(self, user, password, url, access_token, refresh_token,  http_request_kwargs=None):
        """
        :param str user:
        :param str password:
        :param str url:
        :param dict[str,Any] http_request_kwargs:
        """
        self._base_url = url  # type: str
        self._user = user  # type: str
        self._password = password  # type: str
        self.access_token = access_token # type: str
        self.refresh_token = refresh_token # type: str
        if http_request_kwargs is None:
            http_request_kwargs = {"timeout": 180}
        elif "timeout" not in http_request_kwargs:
            http_request_kwargs["timeout"] = 180
        self._http_request_kwargs = http_request_kwargs or {}

    def __setattr__(self, key, value):
        if key == "_base_url":
            value = self._normalize_and_verify_base_url(value)
        self.__dict__[key] = value

    def __str__(self):
        return "[TPP] %s" % self._base_url


    def _get_access_token_on_tpp(self, url, data=None):

        if isinstance(data, dict):
            tpp_url = self._base_url
            if tpp_url.__contains__("vedsdk"):
               tpp_url = tpp_url.replace("vedsdk", "")
            r = requests.post(tpp_url + url, json=data,  **self._http_request_kwargs)
            a = tpp_url + url
            print(a)
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


    @staticmethod
    def _parse_access_token_data_to_object(data):
       identity = ""

       if "identity" in data :
           identity =  data["identity"]

       token_info = AcessToken(
            data["access_token"],
            data["expires"],
            identity,
            data["refresh_token"],
            data["refresh_until"],
            data["scope"],
            data["token_type"]
       )
       return token_info


    def get_access_token(self):
        status, data = self._get_access_token_on_tpp(URLS.NEW_TOKEN, {
                        "username": self._user,
                        "password": self._password,
                        "client_id": "vcert-sdk",
                        "scope": "certificate:manage,revoke",
                        "state": "",
                    })
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on reading zone configuration." % status)
        return self._parse_access_token_data_to_object(data)

    def refresh_tpp_token(self):
        status, data = self._get_access_token_on_tpp(URLS.REFRESH_TOKEN, {
                "refresh_token": self.refresh_token,
                "client_id": "vcert-sdk",
        })
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on reading zone configuration." % status)
        return self._parse_access_token_data_to_object(data)

    #def revoke_access_token





