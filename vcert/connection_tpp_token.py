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

import logging as log
import re
import time
from http import HTTPStatus

import requests

from .common import MIME_JSON, TokenInfo, Authentication
from .connection_tpp_common import TPPCommonConnection, URLS
from .errors import (ClientBadData, ServerUnexptedBehavior, AuthenticationError)


API_TOKEN_URL = "vedauth/"  # type: str
API_BASE_URL = "vedsdk/"  # type: str

PATH_AUTHORIZE_TOKEN = API_TOKEN_URL + "authorize/oauth"  # type: str
PATH_REFRESH_TOKEN = API_TOKEN_URL + "authorize/token"  # type: str
PATH_REVOKE_TOKEN = API_TOKEN_URL + "revoke/token"  # type: str
PATH_CERTIFICATE_GUID = API_BASE_URL + "certificate"  # type: str

HEADER_AUTHORIZATION = "Authorization"  # type: str

KEY_ACCESS_TOKEN = "access_token"  # type: str
KEY_REFRESH_TOKEN = "refresh_token"  # type: str
KEY_EXPIRATION_DATE = "expiration_date"  # type: str


class TPPTokenConnection(TPPCommonConnection):
    def __init__(self, url, user=None, password=None, access_token=None, refresh_token=None, http_request_kwargs=None):
        super().__init__(http_request_kwargs=http_request_kwargs)
        self._base_url = url  # type: str
        self._auth = Authentication(user=user, password=password, access_token=access_token,
                                    refresh_token=refresh_token)  # type: Authentication

    def _create_url_dictionary(self):
        self.urls = dict()
        self.urls[PATH_AUTHORIZE_TOKEN] = PATH_AUTHORIZE_TOKEN
        self.urls[PATH_REFRESH_TOKEN] = PATH_REFRESH_TOKEN
        self.urls[PATH_REVOKE_TOKEN] = PATH_REVOKE_TOKEN

        self.urls[URLS.CERTIFICATE_REQUESTS] = API_BASE_URL + URLS.CERTIFICATE_REQUESTS
        self.urls[URLS.CERTIFICATE_RETRIEVE] = API_BASE_URL + URLS.CERTIFICATE_RETRIEVE
        self.urls[URLS.FIND_POLICY] = API_BASE_URL + URLS.FIND_POLICY
        self.urls[URLS.CERTIFICATE_REVOKE] = API_BASE_URL + URLS.CERTIFICATE_REVOKE
        self.urls[URLS.CERTIFICATE_RENEW] = API_BASE_URL + URLS.CERTIFICATE_RENEW
        self.urls[URLS.CERTIFICATE_SEARCH] = API_BASE_URL + URLS.CERTIFICATE_SEARCH
        self.urls[URLS.CERTIFICATE_IMPORT] = API_BASE_URL + URLS.CERTIFICATE_IMPORT
        self.urls[URLS.ZONE_CONFIG] = API_BASE_URL + URLS.ZONE_CONFIG
        self.urls[URLS.CONFIG_READ_DN] = API_BASE_URL + URLS.CONFIG_READ_DN

    def _get(self, url=None, params=None):
        # There is no token
        if not self._auth.access_token:
            self.get_access_token()
            log.debug("Token is %s, expire date is %s" % (self._auth.access_token, self._auth.token_expires))

        # Token expired, get new token
        elif self._auth.token_expires and self._auth.token_expires < time.time():
            if self._auth.refresh_token:
                self.refresh_access_token()
                log.debug("Token is %s, expire date is %s" % (self._auth.access_token, self._auth.token_expires))
            else:
                raise AuthenticationError("Access Token expired. No refresh token provided.")

        token = TPPTokenConnection._get_auth_header_value(self._auth.access_token)
        r = requests.get(self._base_url + url, headers={HEADER_AUTHORIZATION: token, 'content-type': MIME_JSON,
                         'cache-control': 'no-cache'}, params=params, **self._http_request_kwargs)

        return self.process_server_response(r)

    def _post(self, url=None, data=None):
        if not self._auth.access_token:
            self.get_access_token()
            log.debug("Token is %s, expire date is %s" % (self._auth.access_token, self._auth.token_expires))

        # Token expired, get new token
        elif self._auth.token_expires and self._auth.token_expires < time.time():
            if self._auth.refresh_token:
                self.refresh_access_token()
                log.debug("Token is %s, expire date is %s" % (self._auth.access_token, self._auth.token_expires))
            else:
                raise AuthenticationError("Access Token expired. No refresh token provided.")

        if isinstance(data, dict):
            token = TPPTokenConnection._get_auth_header_value(self._auth.access_token)
            r = requests.post(self._base_url + url, headers={HEADER_AUTHORIZATION: token, 'content-type': MIME_JSON,
                              "cache-control": "no-cache"}, json=data,  **self._http_request_kwargs)
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
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/$", u):
            raise ClientBadData
        return u

    def auth(self):
        raise NotImplementedError

    def import_cert(self, request):
        raise NotImplementedError

    def get_access_token(self, authentication=None):
        """
        Obtains an access token to be used for subsequent api operations.
        """
        if authentication and isinstance(authentication, Authentication):
            self._auth = authentication

        request_data = {
            "username": self._auth.user,
            "password": self._auth.password,
            "client_id": self._auth.client_id,
            "scope": self._auth.scope,
            "state": "",
        }
        status, resp_data = self._token_post(self.urls[PATH_AUTHORIZE_TOKEN], request_data)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on retrieving access token." % status)

        token_info = self._parse_access_token_data_to_object(resp_data)
        self.update_auth(token_info)
        return token_info

    def refresh_access_token(self):
        request_data = {
            "refresh_token": self._auth.refresh_token,
            "client_id": self._auth.client_id,
        }
        status, resp_data = self._token_post(self.urls[PATH_REFRESH_TOKEN], request_data)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on refreshing access token" % status)

        token_info = self._parse_access_token_data_to_object(resp_data)
        self.update_auth(token_info)
        return token_info

    def revoke_access_token(self):
        status, resp_data = self._get(url=self.urls[PATH_REVOKE_TOKEN])
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on revoking access token" % status)
        return status, resp_data

    def _token_post(self, url, data=None):
        if isinstance(data, dict):
            tpp_url = self._base_url
            response = requests.post(tpp_url + url, json=data,  **self._http_request_kwargs)
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(response)

    def update_auth(self, token_info):
        if isinstance(token_info, TokenInfo):
            self._auth.access_token = token_info.access_token
            self._auth.refresh_token = token_info.refresh_token
            self._auth.token_expire_date = token_info.expires

    @staticmethod
    def _get_auth_header_value(token):
        return 'Bearer ' + token

    @staticmethod
    def _parse_access_token_data_to_object(data):
        identity = ""
        if "identity" in data:
            identity = data["identity"]

        token_info = TokenInfo(
            access_token=data["access_token"],
            expires=data["expires"],
            identity=identity,
            refresh_token=data["refresh_token"],
            refresh_until=data["refresh_until"],
            scope=data["scope"],
            token_type=data["token_type"]
        )
        return token_info
