#
# Copyright 2020 Venafi, Inc.
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
import logging as log
import re
import time

import requests

from .common import MIME_JSON, TokenInfo, Authentication
from .connection_tpp_abstract import AbstractTPPConnection, URLS
from .errors import (ClientBadData, ServerUnexptedBehavior, AuthenticationError)
from .http_status import HTTPStatus

HEADER_AUTHORIZATION = 'Authorization'

KEY_ACCESS_TOKEN = 'access_token'  # nosec
KEY_REFRESH_TOKEN = 'refresh_token'  # nosec
KEY_EXPIRATION_DATE = 'expiration_date'


class TPPTokenConnection(AbstractTPPConnection):
    def __init__(self, url, user=None, password=None, access_token=None, refresh_token=None, http_request_kwargs=None):
        """
        :param str url:
        :param str user:
        :param str password:
        :param str access_token:
        :param str refresh_token:
        :param dict[str,Any] http_request_kwargs:
        """
        super().__init__()

        self._base_url = url  # type: str
        self._auth = Authentication(user=user, password=password, access_token=access_token,
                                    refresh_token=refresh_token)  # type: Authentication
        if http_request_kwargs is None:
            http_request_kwargs = {'timeout': 180}
        elif 'timeout' not in http_request_kwargs:
            http_request_kwargs['timeout'] = 180
        self._http_request_kwargs = http_request_kwargs or {}

    def __setattr__(self, key, value):
        if key == '_base_url':
            value = self._normalize_and_verify_base_url(value)
        self.__dict__[key] = value

    def __str__(self):
        return f"[TPP] {self._base_url}"

    def get(self, args):
        """

        :param dict args:
        :rtype: tuple[Any, Any]
        """
        url = args[self.ARG_URL] if self.ARG_URL in args else None
        params = args[self.ARG_PARAMS] if self.ARG_PARAMS in args else None
        check_token = args[self.ARG_CHECK_TOKEN] if self.ARG_CHECK_TOKEN in args else True
        include_token_header = args[self.ARG_INCLUDE_TOKEN_HEADER] if self.ARG_INCLUDE_TOKEN_HEADER in args else True

        return self._get(url=url, params=params, check_token=check_token, include_token_header=include_token_header)

    def post(self, args):
        """

        :param dict args:
        :rtype: tuple[Any, Any]
        """
        url = args[self.ARG_URL] if self.ARG_URL in args else None
        data = args[self.ARG_DATA] if self.ARG_DATA in args else None
        check_token = args[self.ARG_CHECK_TOKEN] if self.ARG_CHECK_TOKEN in args else True
        include_token_header = args[self.ARG_INCLUDE_TOKEN_HEADER] if self.ARG_INCLUDE_TOKEN_HEADER in args else True

        return self._post(url=url, data=data, check_token=check_token, include_token_header=include_token_header)

    def _get(self, url=None, params=None, check_token=True, include_token_header=True):
        if check_token:
            self._check_token()

        headers = {
            'content-type': MIME_JSON,
            'cache-control': "no-cache"
        }
        if include_token_header:
            token = self._get_auth_header_value(self._auth.access_token)
            headers[HEADER_AUTHORIZATION] = token

        r = requests.get(self._base_url + url, headers=headers, params=params, **self._http_request_kwargs)
        return self.process_server_response(r)

    def _post(self, url=None, data=None, check_token=True, include_token_header=True):
        if check_token:
            self._check_token()

        headers = {
            'content-type': MIME_JSON,
            'cache-control': "no-cache"
        }
        if include_token_header:
            token = self._get_auth_header_value(self._auth.access_token)
            headers[HEADER_AUTHORIZATION] = token

        if isinstance(data, dict):
            log.debug(f"POST Request\n\tURL: {self._base_url+url}\n\tHeaders:{headers}\n\tBody:{data}\n")
            r = requests.post(self._base_url + url, headers=headers, json=data,  **self._http_request_kwargs)
        else:
            log.error(f"Unexpected client data type: {type(data)} for {url}")
            raise ClientBadData
        return self.process_server_response(r)

    def _check_token(self):
        if not self._auth.access_token:
            self.get_access_token()
            log.debug(f"Token is {self._auth.access_token}, expire date is {self._auth.token_expires}")

        # Token expired, get new token
        elif self._auth.token_expires and self._auth.token_expires < time.time():
            if self._auth.refresh_token:
                self.refresh_access_token()
                log.debug(f"Token is {self._auth.access_token}, expire date is {self._auth.token_expires}")
            else:
                raise AuthenticationError("Access Token expired. No refresh token provided.")

    @staticmethod
    def _normalize_and_verify_base_url(u):
        if u.startswith('http://'):
            u = f"https://{u[7:]}"
        elif not u.startswith('https://'):
            u = f"https://{u}"
        if not u.endswith("/"):
            u += "/"
        if not re.match(r"^https://[a-zA-Z\d]+[-a-zA-Z\d.]+[a-zA-Z\d][:\d]*/$", u):
            raise ClientBadData
        return u

    def auth(self):
        raise NotImplementedError

    def get_access_token(self, authentication=None):
        """
        Obtains an access token to be used for subsequent api operations.
        """
        if authentication and isinstance(authentication, Authentication):
            self._auth = authentication

        if self._auth.refresh_token:
            return self.refresh_access_token()

        if self._auth.user is None or self._auth.password is None:
            raise ClientBadData("Missing credentials. Cannot request new access token")

        request_data = {
            'username': self._auth.user,
            'password': self._auth.password,
            'client_id': self._auth.client_id,
            'scope': self._auth.scope,
            'state': "",
        }
        status, resp_data = self._post(URLS.AUTHORIZE_TOKEN, request_data, False, False)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior(f"Server returns {status} status on retrieving access token.")

        token_info = self._parse_access_token_data_to_object(resp_data)
        self._update_auth(token_info)
        return token_info

    def refresh_access_token(self):
        request_data = {
            'refresh_token': self._auth.refresh_token,
            'client_id': self._auth.client_id,
        }
        status, resp_data = self._post(URLS.REFRESH_TOKEN, request_data, False, False)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior(f"Server returns {status} status on refreshing access token")

        token_info = self._parse_access_token_data_to_object(resp_data)
        self._update_auth(token_info)
        return token_info

    def revoke_access_token(self):
        status, resp_data = self._get(url=URLS.REVOKE_TOKEN, params=None, check_token=False)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior(f"Server returns {status} status on revoking access token")
        return status, resp_data

    def _update_auth(self, token_info):
        if isinstance(token_info, TokenInfo):
            self._auth.access_token = token_info.access_token
            self._auth.refresh_token = token_info.refresh_token
            self._auth.token_expire_date = token_info.expires

    @staticmethod
    def _get_auth_header_value(token):
        return f"Bearer {token}"

    @staticmethod
    def _parse_access_token_data_to_object(data):
        token_info = TokenInfo(
            access_token=data['access_token'],
            expires=data['expires'],
            refresh_token=data['refresh_token'],
        )
        return token_info

    def _is_valid_auth(self):
        if self._auth and self._auth.access_token:
            return True
        return False
