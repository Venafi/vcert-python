#
# Copyright 2022 Venafi, Inc.
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

from .common import MIME_JSON
from .connection_tpp_abstract import AbstractTPPConnection, URLS
from .errors import (ServerUnexptedBehavior, ClientBadData, AuthenticationError)
from .http_status import HTTPStatus

TOKEN_HEADER_NAME = "x-venafi-api-key"  # nosec


class TPPConnection(AbstractTPPConnection):
    def __init__(self, user, password, url, http_request_kwargs=None):
        """
        :param str user:
        :param str password:
        :param str url:
        :param dict[str,Any] http_request_kwargs:
        """
        super().__init__()
        self._base_url = url  # type: str
        self._user = user  # type: str
        self._password = password  # type: str
        self._token = None  # type: tuple
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

        return self._get(url=url, params=params)

    def post(self, args):
        """

        :param dict args:
        :rtype: tuple[Any, Any]
        """
        url = args[self.ARG_URL] if self.ARG_URL in args else None
        data = args[self.ARG_DATA] if self.ARG_DATA in args else None

        return self._post(url=url, data=data)

    def _get(self, url="", params=None):
        if not self._token or self._token[1] < time.time() + 1:
            self.auth()
            log.debug(f"Token is {self._token[0]}, timeout is {self._token[1]}")

        r = requests.get(f"{self._base_url}{url}",
                         headers={TOKEN_HEADER_NAME: self._token[0],
                                  'content-type': MIME_JSON,
                                  'cache-control': 'no-cache'},
                         params=params,
                         **self._http_request_kwargs)  # nosec B113
        return self.process_server_response(r)

    def _post(self, url, data=None):
        if not self._token or self._token[1] < time.time() + 1:
            self.auth()
            log.debug(f"Token is {self._token[0]}, timeout is {self._token[1]}")

        if isinstance(data, dict):
            r = requests.post(f"{self._base_url}{url}",
                              headers={TOKEN_HEADER_NAME: self._token[0],
                                       'content-type': MIME_JSON,
                                       'cache-control': "no-cache"},
                              json=data,
                              **self._http_request_kwargs)  # nosec B113
        else:
            log.error(f"Unexpected client data type: {type(data)} for {url}")
            raise ClientBadData
        return self.process_server_response(r)

    @staticmethod
    def _normalize_and_verify_base_url(u):
        if u.startswith('http://'):  # nosec
            u = f"https://{u[7:]}"
        elif not u.startswith('https://'):
            u = f"https://{u}"
        if not u.endswith("/"):
            u += "/"
        if u.endswith(URLS.API_BASE_URL):
            u = u[:len(u)-7]  # "vedsdk/"
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/$", u):
            raise ClientBadData
        return u

    def auth(self):
        data = {'Username': self._user, 'Password': self._password}
        r = requests.post(f"{self._base_url}{URLS.AUTHORIZE}",
                          json=data,
                          headers={'content-type': MIME_JSON,
                                   'cache-control': "no-cache"},
                          **self._http_request_kwargs)  # nosec B113

        status, user = self.process_server_response(r)
        if status == HTTPStatus.OK:
            valid_until = int(re.sub(r"\D", "", user["ValidUntil"]))
            self._token = user["APIKey"], valid_until
            return user
        else:
            log.error(f"Authentication status is not {HTTPStatus.OK} but {status[0]}. Exiting")
            raise AuthenticationError

    def _read_config_dn(self, dn, attribute_name):
        status, data = self._post(URLS.CONFIG_READ_DN, {
            'ObjectDN': dn,
            'AttributeName': attribute_name,
        })
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("")
        return data

    def _is_valid_auth(self):
        if self._token:
            return True
        return False
