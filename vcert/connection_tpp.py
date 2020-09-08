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

import requests

from .common import MIME_JSON
from .connection_tpp_common import TPPCommonConnection, URLS
from .errors import (ClientBadData, AuthenticationError, ServerUnexptedBehavior)
from .http import HTTPStatus


TOKEN_HEADER_NAME = "x-venafi-api-key"  # nosec


class TPPConnection(TPPCommonConnection):
    def __init__(self, user, password, url, http_request_kwargs=None):
        """
        :param str user:
        :param str password:
        :param str url:
        :param dict[str,Any] http_request_kwargs:
        """
        super().__init__(http_request_kwargs=http_request_kwargs)
        self._base_url = url  # type: str
        self._user = user  # type: str
        self._password = password  # type: str
        self._token = None  # type: tuple

    def _create_url_dictionary(self):
        self.urls = dict()
        self.urls[URLS.CERTIFICATE_REQUESTS] = URLS.CERTIFICATE_REQUESTS
        self.urls[URLS.CERTIFICATE_RETRIEVE] = URLS.CERTIFICATE_RETRIEVE
        self.urls[URLS.FIND_POLICY] = URLS.FIND_POLICY
        self.urls[URLS.CERTIFICATE_REVOKE] = URLS.CERTIFICATE_REVOKE
        self.urls[URLS.CERTIFICATE_RENEW] = URLS.CERTIFICATE_RENEW
        self.urls[URLS.CERTIFICATE_SEARCH] = URLS.CERTIFICATE_SEARCH
        self.urls[URLS.CERTIFICATE_IMPORT] = URLS.CERTIFICATE_IMPORT
        self.urls[URLS.ZONE_CONFIG] = URLS.ZONE_CONFIG
        self.urls[URLS.CONFIG_READ_DN] = URLS.CONFIG_READ_DN

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

    def import_cert(self, request):
        raise NotImplementedError

    def _read_config_dn(self, dn, attribute_name):
        status, data = self._post(self.urls[URLS.CONFIG_READ_DN], {
            "ObjectDN": dn,
            "AttributeName": attribute_name,
        })
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("")
        return data
