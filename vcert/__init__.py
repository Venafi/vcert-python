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

from .common import CertificateRequest, CommonConnection, RevocationRequest, ZoneConfig, CertField, KeyType, \
    CustomField, Authentication, SCOPE_CM, SCOPE_PM, SCOPE_SSH
from .connection_cloud import CloudConnection
from .connection_tpp import TPPConnection
from .connection_tpp_token import TPPTokenConnection
from .connection_fake import FakeConnection
from .pem import Certificate
from .ssh_utils import SSHCertRequest, SSHKeyPair, write_ssh_files


def Connection(url=None, token=None, user=None, password=None, fake=False, http_request_kwargs=None):
    """
    Return connection based on credentials list.
    Venafi Platform (TPP) required URL, user, password
    Cloud required token and optional URL
    Fake required no parameters
    :param str url: TPP or Venafi Cloud URL (for Cloud is optional)
    :param str token: Venafi Cloud token
    :param str user: TPP user
    :param str password: TPP password
    :param bool fake: Use fake connection
    :param dict[str, Any] http_request_kwargs: Option for work with untrusted  https certificate (only for TPP).
    :rtype CommonConnection:
    """
    if fake:
        return FakeConnection()
    if url and user and password:
        return TPPConnection(user=user, password=password, url=url, http_request_kwargs=http_request_kwargs)
    if token:
        return CloudConnection(token=token, url=url, http_request_kwargs=http_request_kwargs)
    else:
        raise Exception("Bad credentials list")


def venafi_connection(url=None, api_key=None, user=None, password=None, access_token=None, refresh_token=None,
                      fake=False, http_request_kwargs=None):
    """
    Return connection based on credentials list.
    Venafi Platform (TPP) requires URL and access_token (or user and password for getting a new access_token)
    Cloud requires api_key and optional URL
    Fake requires no parameters
    :param str url: TPP or Venafi Cloud URL (for Cloud is optional)
    :param str api_key: Venafi Cloud API Key
    :param str user: TPP username for getting new tokens
    :param str password: TPP password for getting new tokens
    :param str access_token: TPP access token
    :param str refresh_token: TPP refresh token (optional)
    :param bool fake: Use fake connection
    :param dict[str, Any] http_request_kwargs: Option for specifying trust bundle or to operate insecurely.
    :rtype CommonConnection:
    """
    if fake:
        return FakeConnection()
    if url and (access_token or refresh_token or (user and password)):
        return TPPTokenConnection(url=url, user=user, password=password, access_token=access_token,
                                  refresh_token=refresh_token, http_request_kwargs=http_request_kwargs)
    if api_key:
        return CloudConnection(token=api_key, url=url, http_request_kwargs=http_request_kwargs)
    else:
        raise Exception("Bad credentials list")
