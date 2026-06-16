#
# Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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
from .common import (CertificateRequest, CommonConnection, RevocationRequest, ZoneConfig, CertField, KeyType,
                     CustomField, Authentication, SCOPE_CM, SCOPE_PM, SCOPE_SSH, CSR_ORIGIN_LOCAL, CSR_ORIGIN_PROVIDED,
                     CSR_ORIGIN_SERVICE, CHAIN_OPTION_FIRST, CHAIN_OPTION_IGNORE, CHAIN_OPTION_LAST, VenafiPlatform)
from .connection_cloud import CloudConnection
from .connection_ngts import NGTSConnection
from .connection_tpp import TPPConnection
from .connection_tpp_token import TPPTokenConnection
from .connection_fake import FakeConnection
from .errors import VenafiError
from .logger import setup_logger, get_logger, get_child
from .pem import Certificate
from .ssh_utils import SSHCertRequest, SSHKeyPair, write_ssh_files, SSHCATemplateRequest, SSHConfig
from .tpp_utils import IssuerHint

setup_logger()


def Connection(url=None, token=None, user=None, password=None, fake=False, http_request_kwargs=None):
    """
    Return connection based on credentials list.
    CyberArk Platform (CyberArk Certificate Manager, Self-Hosted) required URL, user, password
    Cloud required token and optional URL
    Fake required no parameters
    :param str url: CyberArk Certificate Manager, Self-Hosted or CyberArk Certificate Manager, SaaS URL (for Cloud is optional)
    :param str token: CyberArk Certificate Manager, SaaS token
    :param str user: CyberArk Certificate Manager, Self-Hosted user
    :param str password: CyberArk Certificate Manager, Self-Hosted password
    :param bool fake: Use fake connection
    :param dict[str, Any] http_request_kwargs: Option for work with untrusted  https certificate (only for CyberArk Certificate Manager, Self-Hosted).
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
                      fake=False, http_request_kwargs=None, platform=None, client_id=None, client_secret=None,
                      token_url=None, scope=None, tsg_id=None):
    """
    Return connection based on credentials list.
    CyberArk Platform (CyberArk Certificate Manager, Self-Hosted) requires URL and access_token (or user and password for getting a new access_token)
    Cloud requires api_key and optional URL
    NGTS (Palo Alto Networks Next-Gen Trust Security) requires OAuth2 service-account credentials (client_id, client_secret, tsg_id/scope); url and token_url are optional and default to the Palo Alto production endpoints
    Fake requires no parameters
    :param str url: CyberArk Certificate Manager, Self-Hosted / SaaS / NGTS URL (optional for Cloud and NGTS)
    :param str api_key: CyberArk Certificate Manager, SaaS API Key
    :param str user: CyberArk Certificate Manager, Self-Hosted username for getting new tokens
    :param str password: CyberArk Certificate Manager, Self-Hosted password for getting new tokens
    :param str access_token: CyberArk Certificate Manager, Self-Hosted access token (or a pre-issued NGTS access token)
    :param str refresh_token: CyberArk Certificate Manager, Self-Hosted refresh token (optional)
    :param bool fake: Use fake connection
    :param dict[str, Any] http_request_kwargs: Option for specifying trust bundle or to operate insecurely.
    :param VenafiPlatform platform: The platform to be used with the Connector
    :param str client_id: NGTS OAuth2 service-account client id
    :param str client_secret: NGTS OAuth2 service-account client secret
    :param str token_url: NGTS OAuth2 token endpoint (optional; defaults to the Palo Alto production endpoint, override for non-production environments)
    :param str scope: NGTS OAuth2 scope (``tsg_id:<TSG_ID>``); derived from tsg_id when omitted
    :param str tsg_id: NGTS tenant service group id
    :rtype CommonConnection:
    """
    if platform:
        if platform == VenafiPlatform.FAKE:
            return FakeConnection()
        elif platform == VenafiPlatform.TPP:
            return TPPTokenConnection(url=url, user=user, password=password, access_token=access_token,
                                      refresh_token=refresh_token, http_request_kwargs=http_request_kwargs)
        elif platform == VenafiPlatform.VAAS:
            return CloudConnection(token=api_key, url=url, http_request_kwargs=http_request_kwargs)
        elif platform == VenafiPlatform.NGTS:
            return NGTSConnection(client_id=client_id, client_secret=client_secret, token_url=token_url, scope=scope,
                                  tsg_id=tsg_id, access_token=access_token, url=url,
                                  http_request_kwargs=http_request_kwargs)
        else:
            raise VenafiError(f"Invalid Platform: {platform}. Cannot instantiate a Connector.")
    else:
        if fake:
            return FakeConnection()
        # NGTS is detected before the TPP/Cloud branches so its OAuth service-account credentials
        # are not shadowed by them. client_id + client_secret are NGTS-specific (TPP/Cloud use
        # neither); token_url is optional now that it defaults to the production endpoint.
        if client_id and client_secret:
            return NGTSConnection(client_id=client_id, client_secret=client_secret, token_url=token_url, scope=scope,
                                  tsg_id=tsg_id, access_token=access_token, url=url,
                                  http_request_kwargs=http_request_kwargs)
        if url and (access_token or refresh_token or (user and password)):
            return TPPTokenConnection(url=url, user=user, password=password, access_token=access_token,
                                      refresh_token=refresh_token, http_request_kwargs=http_request_kwargs)
        if api_key:
            return CloudConnection(token=api_key, url=url, http_request_kwargs=http_request_kwargs)
        else:
            raise VenafiError("Bad credentials list")
