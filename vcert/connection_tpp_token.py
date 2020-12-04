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


from __future__ import (absolute_import, division, generators, unicode_literals, print_function, nested_scopes,
                        with_statement)

import base64
import logging as log
import re
import time

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509 import SignatureAlgorithmOID as AlgOID

from .http import HTTPStatus

import requests

from .common import MIME_JSON, TokenInfo, Authentication, CommonConnection, KeyType, Policy, ZoneConfig, CertField
from .errors import (ClientBadData, ServerUnexptedBehavior, AuthenticationError, CertificateRequestError,
                     CertificateRenewError)
from .pem import parse_pem

HEADER_AUTHORIZATION = "Authorization"  # type: str

KEY_ACCESS_TOKEN = "access_token"  # type: str  # nosec
KEY_REFRESH_TOKEN = "refresh_token"  # type: str  # nosec
KEY_EXPIRATION_DATE = "expiration_date"  # type: str


class URLS:
    API_TOKEN_URL = "vedauth/"  # type: str  # nosec
    API_BASE_URL = "vedsdk/"  # type: str  # nosec

    AUTHORIZE_TOKEN = API_TOKEN_URL + "authorize/oauth"  # type: str
    REFRESH_TOKEN = API_TOKEN_URL + "authorize/token"  # type: str
    REVOKE_TOKEN = API_TOKEN_URL + "revoke/token"  # type: str

    AUTHORIZE = API_BASE_URL + "authorize/"
    CERTIFICATE_REQUESTS = API_BASE_URL + "certificates/request"
    CERTIFICATE_RETRIEVE = API_BASE_URL + "certificates/retrieve"
    FIND_POLICY = API_BASE_URL + "config/findpolicy"
    CERTIFICATE_REVOKE = API_BASE_URL + "certificates/revoke"
    CERTIFICATE_RENEW = API_BASE_URL + "certificates/renew"
    CERTIFICATE_SEARCH = API_BASE_URL + "certificates/"
    CERTIFICATE_IMPORT = API_BASE_URL + "certificates/import"
    ZONE_CONFIG = API_BASE_URL + "certificates/checkpolicy"
    CONFIG_READ_DN = API_BASE_URL + "Config/ReadDn"


class TPPTokenConnection(CommonConnection):
    def __init__(self, url, user=None, password=None, access_token=None, refresh_token=None, http_request_kwargs=None):
        """
        :param str url:
        :param str user:
        :param str password:
        :param str access_token:
        :param str refresh_token:
        :param dict[str,Any] http_request_kwargs:
        """
        self._base_url = url  # type: str
        self._auth = Authentication(user=user, password=password, access_token=access_token,
                                    refresh_token=refresh_token)  # type: Authentication
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

    def _get(self, url=None, params=None, check_token=True, include_headers=True):
        if check_token:
            self._check_token()

        headers = {}
        if include_headers:
            token = self._get_auth_header_value(self._auth.access_token)
            headers = {HEADER_AUTHORIZATION: token, 'content-type': MIME_JSON, 'cache-control': 'no-cache'}

        r = requests.get(self._base_url + url, headers=headers, params=params, **self._http_request_kwargs)
        return self.process_server_response(r)

    def _post(self, url=None, data=None, check_token=True, include_headers=True):
        if check_token:
            self._check_token()

        headers = {}
        if include_headers:
            token = self._get_auth_header_value(self._auth.access_token)
            headers = {HEADER_AUTHORIZATION: token, 'content-type': MIME_JSON, "cache-control": "no-cache"}

        if isinstance(data, dict):
            r = requests.post(self._base_url + url, headers=headers, json=data,  **self._http_request_kwargs)
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(r)

    def _check_token(self):
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

    # TODO: Need to add service generated CSR implementation
    def request_cert(self, request, zone):
        if not request.csr:
            request.build_csr()
        request_data = {"PolicyDN": self._get_policy_dn(zone),
                        "PKCS10": request.csr,
                        "ObjectName": request.friendly_name,
                        "DisableAutomaticRenewal": "true"}
        if request.origin:
            request_data["Origin"] = request.origin
            ca_origin = {"Name": "Origin", "Value": request.origin}
            if request_data.get("CASpecificAttributes"):
                request_data["CASpecificAttributes"].append(ca_origin)
            else:
                request_data["CASpecificAttributes"] = [ca_origin]

        if request.custom_fields:
            custom_fields_map = {}
            for c_field in request.custom_fields:
                if custom_fields_map.get(c_field.name):
                    custom_fields_map[c_field.name].append(c_field.value)
                else:
                    custom_fields_map[c_field.name] = [c_field.value]

            for key in custom_fields_map:
                custom_field_json = {
                    "Name": key,
                    "Values": custom_fields_map[key]
                }
                if request_data.get("CustomFields"):
                    request_data["CustomFields"].append(custom_field_json)
                else:
                    request_data["CustomFields"] = [custom_field_json]

        status, data = self._post(URLS.CERTIFICATE_REQUESTS, data=request_data)
        if status == HTTPStatus.OK:
            request.id = data['CertificateDN']
            log.debug("Certificate sucessfully requested with request id %s." % request.id)
            return True

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
        else:
            raise ClientBadData
        if request.comments:
            d["Comments"] = request.comments
        status, data = self._post(URLS.CERTIFICATE_REVOKE, data=d)
        if status in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
            return data
        else:
            raise ServerUnexptedBehavior

    def renew_cert(self, request, reuse_key=False):
        if not request.id and not request.thumbprint:
            log.debug("Request id or thumbprint must be specified for TPP")
            raise CertificateRenewError
        if not request.id and request.thumbprint:
            request.id = self.search_by_thumbprint(request.thumbprint)
        if reuse_key:
            log.debug("Trying to renew certificate %s" % request.id)
            status, data = self._post(URLS.CERTIFICATE_RENEW, data={"CertificateDN": request.id})
            if not data['Success']:
                raise CertificateRenewError
            return
        cert = self.retrieve_cert(request)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        for a in cert.subject:
            if a.oid == x509.NameOID.COMMON_NAME:
                request.common_name = a.value
            elif a.oid == x509.NameOID.COUNTRY_NAME:
                request.country = a.value
            elif a.oid == x509.NameOID.LOCALITY_NAME:
                request.locality = a.value
            elif a.oid == x509.NameOID.STATE_OR_PROVINCE_NAME:
                request.province = a.value
            elif a.oid == x509.NameOID.ORGANIZATION_NAME:
                request.organization = a.value
            elif a.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                request.organizational_unit = a.value
        for e in cert.extensions:
            if e.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME:
                request.san_dns = list([x.value for x in e.value if isinstance(x, x509.DNSName)])
                request.email_addresses = list([x.value for x in e.value if isinstance(x, x509.RFC822Name)])
                request.ip_addresses = list([x.value.exploded for x in e.value if isinstance(x, x509.IPAddress)])
                # remove header bytes from ASN1 encoded UPN field before setting it in the request object
                upns = []
                for x in e.value:
                    if isinstance(x,x509.OtherName):
                        upns.append(x.value[2 : :])
                request.user_principal_names = upns
                request.uniform_resource_identifiers = list([x.value for x in e.value if isinstance(x,x509.UniformResourceIdentifier)])
        if cert.signature_algorithm_oid in (AlgOID.ECDSA_WITH_SHA1, AlgOID.ECDSA_WITH_SHA224, AlgOID.ECDSA_WITH_SHA256,
                                            AlgOID.ECDSA_WITH_SHA384, AlgOID.ECDSA_WITH_SHA512):
            request.key_type = (KeyType.ECDSA, KeyType.ALLOWED_CURVES[0])
        else:
            request.key_type = KeyType(KeyType.RSA, 2048)  # todo: make parsing key size
        if not request.csr:
            request.build_csr()
        status, data = self._post(URLS.CERTIFICATE_RENEW,
                                  data={"CertificateDN": request.id, "PKCS10": request.csr})
        if status == HTTPStatus.OK:
            if "CertificateDN" in data:
                request.id = data['CertificateDN']
            log.debug("Certificate successfully requested with request id %s." % request.id)
            return True

        log.error("Request status is not %s. %s." % HTTPStatus.OK, status)
        raise CertificateRequestError

    @staticmethod
    def _parse_zone_config_to_policy(data):
        # todo: parse over values to regexps (dont forget tests!)
        p = data["Policy"]
        if p["KeyPair"]["KeyAlgorithm"]["Locked"]:
            if p["KeyPair"]["KeyAlgorithm"]["Value"] == "RSA":
                if p["KeyPair"]["KeySize"]["Locked"]:
                    key_types = [KeyType(KeyType.RSA, p["KeyPair"]["KeySize"]["Value"])]
                else:
                    key_types = [KeyType(KeyType.RSA, x) for x in KeyType.ALLOWED_SIZES]
            elif p["KeyPair"]["KeyAlgorithm"]["Value"] == "ECC":
                if p["KeyPair"]["EllipticCurve"]["Locked"]:
                    key_types = [KeyType(KeyType.ECDSA, p["KeyPair"]["EllipticCurve"]["Value"])]
                else:
                    key_types = [KeyType(KeyType.ECDSA, x) for x in KeyType.ALLOWED_CURVES]
            else:
                raise ServerUnexptedBehavior
        else:
            key_types = []
            if p["KeyPair"].get("KeySize", {}).get("Locked"):
                key_types += [KeyType(KeyType.RSA, p["KeyPair"]["KeySize"]["Value"])]
            else:
                key_types += [KeyType(KeyType.RSA, x) for x in KeyType.ALLOWED_SIZES]
            if p["KeyPair"].get("EllipticCurve", {}).get("Locked"):
                key_types += [KeyType(KeyType.ECDSA, p["KeyPair"]["EllipticCurve"]["Value"])]
            else:
                key_types += [KeyType(KeyType.ECDSA, x) for x in KeyType.ALLOWED_CURVES]
        return Policy(key_types=key_types)

    @staticmethod
    def _parse_zone_data_to_object(data):
        s = data["Policy"]["Subject"]
        ou = s['OrganizationalUnit'].get('Values')
        policy = TPPTokenConnection._parse_zone_config_to_policy(data)
        if data["Policy"]["KeyPair"]["KeyAlgorithm"]["Value"] == "RSA":
            key_type = KeyType(KeyType.RSA, data["Policy"]["KeyPair"]["KeySize"]["Value"])
        elif data["Policy"]["KeyPair"]["KeyAlgorithm"]["Value"] == "ECC":
            key_type = KeyType(KeyType.ECDSA, data["Policy"]["KeyPair"]["EllipticCurve"]["Value"])
        else:
            key_type = None
        z = ZoneConfig(
            organization=CertField(s['Organization']['Value'], locked=s['Organization']['Locked']),
            organizational_unit=CertField(ou, locked=s['OrganizationalUnit']['Locked']),
            country=CertField(s['Country']['Value'], locked=s['Country']['Locked']),
            province=CertField(s['State']['Value'], locked=s['State']['Locked']),
            locality=CertField(s['City']['Value'], locked=s['City']['Locked']),
            policy=policy,
            key_type=key_type,
        )
        return z

    def read_zone_conf(self, tag):
        status, data = self._post(URLS.ZONE_CONFIG, {"PolicyDN": self._get_policy_dn(tag)})
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on reading zone configuration." % status)
        return self._parse_zone_data_to_object(data)

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

    def _read_config_dn(self, dn, attribute_name):
        status, data = self._post(URLS.CONFIG_READ_DN, {
            "ObjectDN": dn,
            "AttributeName": attribute_name,
        })
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("")
        return data

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
            "username": self._auth.user,
            "password": self._auth.password,
            "client_id": self._auth.client_id,
            "scope": self._auth.scope,
            "state": "",
        }
        status, resp_data = self._post(URLS.AUTHORIZE_TOKEN, request_data, False, False)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on retrieving access token." % status)

        token_info = self._parse_access_token_data_to_object(resp_data)
        self._update_auth(token_info)
        return token_info

    def refresh_access_token(self):
        request_data = {
            "refresh_token": self._auth.refresh_token,
            "client_id": self._auth.client_id,
        }
        status, resp_data = self._post(URLS.REFRESH_TOKEN, request_data, False, False)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on refreshing access token" % status)

        token_info = self._parse_access_token_data_to_object(resp_data)
        self._update_auth(token_info)
        return token_info

    def revoke_access_token(self):
        status, resp_data = self._get(url=URLS.REVOKE_TOKEN, params=None, check_token=False)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on revoking access token" % status)
        return status, resp_data

    def _update_auth(self, token_info):
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
