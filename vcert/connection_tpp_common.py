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
from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509 import SignatureAlgorithmOID as algos

from .common import CommonConnection, CertField, ZoneConfig, Policy, KeyType
from .pem import parse_pem
from .errors import (ServerUnexptedBehavior, ClientBadData, CertificateRequestError, CertificateRenewError)
from .http import HTTPStatus


class URLS:
    AUTHORIZE = "authorize/"
    CERTIFICATE_REQUESTS = "certificates/request"
    CERTIFICATE_RETRIEVE = "certificates/retrieve"
    FIND_POLICY = "config/findpolicy"
    CERTIFICATE_REVOKE = "certificates/revoke"
    CERTIFICATE_RENEW = "certificates/renew"
    CERTIFICATE_SEARCH = "certificates/"
    CERTIFICATE_IMPORT = "certificates/import"
    ZONE_CONFIG = "certificates/checkpolicy"
    CONFIG_READ_DN = "Config/ReadDn"


class TPPCommonConnection(CommonConnection, ABC):
    def __init__(self, http_request_kwargs=None):
        """
        :param str url:
        :param dict[str,Any] http_request_kwargs:
        """
        if http_request_kwargs is None:
            http_request_kwargs = {"timeout": 180}
        elif "timeout" not in http_request_kwargs:
            http_request_kwargs["timeout"] = 180
        self._http_request_kwargs = http_request_kwargs or {}
        self.urls = dict()
        self._create_url_dictionary()

    def __setattr__(self, key, value):
        if key == "_base_url":
            value = self._normalize_and_verify_base_url(value)
        self.__dict__[key] = value

    def __str__(self):
        return "[TPP] %s" % self._base_url

    @abstractmethod
    def _create_url_dictionary(self):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def _normalize_and_verify_base_url(u):
        raise NotImplementedError

    @abstractmethod
    def _get(self, url=None, params=None):
        raise NotImplementedError

    @abstractmethod
    def _post(self, url=None, data=None):
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
        status, data = self._post(self.urls[URLS.CERTIFICATE_REQUESTS], data=request_data)
        if status == HTTPStatus.OK:
            request.id = data['CertificateDN']
            log.debug("Certificate sucessfully requested with request id %s." % request.id)
            return True
        else:
            log.error("Request status is not %s. %s." % HTTPStatus.OK, status)
            raise CertificateRequestError

    def retrieve_cert(self, certificate_request):
        log.debug("Getting certificate status for id %s" % certificate_request.id)

        retrieve_request = dict(CertificateDN=certificate_request.id, Format="base64", IncludeChain='true')

        if certificate_request.chain_option == "last":
            retrieve_request['RootFirstOrder'] = 'false'
            retrieve_request['IncludeChain'] = 'true'
        elif certificate_request.chain_option == "first":
            retrieve_request['RootFirstOrder'] = 'true'
            retrieve_request['IncludeChain'] = 'true'
        elif certificate_request.chain_option == "ignore":
            retrieve_request['IncludeChain'] = 'false'
        else:
            log.error("chain option %s is not valid" % certificate_request.chain_option)
            raise ClientBadData

        status, data = self._post(self.urls[URLS.CERTIFICATE_RETRIEVE], data=retrieve_request)
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
        status, data = self._post(self.urls[URLS.CERTIFICATE_REVOKE], data=d)
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
            status, data = self._post(self.urls[URLS.CERTIFICATE_RENEW], data={"CertificateDN": request.id})
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
        if cert.signature_algorithm_oid in (algos.ECDSA_WITH_SHA1, algos.ECDSA_WITH_SHA224, algos.ECDSA_WITH_SHA256,
                                            algos.ECDSA_WITH_SHA384, algos.ECDSA_WITH_SHA512):
            request.key_type = (KeyType.ECDSA, KeyType.ALLOWED_CURVES[0])
        else:
            request.key_type = KeyType(KeyType.RSA, 2048)  # todo: make parsing key size
        if not request.csr:
            request.build_csr()
        status, data = self._post(self.urls[URLS.CERTIFICATE_RENEW],
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
        policy = TPPCommonConnection._parse_zone_config_to_policy(data)
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
        status, data = self._post(self.urls[URLS.ZONE_CONFIG], {"PolicyDN":  self._get_policy_dn(tag)})
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
        status, data = self._get(self.urls[URLS.CERTIFICATE_SEARCH], params={"Thumbprint": thumbprint})
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior

        if not data['Certificates']:
            raise ClientBadData("Certificate not found by thumbprint")
        return data['Certificates'][0]['DN']

    @abstractmethod
    def _read_config_dn(self, dn, attribute_name):
        raise NotImplementedError
