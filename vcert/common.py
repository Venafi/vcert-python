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

from __future__ import absolute_import, division, generators, unicode_literals, print_function, nested_scopes, \
    with_statement

import datetime
import logging as log
import socket
import sys

import ipaddress
from builtins import bytes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
from six import string_types, binary_type

from .errors import VenafiConnectionError, ServerUnexptedBehavior, BadData, ClientBadData
from .http import HTTPStatus
from .policy import PolicySpecification


MIME_JSON = "application/json"
MIME_HTML = "text/html"
MIME_TEXT = "text/plain"
MIME_CSV = "text/csv"
MIME_ANY = "*/*"
LOCALHOST = "127.0.0.1"


class CertField:
    def __init__(self, value, locked=False):
        self.value = value
        self.locked = locked

    def __bool__(self):
        return bool(self.value)


def log_errors(data):
    if not isinstance(data, dict) or "errors" not in data:
        log.error("Unknown error format: %s", data)
        return
    for e in data["errors"]:
        log.error("%s: %s" % (e['code'], e['message']))


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = None
    try:
        # doesn't even have to be reachable, it just allows the socket to be opened
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = LOCALHOST
    finally:
        s.close()
    return ip


class KeyType:
    ALLOWED_SIZES = [2048, 3072, 4096, 8192]
    ALLOWED_CURVES = ["p256", "p384", "p521"]
    RSA = "rsa"
    ECDSA = "ec"

    def __init__(self, key_type, option):
        """
        :param str key_type:
        :param Union[str, int] option: key length for RSA (in int) or curve name for ECDSA
        """
        self.key_type = {"rsa": "rsa", "ec": "ec", "ecdsa": "ec"}.get(key_type.lower().strip())
        if self.key_type == KeyType.RSA:
            if option not in KeyType.ALLOWED_SIZES:
                log.error("unknown size: %s" % option)
                raise BadData
        elif self.key_type == KeyType.ECDSA:
            option = {"secp521r1": "p521", "secp384r1": "p384", "secp256r1": "p256", "p256": "p256", "p384": "p384",
                      "p521": "p521"}[option.lower().strip()]
            if option not in KeyType.ALLOWED_CURVES:
                log.error("unknown curve: %s, should be one of %s" % (option, KeyType.ALLOWED_CURVES))
                raise BadData
        else:
            log.error("unknown key type: %s" % key_type)
            raise BadData
        self.option = option

    def __repr__(self):
        return "KeyType(%s, %s)" % (self.key_type, self.option)

    def __eq__(self, other):
        if not isinstance(other, KeyType):
            return False
        return self.key_type == other.key_type and self.option == other.option


class ZoneConfig:
    def __init__(self, organization, organizational_unit, country, province, locality,
                 policy, key_type):
        """
        :param CertField organization:
        :param CertField organizational_unit:
        :param CertField country:
        :param CertField province:
        :param CertField locality:
        :param Policy policy:
        :param KeyType key_type:
        """
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.country = country
        self.province = province
        self.locality = locality
        self.policy = policy
        self.key_type = key_type


class TokenInfo:
    def __init__(self, access_token, expires, identity, refresh_token, refresh_until,
                 scope, token_type):
        self.access_token = access_token
        self.expires = expires
        self.identity = identity
        self.refresh_token = refresh_token
        self.refresh_until = refresh_until
        self.scope = scope
        self.token_type = token_type


class Policy:
    # This is the Certificate Issuing Template.
    # It is used by both TPP and Cloud implementations, hence the name was adapted to something more generic.
    def __init__(self, policy_id=None, company_id=None, name=None, system_generated=None,
                 creation_date=None, subject_cn_regexes=None, subject_o_regexes=None,
                 subject_ou_regexes=None, subject_st_regexes=None, subject_l_regexes=None, subject_c_regexes=None,
                 san_regexes=None, key_types=None, key_reuse=None, cert_authority=None, cert_authority_account_id=None,
                 cert_authority_product_option_id=None, priority=None, modification_date=None, status=None, reason=None,
                 validity_period=None, recommended_settings=None):
        """
        :param str policy_id:
        :param str company_id:
        :param str name:
        :param bool system_generated:
        :param datetime.datetime creation_date:
        :param list[str] subject_cn_regexes:
        :param list[str] subject_o_regexes:
        :param list[str] subject_ou_regexes:
        :param list[str] subject_st_regexes:
        :param list[str] subject_l_regexes:
        :param list[str] subject_c_regexes:
        :param list[str] san_regexes:
        :param list[KeyType] key_types:
        :param bool key_reuse:
        :param str cert_authority:
        :param str cert_authority_account_id:
        :param str cert_authority_product_option_id:
        :param int priority:
        :param str modification_date:
        :param str status:
        :param str reason:
        :param str validity_period:
        :param RecommendedSettings recommended_settings:
        """
        self.id = policy_id
        self.company_id = company_id
        self.name = name
        self.system_generated = system_generated
        self.creation_date = creation_date
        self.SubjectCNRegexes = subject_cn_regexes
        self.SubjectORegexes = subject_o_regexes
        self.SubjectOURegexes = subject_ou_regexes
        self.SubjectSTRegexes = subject_st_regexes
        self.SubjectLRegexes = subject_l_regexes
        self.SubjectCRegexes = subject_c_regexes
        self.SANRegexes = san_regexes
        self.key_types = key_types
        self.key_reuse = key_reuse

        self.cert_authority = cert_authority
        self.cert_authority_account_id = cert_authority_account_id
        self.cert_authority_product_option_id = cert_authority_product_option_id
        self.priority = priority
        self.modification_date = modification_date
        self.status = status
        self.reason = reason
        self.validity_period = validity_period
        self.recommended_settings = recommended_settings

    def __repr__(self):
        return "Policy:\n" + "\n".join(["  %s: %s" % (k, v) for k, v in (
            ("Id", self.id),
            ("Name", self.name),
            ("KeyReuse", self.key_reuse),
            ("Created", self.creation_date)
        )])

    def __str__(self):
        return self.name


class RecommendedSettings:
    def __init__(self, subject_o_value=None, subject_ou_value=None, subject_l_value=None, subject_st_value=None,
                 subject_c_value=None, key_type=None, key_reuse=None):
        """
        :param str subject_o_value:
        :param str subject_ou_value:
        :param str subject_l_value:
        :param str subject_st_value:
        :param str subject_c_value:
        :param KeyType key_type:
        :param bool key_reuse:
        """
        self.subjectOValue = subject_o_value
        self.subjectOUValue = subject_ou_value
        self.subjectLValue = subject_l_value
        self.subjectSTValue = subject_st_value
        self.subjectCValue = subject_c_value
        self.keyType = key_type
        self.keyReuse = key_reuse


class CertificateRequest:
    def __init__(self, cert_id=None,
                 san_dns=None,
                 email_addresses="",
                 ip_addresses=None,
                 user_principal_names=None,
                 uniform_resource_identifiers=None,
                 attributes=None,
                 key_type=None,
                 private_key=None,
                 key_password=None,
                 csr=None,
                 friendly_name=None,
                 common_name=None,
                 thumbprint=None,
                 organization=None,
                 organizational_unit=None,
                 country=None,
                 province=None,
                 locality=None,
                 origin=None,
                 custom_fields=None,
                 ):
        """
        :param str cert_id: Certificate request id. Generating by server.
        :param list[str] san_dns: Alternative names for SNI.
        :param list[str] email_addresses: List of email addresses
        :param list[str] ip_addresses: List of IP addresses
        :param list[str] user_principal_names: user principal names in username@domain format
        :param list[str] uniform_resource_identifiers: URIs
        :param attributes:
        :param KeyType key_type: Type of asymmetric cryptography algorithm. Default is RSA 2048.
        :param asymmetric.PrivateKey private_key: String with pem encoded private key or  asymmetric.PrivateKey
        :param str key_password: Password for encrypted private key. Not supported at this moment.
        :param str csr: Certificate Signing Request in pem format
        :param str friendly_name: Name for certificate in the platform. If not specified common name will be used.
        :param str common_name: Common name of certificate. Usually domain name.
        :param str thumbprint: Certificate thumbprint. Can be used for identifying certificate on the platform.
        :param str origin: application identifier
        :param list[CustomField] custom_fields: list of custom fields values to be added to the certificate.
        """

        self.chain_option = "last"
        self.san_dns = san_dns or []
        self.email_addresses = email_addresses
        self.ip_addresses = ip_addresses or []
        self.user_principal_names = user_principal_names or []
        self.uniform_resource_identifiers = uniform_resource_identifiers or []
        self.attributes = attributes
        self.key_password = key_password
        self.key_type = key_type
        self.private_key = private_key
        self.public_key = None
        self._public_key_from_private()
        self.friendly_name = friendly_name or common_name
        self.id = cert_id
        self.common_name = common_name
        self.thumbprint = thumbprint
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.country = country
        self.province = province
        self.locality = locality
        # CSR should be last, because it checks subject to match with over parameters
        self.csr = csr
        self.origin = origin or "Venafi VCert-Python"
        self.custom_fields = custom_fields
        self.cert_guid = None

    def __setattr__(self, key, value):
        if key == "key_password":
            if isinstance(value, string_types):
                value = value.encode()
        elif key == "common_name":
            if isinstance(value, binary_type):
                value = value.decode()
        elif key == "key_type":
            if value is not None and not isinstance(value, KeyType):
                raise ClientBadData("key_type should be instance of vcert.KeyType")
        elif key == "private_key":
            if isinstance(value, string_types):
                value = serialization.load_pem_private_key(value.encode(),
                                                           password=self.key_password, backend=default_backend())
            if isinstance(value, rsa.RSAPrivateKey):
                self.key_type = KeyType(KeyType.RSA, value.key_size)
            elif isinstance(value, ec.EllipticCurvePrivateKey):
                self.key_type = KeyType(KeyType.ECDSA, value.curve.name)
            elif value is None:
                self.public_key = None
            else:
                raise ClientBadData("invalid private key type %s" % type(value))
        elif key == "csr":
            if isinstance(value, binary_type):
                value = value.decode()
            elif not (isinstance(value, string_types) or value is None):
                raise ClientBadData("invalid csr type %s" % type(value))
            if value:
                csr = x509.load_pem_x509_csr(value.encode(), default_backend())
                cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if self.common_name and self.common_name != cn:
                    raise ClientBadData("Common name from CSR doesn`t matches to CertificateRequest.common_name")
                ips = []
                dns = []
                try:
                    for e in csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value:
                        if isinstance(e, x509.general_name.DNSName):
                            dns.append(e.value)
                        elif isinstance(e, x509.general_name.IPAddress):
                            ips.append(e.value.exploded)
                    if self.ip_addresses and sorted(self.ip_addresses) != sorted(ips):
                        raise ClientBadData
                    if self.san_dns and sorted(self.san_dns) != sorted(dns):
                        raise ClientBadData
                except x509.extensions.ExtensionNotFound:
                    pass
        self.__dict__[key] = value

    def _gen_key(self):
        if self.key_type == None:
            self.key_type = KeyType(KeyType.RSA, 2048)
        if self.key_type.key_type == KeyType.RSA:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_type.option,
                backend=default_backend()
            )
        elif self.key_type.key_type == KeyType.ECDSA:
            if self.key_type.option == "p521":
                curve = ec.SECP521R1()
            elif self.key_type.option == "p384":
                curve = ec.SECP384R1()
            elif self.key_type.option == "p256":
                curve = ec.SECP256R1()
            else:
                curve = ec.SECP256R1()
            self.private_key = ec.generate_private_key(
                curve, default_backend()
            )
        else:
            raise ClientBadData
        self._public_key_from_private()

    def build_csr(self):
        if not self.private_key:
            self._gen_key()

        csr_builder = x509.CertificateSigningRequestBuilder()
        subject = [x509.NameAttribute(NameOID.COMMON_NAME, self.common_name,)]
        if self.locality:
            subject.append(x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality))
        if self.province:
            subject.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.province))
        if self.country:
            subject.append(x509.NameAttribute(NameOID.COUNTRY_NAME, self.country))
        if self.organization:
            subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization))
        if self.organizational_unit:
            if isinstance(self.organizational_unit, string_types):
                subject.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit))
            elif isinstance(self.organizational_unit, list):
                for u in self.organizational_unit:
                    subject.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u))

        csr_builder = csr_builder.subject_name(x509.Name(subject))

        alt_names = []
        if self.ip_addresses:
            for ip in self.ip_addresses:
                alt_names.append(x509.IPAddress(ipaddress.IPv4Address(ip)))

        if self.san_dns:
            for ns in self.san_dns:
                alt_names.append(x509.DNSName(ns))

        if self.email_addresses:
            for mail in self.email_addresses:
                alt_names.append(x509.RFC822Name(mail))

        if self.uniform_resource_identifiers:
            for uri in self.uniform_resource_identifiers:
                alt_names.append(x509.UniformResourceIdentifier(uri))

        if self.user_principal_names:
            for upn in self.user_principal_names:
                # Python cryptography library doesn't include
                # OID for UPN in any of the OID constants
                # See http://www.oid-info.com/get/1.3.6.1.4.1.311.20.2.3
                # and https://docs.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration
                UPNOID = x509.ObjectIdentifier('1.3.6.1.4.1.311.20.2.3')
                # x509 library expects DER encoded string, so encode UPN into bytes
                # with ASN1 syntax for UTF8String, which is a type/length/value encoding
                # per https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-utf8string
                # Construct the array of bytes (note bytes are strings in python2)
                # by inserting the header consisting of the tag '0x0C' followed by the length of the upn
                if sys.version_info > (3, 0):
                    # For python3, since we have native bytes available we'll convert the string into bytes.
                    # However, for cases when this method is called with inputs extracted from existing certificates
                    # & csrs, the input will already be encoded as bytes. So we'll check the input, if it is a 
                    # string we'll convert it into a bytes object then insert our header. Otherwise, we'll just
                    # insert the header in the passed in bytes.
                    if isinstance(upn, str):
                        bupn = bytes(upn,'utf-8')
                    else:
                        bupn = upn
                    values = [12,len(upn)]
                    header = bytes(values)
                    data = header + bupn
                    alt_names.append(x509.OtherName(UPNOID, data))
                else:
                    # For python2, since there is no native bytes method, we'll use the bytes method 
                    # in the future module to convert the string we constructed into bytes.
                    bupn = ''.join(chr(x) for x in [12,len(upn)])
                    bupn = bupn + str(upn)
                    alt_names.append(x509.OtherName(UPNOID,bytes(bupn, 'utf-8')))

        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
        )

        csr_builder = csr_builder.sign(self.private_key, hashes.SHA256(),
                                       default_backend())
        self.csr = csr_builder.public_bytes(serialization.Encoding.PEM).decode()
        return

    @property
    def private_key_pem(self):
        if self.key_password:
            encryption = serialization.BestAvailableEncryption(self.key_password)
        else:
            encryption = serialization.NoEncryption()

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        ).decode()

    def _public_key_from_private(self):
        if self.private_key is None:
            return
        self.public_key = self.private_key.public_key()

    @property
    def public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def update_from_zone_config(self, zone):
        # TODO: check request against zone configuration
        """
        :param ZoneConfig zone:
        """
        if zone.organization.locked or (not self.organization and zone.organization):
            self.organization = zone.organization.value
        if zone.organizational_unit.locked or (not self.organizational_unit and zone.organizational_unit):
            self.organizational_unit = zone.organizational_unit.value
        if zone.country.locked or (not self.country and zone.country):
            self.country = zone.country.value
        if zone.province.locked or (not self.province and zone.province):
            self.province = zone.province.value
        if zone.locality.locked or (not self.locality and zone.locality):
            self.locality = zone.locality.value
        if not self.key_type and zone.key_type:
            self.key_type = zone.key_type


class CustomField:
    def __init__(self, name, value):
        """
        :param str name: The name of the custom field
        :param str value: The value to be added to the specified custom field
        """
        self.name = name
        self.value = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class RevocationRequest:
    class RevocationReasons:
        NoReason = 0
        key_compromise = 1
        ca_compromise = 2
        affiliation_changed = 3
        superseded = 4
        cessation_of_operation = 5  # OriginalUseNoLongerValid

    def __init__(self, req_id=None, thumbprint=None,  reason=RevocationReasons.NoReason,
                 comments="Revoked via api with python bindings", disable=True):
        """
        :param req_id:
        :param thumbprint:
        """
        self.id = req_id
        self.thumbprint = thumbprint
        self.reason = reason
        self.comments = comments
        self.disable = disable


CLIENT_ID = "vcert-sdk"  # type: str
SCOPE = "certificate:manage,revoke;configuration:manage"  # type: str


class Authentication:
    def __init__(self, user=None, password=None, access_token=None, refresh_token=None, api_key=None, state=None,
                 token_expires=None, client_id=CLIENT_ID, scope=SCOPE):
        self.user = user
        self.password = password
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_expires = token_expires
        self.api_key = api_key
        self.client_id = client_id
        self.scope = scope
        self.state = state


class AppDetails:
    def __init__(self, app_id=None, cit_map=None, company_id=None, name=None, description=None,
                 owner_ids_and_types=None, fq_dns=None, internal_fq_dns=None, external_ip_ranges=None,
                 internal_ip_ranges=None, internal_ports=None, fully_qualified_domain_names=None, ip_ranges=None,
                 ports=None, org_unit_id=None):
        """
        :param str app_id:
        :param dict cit_map:
        """
        self.app_id = app_id
        self.cit_alias_id_map = cit_map
        self.company_id = company_id
        self.name = name
        self.description = description
        self.owner_ids_and_types = owner_ids_and_types
        self.fq_dns = fq_dns
        self.internal_fq_dns = internal_fq_dns
        self.external_ip_ranges = external_ip_ranges
        self.internal_ip_ranges = internal_ip_ranges
        self.internal_ports = internal_ports
        self.fully_qualified_domain_names = fully_qualified_domain_names
        self.ip_ranges = ip_ranges
        self.ports = ports
        self.org_unit_id = org_unit_id


class CommonConnection:

    def auth(self):
        """
        Authorize connection on platform. Return user object.
        Optional for making calls. Connection controls auth status by itself.
        """
        raise NotImplementedError

    def request_cert(self, request, zone):
        """
        Making request to certificate. It will generate CSR from data if CSR not specified, generate key if required and send to server for signing. Set request.id for retrieving certificate.

        :param CertificateRequest request: Certificate in PEM format
        :param str zone: Venafi zone tag name
        :rtype: bool
        """
        raise NotImplementedError

    def retrieve_cert(self, request):
        """
        Get signed certificate from server by request.id

        :param CertificateRequest request:
        :rtype: Certificate
        """
        raise NotImplementedError

    def revoke_cert(self, request):
        """
        :param RevocationRequest request:
        """
        raise NotImplementedError

    def renew_cert(self, request, reuse_key=False):
        """
        :param CertificateRequest request:
        :param bool reuse_key:
        """
        raise NotImplementedError

    def read_zone_conf(self, tag):
        """
        :param str tag:
        :rtype: ZoneConfig
        """
        raise NotImplementedError

    def import_cert(self, request):
        raise NotImplementedError

    def get_policy(self, zone):
        """
        :param str zone:
        :rtype: PolicySpecification
        """
        raise NotImplementedError

    def set_policy(self, zone, policy_spec):
        """
        :param str zone:
        :param PolicySpecification policy_spec:
        :rtype: None
        """
        raise NotImplementedError

    @staticmethod
    def process_server_response(r):
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.ACCEPTED, HTTPStatus.CREATED, HTTPStatus.CONFLICT):
            try:
                log_errors(r.json())
            except:
                log_errors(r.content)
            raise VenafiConnectionError("Server status: %s\nResponse: %s" % (r.status_code, r.request.url))

        content_type = r.headers.get("content-type")
        # Content-type not present, return status and reason (if any)
        if content_type is None:
            return r.status_code, r.reason
        if content_type.startswith(MIME_TEXT):
            log.debug(r.text)
            return r.status_code, r.text
        elif content_type.startswith(MIME_HTML):
            log.debug(r.text)
            return r.status_code, r.text
        # content-type in response is  application/json; charset=utf-8
        elif content_type.startswith(MIME_JSON):
            # log.debug(r.content.decode())
            return r.status_code, r.json()
        elif content_type.startswith(MIME_CSV):
            log.debug(r.content.decode())
            return r.status_code, r.content.decode()
        else:
            log.error("Unexpected content type: %s for request %s" % (content_type, r.request.url))
            raise ServerUnexptedBehavior
