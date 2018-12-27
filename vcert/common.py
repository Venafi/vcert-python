from __future__ import absolute_import, division, generators, unicode_literals, print_function, nested_scopes, \
    with_statement

import datetime
import logging as log

import dateutil.parser
from csrbuilder import CSRBuilder, pem_armor_csr
from oscrypto import asymmetric

from .errors import VenafiConnectionError, ServerUnexptedBehavior, BadData, ClientBadData
from .http import HTTPStatus

MIME_JSON = "application/json"
MINE_HTML = "text/html"
MINE_TEXT = "text/plain"
MINE_ANY = "*/*"


class CertField(str):
    def __init__(self, *args, **kwargs):
        self.locked = False
        super(CertField, self).__init__(*args, **kwargs)


def log_errors(data):
    if "errors" not in data:
        log.error("Unknown error format: %s", data)
        return
    for e in data["errors"]:
        log.error(str(e))  # todo: beta formatter


class Zone:
    def __init__(self, zone_id, company_id, tag, zonetype, cert_policy_ids, default_cert_identity_policy,
                 default_cert_use_policy, system_generated, creation_date):
        """
        :param str zone_id:
        :param str company_id:
        :param str tag:
        :param str zonetype:
        :param cert_policy_ids:
        :param str default_cert_identity_policy:
        :param str default_cert_use_policy:
        :param bool system_generated:
        :param datetime.datetime creation_date:
        """
        self.id = zone_id
        self.company_id = company_id
        self.tag = tag
        self.zonetype = zonetype
        self.cert_policy_ids = cert_policy_ids
        self.default_cert_identity_policy = default_cert_identity_policy
        self.default_cert_use_policy = default_cert_use_policy
        self.system_generated = system_generated
        self.creation_date = creation_date

    def __repr__(self):
        return "Zone %s:\n" % self.tag + "\n".join(["  %s: %s" % (k, v) for k, v in (
            ("Id", self.id),
            ("CompanyID", self.company_id),
            ("Type", self.zonetype),
            ("SystemGenerated", self.system_generated),
            ("Created", self.creation_date.isoformat())
        )])

    def __str__(self):
        return self.tag

    @classmethod
    def from_server_response(cls, d):
        return cls(d['id'], d['companyId'], d['tag'], d['zoneType'], d['certificatePolicyIds'],
                   d['defaultCertificateIdentityPolicyId'], d['defaultCertificateUsePolicyId'], d['systemGenerated'],
                   dateutil.parser.parse(d['creationDate']))


class KeyTypes:
    RSA = "rsa"
    ECDSA = "ec"


class KeyType:
    def __init__(self, key_type, key_sizes=None, key_curves=None):
        self.key_type = key_type.lower()
        if self.key_type == KeyTypes.RSA:
            self.key_size = key_sizes
        elif self.key_type == KeyTypes.ECDSA:
            self.key_curves = list([x.lower() for x in key_curves])
        else:
            log.error("unknown key type: %s" % key_type)
            raise BadData

    def __repr__(self):
        return "KeyType(%s, %s)" % (self.key_type, self.key_size or self.key_curves)


class ZoneConfig:
    def __init__(self, organization=None, organizational_unit=None, country=None, province=None, locality=None,
                 CustomAttributeValues=None, SubjectCNRegexes=None, SubjectORegexes=None, SubjectOURegexes=None,
                 SubjectSTRegexes=None, SubjectLRegexes=None, SubjectCRegexes=None, SANRegexes=None,
                 allowed_key_configurations=None, KeySizeLocked=None, HashAlgorithm=None):
        """
        :param CertField organization:
        :param list[str] organizational_unit:
        :param CertField country:
        :param CertField province:
        :param CertField locality:
        :param dict[str, str] CustomAttributeValues:
        :param list[str] SubjectCNRegexes:
        :param list[str] SubjectORegexes:
        :param list[str] SubjectOURegexes:
        :param list[str] SubjectSTRegexes:
        :param list[str] SubjectLRegexes:
        :param list[str] SubjectCRegexes:
        :param list[str] SANRegexes:
        :param list[KeyType] allowed_key_configurations:
        :param bool KeySizeLocked:
        :param HashAlgorithm:
        """

        self.allowed_key_configurations = allowed_key_configurations or []

    @classmethod
    def from_policy(cls, policy):
        """
        :param Policy policy:
        """
        return cls(allowed_key_configurations=policy.key_types[:])


class Policy:
    class Type:
        CERTIFICATE_IDENTITY = "CERTIFICATE_IDENTITY"
        CERTIFICATE_USE = "CERTIFICATE_USE"

    def __init__(self, policy_type=None, id=None, company_id=None, name=None, system_generated=None, creation_date=None,
                 cert_provider_id=None, subject_cn_regexes=None, subject_o_regexes=None, subject_ou_regexes=None,
                 subject_st_regexes=None, subject_l_regexes=None, subject_c_regexes=None, san_regexes=None,
                 key_types=None, key_reuse=None):
        """
        :param str policy_type:
        :param str id:
        :param str company_id:
        :param str name:
        :param bool system_generated:
        :param datetime.datetime creation_date:
        :param str cert_provider_id:
        :param list[str] subject_cn_regexes:
        :param list[str] subject_o_regexes:
        :param list[str] subject_ou_regexes:
        :param list[str] subject_st_regexes:
        :param list[str] subject_l_regexes:
        :param list[str] subject_c_regexes:
        :param list[str] san_regexes:
        :param list[KeyType] key_types:
        :param bool key_reuse:
        """
        self.policy_type = policy_type
        self.id = id
        self.company_id = company_id
        self.name = name
        self.system_generated = system_generated
        self.creation_date = creation_date
        self.cert_provider_id = cert_provider_id
        self.SubjectCNRegexes = subject_cn_regexes
        self.SubjectORegexes = subject_o_regexes
        self.SubjectOURegexes = subject_ou_regexes
        self.SubjectSTRegexes = subject_st_regexes
        self.SubjectLRegexes = subject_l_regexes
        self.SubjectCRegexes = subject_c_regexes
        self.SANRegexes = san_regexes
        self.key_types = key_types
        self.key_reuse = key_reuse

    @classmethod
    def from_server_response(cls, d):
        """
        :rtype Policy:
        """
        policy = cls(d['certificatePolicyType'], d['id'], d['companyId'], d['name'], d['systemGenerated'],
                     dateutil.parser.parse(d['creationDate']), d.get('certificateProviderId'),
                     d.get('subjectCNRegexes', []), d.get('subjectORegexes', []), d.get('subjectOURegexes', []),
                     d.get('subjectSTRegexes', []), d.get('subjectLRegexes', []), d.get('subjectCRegexes', []),
                     d.get('sanRegexes', []), [], d.get('keyReuse'))
        for kt in d.get('keyTypes', []):
            policy.key_types.append(KeyType(key_type=kt['keyType'], key_sizes=kt['keyLengths']))  # todo: curves
        return policy

    def __repr__(self):
        return "Policy:\n" + "\n".join(["  %s: %s" % (k, v) for k, v in (
            ("Id", self.id),
            ("Type", self.policy_type),
            ("Name", self.name),
            ("KeyReuse", self.key_reuse),
            ("Created", self.creation_date)
        )])

    def __str__(self):
        return self.name


class CertificateRequest:
    def __init__(self, id=None,
                 status=None,
                 dns_names=None,
                 email_addresses="",
                 ip_addresses=None,
                 attributes=None,
                 key_type=KeyTypes.RSA,
                 key_length=2048,
                 key_curve="P521",
                 private_key=None,
                 csr_origin=None,
                 key_password=None,
                 csr=None,
                 friendly_name=None,
                 chain_option="first",
                 common_name=None,
                 thumbprint=None):

        self.csr = csr
        self.chain_option = chain_option
        self.dns_names = dns_names or []
        self.email_addresses = email_addresses
        self.ip_addresses = ip_addresses or []
        self.attributes = attributes

        self.key_type = key_type
        self.key_length = key_length
        self.key_curve = key_curve
        if isinstance(private_key, str):
            self.private_key = asymmetric.load_private_key(private_key)
            self.key_type = self.private_key.algorithm
            self.public_key = None
        elif isinstance(private_key, asymmetric.PrivateKey):
            self.private_key = private_key
            self.key_type = self.private_key.algorithm
            self.public_key = None
        elif private_key is None:
            self.private_key = None
        self.csr_origin = csr_origin
        self.key_password = key_password
        self.csr = csr
        self.friendly_name = friendly_name or common_name
        self.chain_option = chain_option
        self.id = id
        self.status = status
        self.common_name = common_name
        self.thumbprint = thumbprint

    def build_csr(self):
        if not self.private_key:
            if self.key_type == KeyTypes.RSA:
                self.public_key, self.private_key = asymmetric.generate_pair("rsa", bit_size=self.key_length)
            elif self.key_type == KeyTypes.ECDSA:
                self.public_key, self.private_key = asymmetric.generate_pair("ec", curve=self.key_curve)
            else:
                raise ClientBadData
        else:
            raise NotImplementedError
            # public_key = gen_public_from_private(self.private_key, self.key_type)  # todo: write function

        data = {
            'common_name': self.common_name,
        }
        if self.email_addresses:
            data['email_address'] = self.email_addresses

        builder = CSRBuilder(
            data,
            self.public_key
        )

        if self.ip_addresses:
            builder.subject_alt_ips = self.ip_addresses
        if self.dns_names:
            builder.subject_alt_domains = self.dns_names

        builder.hash_algo = "sha256"
        builder.subject_alt_domains = [self.common_name]
        self.csr = pem_armor_csr(builder.build(self.private_key)).decode()
        return

    @property
    def private_key_pem(self):
        return asymmetric.dump_private_key(self.private_key, None, "pem").decode()


class CommonConnection:
    def _get_cert_status(self, request):
        """
        :param CertificateRequest request:
        """
        raise NotImplementedError

    def ping(self):
        """

        :return:
        """
        raise NotImplementedError

    def auth(self):
        raise NotImplementedError

    def request_cert(self, request, zone):
        """
        :param CertificateRequest request: Certitficate in PEM format
        :param str zone: Venafi zone tag name
        :rtype bool : Success
        """
        raise NotImplementedError

    def retrieve_cert(self, request):
        """
        :param CertificateRequest request:
        """
        raise NotImplementedError

    def revoke_cert(self, request):
        raise NotImplementedError

    def renew_cert(self, request):
        """
        :param CertificateRequest request:
        """
        raise NotImplementedError

    def read_zone_conf(self, tag):
        """
        :param str tag:
        :rtype ZoneConfig
        """
        raise NotImplementedError

    def import_cert(self, request):
        raise NotImplementedError

    @staticmethod
    def process_server_response(r):
        if r.status_code not in (HTTPStatus.OK, HTTPStatus.ACCEPTED, HTTPStatus.CREATED, HTTPStatus.CONFLICT):
            raise VenafiConnectionError("Server status: %s, %s\n Response: %s",
                                        (r.status_code, r.request.url, r.content))
        content_type = r.headers.get("content-type")
        if content_type == MINE_TEXT:
            log.debug(r.text)
            return r.status_code, r.text
        elif content_type == MINE_HTML:
            log.debug(r.text)
            return r.status_code, r.text
        # content-type in respons is  application/json; charset=utf-8
        elif content_type.startswith(MIME_JSON):
            log.debug(r.content.decode())
            return r.status_code, r.json()
        else:
            log.error("unexpected content type: %s for request %s" % (content_type, r.request.url))
            raise ServerUnexptedBehavior
