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
import base64
import logging as log
import re
import time
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import SignatureAlgorithmOID as AlgOID
from six.moves.urllib import parse as url_parse

from .common import CertField, CommonConnection, CertificateRequest, CSR_ORIGIN_LOCAL, CSR_ORIGIN_PROVIDED, \
    CSR_ORIGIN_SERVICE, KeyType, CHAIN_OPTION_LAST, CHAIN_OPTION_FIRST, CHAIN_OPTION_IGNORE, Policy, ZoneConfig
from .errors import VenafiError, ServerUnexptedBehavior, ClientBadData, RetrieveCertificateTimeoutError, \
    CertificateRequestError, CertificateRenewError
from .http_status import HTTPStatus
from .pem import parse_pem
from .policy import RPA, SPA
from .policy.pm_tpp import TPPPolicy, is_service_generated_csr, SetAttrResponse, validate_policy_spec, \
    get_int_value
from .ssh_utils import SSHCertRequest, SSHCertResponse, build_tpp_retrieve_request, SSHResponse, \
    SSHRetrieveResponse, build_tpp_request, SSHCATemplateRequest, SSHConfig, PATH_SEPARATOR, CA_ROOT_PATH, \
    SSHTPPCADetails
from .tpp_utils import IssuerHint

POLICY_ATTR_CLASS = "X509 Certificate"  # type: str
ROOT_PATH = "\\VED\\Policy\\"  # type: str
POLICY_CLASS = "Policy"  # type: str


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

    POLICY_IS_VALID = API_BASE_URL + "config/isvalid"
    POLICY_CREATE = API_BASE_URL + "config/create"
    POLICY_SET_ATTRIBUTE = API_BASE_URL + "config/writepolicy"
    POLICY_CLEAR_ATTRIBUTE = API_BASE_URL + "config/clearpolicyattribute"

    SSH_BASE_URL = API_BASE_URL + "SSHCertificates/"
    SSH_CERTIFICATE_REQUEST = SSH_BASE_URL + "request"
    SSH_CERTIFICATE_RETRIEVE = SSH_BASE_URL + "retrieve"
    SSH_CA_DETAILS = SSH_BASE_URL + "Template/Retrieve"
    SSH_CA_PUBLIC_KEY = SSH_CA_DETAILS + "/PublicKeyData"

    def __init__(self):
        pass


class AbstractTPPConnection(CommonConnection):
    def __init__(self):
        super().__init__()

    ARG_URL = 'url'
    ARG_PARAMS = 'params'
    ARG_CHECK_TOKEN = 'check_token'  # nosec
    ARG_INCLUDE_TOKEN_HEADER = 'include_token_header'  # nosec
    ARG_DATA = 'data'

    def auth(self):
        raise NotImplementedError

    def request_cert(self, request, zone):
        request_data = {
            'PolicyDN': self._normalize_zone(zone),
            'ObjectName': request.friendly_name,
            'DisableAutomaticRenewal': "true"
        }
        zone_config = self.read_zone_conf(zone)
        request.update_from_zone_config(zone_config)

        if request.csr_origin == CSR_ORIGIN_LOCAL:
            request.build_csr()

        if request.csr_origin in [CSR_ORIGIN_PROVIDED, CSR_ORIGIN_LOCAL]:
            request_data['PKCS10'] = request.csr
        elif request.csr_origin == CSR_ORIGIN_SERVICE:
            request_data['Subject'] = request.common_name
            request_data['SubjectAltNames'] = self.wrap_alt_names(request)
        else:
            log.error(f"CSR Origin option [{request.csr_origin}] is not valid")
            raise ClientBadData

        if request.origin:
            request_data['Origin'] = request.origin
            ca_origin = {'Name': "Origin", 'Value': request.origin}
            if request_data.get('CASpecificAttributes'):
                request_data['CASpecificAttributes'].append(ca_origin)
            else:
                request_data['CASpecificAttributes'] = [ca_origin]

        if request.validity_hours is not None:
            if request.issuer_hint == IssuerHint.MICROSOFT:
                exp_date_attr = IssuerHint.MICROSOFT.json_value
            elif request.issuer_hint == IssuerHint.DIGICERT:
                exp_date_attr = IssuerHint.DIGICERT.json_value
            elif request.issuer_hint == IssuerHint.ENTRUST:
                exp_date_attr = IssuerHint.ENTRUST.json_value
            else:
                exp_date_attr = IssuerHint.DEFAULT.json_value

            expiration_date = datetime.utcnow() + timedelta(hours=request.validity_hours)
            formatted_expiration_date = expiration_date.strftime("%Y-%m-%d %H:%M:%S")

            expiration_date = {'Name': exp_date_attr, 'Value': formatted_expiration_date}
            if request_data.get('CASpecificAttributes'):
                request_data['CASpecificAttributes'].append(expiration_date)
            else:
                request_data['CASpecificAttributes'] = [expiration_date]

        if request.custom_fields:
            custom_fields_map = {}
            for c_field in request.custom_fields:
                if custom_fields_map.get(c_field.name):
                    custom_fields_map[c_field.name].append(c_field.value)
                else:
                    custom_fields_map[c_field.name] = [c_field.value]

            for key in custom_fields_map:
                custom_field_json = {
                    'Name': key,
                    'Values': custom_fields_map[key]
                }
                if request_data.get('CustomFields'):
                    request_data['CustomFields'].append(custom_field_json)
                else:
                    request_data['CustomFields'] = [custom_field_json]

        args = {
            self.ARG_URL: URLS.CERTIFICATE_REQUESTS,
            self.ARG_DATA: request_data
        }
        status, data = self.post(args)
        if status == HTTPStatus.OK:
            request.id = data['CertificateDN']
            request.cert_guid = data['Guid']
            log.debug(f"Certificate successfully requested with request id {request.id}")
            log.debug(f"Certificate successfully requested with GUID {request.cert_guid}")
            return True

        log.error(f"Request status is not {HTTPStatus.OK}. {status}")
        raise CertificateRequestError

    def retrieve_cert(self, cert_request):
        log.debug(f"Getting certificate status for id {cert_request.id}")

        retrieve_request = dict(CertificateDN=cert_request.id,
                                Format="base64",
                                IncludeChain=True)

        if cert_request.csr_origin == CSR_ORIGIN_SERVICE:
            retrieve_request['IncludePrivateKey'] = cert_request.include_private_key
            if cert_request.key_password:
                # The password is encoded when assigned (for local use, I suppose).
                # decode is needed to send a raw string
                retrieve_request['Password'] = cert_request.key_password.decode()

        if cert_request.chain_option == CHAIN_OPTION_LAST:
            retrieve_request['RootFirstOrder'] = 'false'
            retrieve_request['IncludeChain'] = 'true'
        elif cert_request.chain_option == CHAIN_OPTION_FIRST:
            retrieve_request['RootFirstOrder'] = 'true'
            retrieve_request['IncludeChain'] = 'true'
        elif cert_request.chain_option == CHAIN_OPTION_IGNORE:
            retrieve_request['IncludeChain'] = 'false'
        else:
            log.error(f"chain option {cert_request.chain_option} is not valid")
            raise ClientBadData

        time_start = time.time()
        while True:
            try:
                # TODO: Change _post() with post(args)
                status, data = self._post(URLS.CERTIFICATE_RETRIEVE, data=retrieve_request)
            except VenafiError:
                log.debug(f"Certificate with id {cert_request.id} not found")
                status = 0

            if status == HTTPStatus.OK:
                pem64 = data['CertificateData']
                pem = base64.b64decode(pem64)
                cert_response = parse_pem(pem.decode(), cert_request.chain_option)
                if cert_response.key is None and cert_request.private_key is not None:
                    log.debug("Adding private key to response...")
                    cert_response.key = cert_request.private_key_pem
                return cert_response
            elif (time.time() - time_start) < cert_request.timeout:
                log.debug("Waiting for certificate...")
                time.sleep(2)
            else:
                raise RetrieveCertificateTimeoutError(f"Operation timed out at {cert_request.timeout} seconds while "
                                                      f"retrieving certificate with id {cert_request.id}")

    def renew_cert(self, request, reuse_key=False):
        if not request.id and not request.thumbprint:
            log.debug("Request id or thumbprint must be specified for TPP")
            raise CertificateRenewError
        if not request.id and request.thumbprint:
            request.id = self.search_by_thumbprint(request.thumbprint)

        if reuse_key:
            log.debug(f"Trying to renew certificate {request.id}")
            # TODO: Change _post() with post(args)
            status, data = self._post(URLS.CERTIFICATE_RENEW, data={'CertificateDN': request.id})
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
            dns = []
            emails = []
            ips = []
            upns = []
            uris = []
            if e.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME:
                for x in e.value:
                    if isinstance(x, x509.DNSName):
                        dns.append(x.value)
                    elif isinstance(x, x509.RFC822Name):
                        emails.append(x.value)
                    elif isinstance(x, x509.IPAddress):
                        ips.append(x.value)
                    elif isinstance(x, x509.OtherName):
                        # remove header bytes from ASN1 encoded UPN field before setting it in the request object
                        upns.append(x.value[2::])
                    elif isinstance(x, x509.UniformResourceIdentifier):
                        uris.append(x.value)
                # request.san_dns = list([x.value for x in e.value if isinstance(x, x509.DNSName)])
                # request.email_addresses = list([x.value for x in e.value if isinstance(x, x509.RFC822Name)])
                # request.ip_addresses = list([x.value.exploded for x in e.value if isinstance(x, x509.IPAddress)])
                # remove header bytes from ASN1 encoded UPN field before setting it in the request object
                # upns = []
                # for x in e.value:
                #     if isinstance(x, x509.OtherName):
                #         upns.append(x.value[2::])
                # request.user_principal_names = upns
                # request.uniform_resource_identifiers = \
                #     list([x.value for x in e.value if isinstance(x, x509.UniformResourceIdentifier)])
            request.san_dns = dns
            request.email_addresses = emails
            request.ip_addresses = ips
            request.user_principal_names = upns
            request.uniform_resource_identifiers = uris

        if request.csr_origin == CSR_ORIGIN_LOCAL:
            if cert.signature_algorithm_oid in (AlgOID.ECDSA_WITH_SHA1, AlgOID.ECDSA_WITH_SHA224,
                                                AlgOID.ECDSA_WITH_SHA256, AlgOID.ECDSA_WITH_SHA384,
                                                AlgOID.ECDSA_WITH_SHA512):
                request.key_type = (KeyType.ECDSA, KeyType.ALLOWED_CURVES[0])
            else:
                request.key_type = KeyType(KeyType.RSA, 2048)  # todo: make parsing key size
            request.build_csr()

        request_data = {'CertificateDN': request.id}
        if request.csr_origin in [CSR_ORIGIN_PROVIDED, CSR_ORIGIN_LOCAL]:
            request_data['PKCS10'] = request.csr
        elif request.csr_origin == CSR_ORIGIN_SERVICE:
            request_data['Subject'] = request.common_name
            request_data['SubjectAltNames'] = self.wrap_alt_names(request)

        # TODO: Change _post() with post(args)
        status, data = self._post(URLS.CERTIFICATE_RENEW, data=request_data)
        if status == HTTPStatus.OK:
            if 'CertificateDN' in data:
                request.id = data['CertificateDN']
            log.debug(f"Certificate successfully requested with request id {request.id}")
            return True

        log.error(f"Request status is not {HTTPStatus.OK}. {status}")
        raise CertificateRequestError

    def revoke_cert(self, request):
        if not (request.id or request.thumbprint):
            raise ClientBadData
        d = {
            'Disable': request.disable
        }
        if request.reason:
            d['Reason'] = request.reason
        if request.id:
            d['CertificateDN'] = request.id
        elif request.thumbprint:
            d['Thumbprint'] = request.thumbprint
        else:
            raise ClientBadData
        if request.comments:
            d['Comments'] = request.comments
        # TODO: Change _post() with post(args)
        status, data = self._post(URLS.CERTIFICATE_REVOKE, data=d)
        if status in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
            return data

        raise ServerUnexptedBehavior

    def import_cert(self, request):
        raise NotImplementedError

    def read_zone_conf(self, tag):
        args = {
            self.ARG_URL: URLS.ZONE_CONFIG,
            self.ARG_DATA: {
                'PolicyDN': self._normalize_zone(tag)
            }
        }
        status, data = self.post(args=args)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior(f"Server returns {status} status on reading zone configuration")
        return self._parse_zone_data_to_object(data)

    def get_policy(self, zone):
        # get policy spec from name
        policy_name = self._normalize_zone(zone)
        exists = self._policy_exists(policy_name)
        if not exists:
            log.error(f"The Policy {policy_name} does not exist")
            raise VenafiError

        # TODO: Change _post() with post(args)
        status, data = self._post(URLS.ZONE_CONFIG, {"PolicyDN": policy_name})
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior(f"Server returns {status} status on reading policy configuration")

        if not ('Policy' in data):
            raise VenafiError(f"Policy structure not found in response data for [{policy_name}] policy")
        p = data['Policy']
        tpp_policy = TPPPolicy()

        value = 'Value'
        locked = 'Locked'

        # Contact
        if RPA.TPP_CONTACT in p:
            tpp_policy.contact = [p[RPA.TPP_CONTACT][value]]

        # Approver
        if RPA.TPP_APPROVER in p:
            tpp_policy.approver = [p[RPA.TPP_APPROVER][value]]

        # Prohibited wildcard
        if RPA.TPP_WILDCARDS_ALLOWED in p:
            tpp_policy.wildcards_allowed = p[RPA.TPP_WILDCARDS_ALLOWED]

        # Domain suffix whitelist
        if RPA.TPP_DOMAIN_SUFFIX_WHITELIST in p:
            tpp_policy.domain_suffix_whitelist = p[RPA.TPP_DOMAIN_SUFFIX_WHITELIST]

        # Certification Authority
        if RPA.TPP_CERT_AUTHORITY in p:
            tpp_policy.cert_authority = p[RPA.TPP_CERT_AUTHORITY][value]

        # Management Type
        if RPA.TPP_MANAGEMENT_TYPE in p:
            tpp_policy.management_type = p[RPA.TPP_MANAGEMENT_TYPE][value]

        if not ('Subject' in p):
            raise VenafiError(f"Subject structure not found in response data for [{policy_name}] policy")
        subject = p['Subject']

        # Organization
        if RPA.TPP_ORGANIZATION in subject:
            org = subject[RPA.TPP_ORGANIZATION]
            tpp_policy.org = CertField(org[value], org[locked])

        # Organizational Unit
        if RPA.TPP_ORG_UNIT in subject:
            ou = subject[RPA.TPP_ORG_UNIT]
            tpp_policy.org_unit = CertField(ou[value+"s"], ou[locked])

        # City
        if RPA.TPP_CITY in subject:
            city = subject[RPA.TPP_CITY]
            tpp_policy.city = CertField(city[value], city[locked])

        # State
        if RPA.TPP_STATE in subject:
            st = subject[RPA.TPP_STATE]
            tpp_policy.state = CertField(st[value], st[locked])

        # Country
        if RPA.TPP_COUNTRY in subject:
            country = subject[RPA.TPP_COUNTRY]
            tpp_policy.country = CertField(country[value], country[locked])

        if not ('KeyPair' in p):
            raise VenafiError(f"KeyPair structure not found in response data for [{policy_name}] policy")
        kp = p['KeyPair']

        # Key Algorithm
        if RPA.TPP_KEY_ALGORITHM in kp:
            tpp_policy.key_algo = CertField(kp[RPA.TPP_KEY_ALGORITHM][value], kp[RPA.TPP_KEY_ALGORITHM][locked])

        # Key Bit Strength
        if RPA.TPP_KEY_SIZE in kp:
            tpp_policy.key_bit_str = CertField(kp[RPA.TPP_KEY_SIZE][value], kp[RPA.TPP_KEY_SIZE][locked])

        # Elliptic Curve
        if RPA.TPP_ELLIPTIC_CURVE in kp:
            tpp_policy.elliptic_curve = CertField(kp[RPA.TPP_ELLIPTIC_CURVE][value], kp[RPA.TPP_ELLIPTIC_CURVE][locked])

        # Manual CSR
        if RPA.TPP_CSR_GENERATION in p:
            bool_val = is_service_generated_csr(p[RPA.TPP_CSR_GENERATION][value])
            tpp_policy.service_generated = CertField(bool_val, p[RPA.TPP_CSR_GENERATION][locked])

        # ALLOWED SANS
        if RPA.TPP_DNS_ALLOWED in p:
            tpp_policy.dns_allowed = p[RPA.TPP_DNS_ALLOWED]
        if RPA.TPP_EMAIL_ALLOWED in p:
            tpp_policy.email_allowed = p[RPA.TPP_EMAIL_ALLOWED]
        if RPA.TPP_IP_ALLOWED in p:
            tpp_policy.ip_allowed = p[RPA.TPP_IP_ALLOWED]
        if RPA.TPP_UPN_ALLOWED in p:
            tpp_policy.upn_allowed = p[RPA.TPP_UPN_ALLOWED]
        if RPA.TPP_URI_ALLOWED in p:
            tpp_policy.uri_allowed = p[RPA.TPP_URI_ALLOWED]

        # Allow Private Key Reuse
        if RPA.TPP_ALLOWED_PRIVATE_KEY_REUSE in p:
            tpp_policy.allow_private_key_reuse = p[RPA.TPP_ALLOWED_PRIVATE_KEY_REUSE]

        # TPP Want Renewal
        # tpp_want_renewal, _ = self._get_policy_attr(policy_name, TPPPolicyAttr.TPP_WANT_RENEWAL)
        # if tpp_want_renewal:
        #     tpp_policy.want_renewal = tpp_want_renewal[0]

        log.info("Building Policy Specification")
        spec = tpp_policy.to_policy_spec()

        return spec

    def set_policy(self, zone, policy_spec):
        """
        :param str zone:
        :param PolicySpecification policy_spec:
        :rtype: PolicySpecification
        """
        validate_policy_spec(policy_spec)
        tpp_policy = TPPPolicy.build_tpp_policy(policy_spec)
        name = self._normalize_zone(zone)
        tpp_policy.name = name

        create_policy = False
        policy_exists = self._policy_exists(name)
        if not policy_exists:
            log.info(f"Policy [{name}] does not exist, validating parent existence")
            parent_name = self._get_policy_parent(name)
            if self._policy_exists(parent_name) or parent_name == ROOT_PATH:
                log.info(f"Parent policy [{parent_name}] exists")
                create_policy = True
            else:
                raise VenafiError(f"Parent Policy [{parent_name}] does not exist")

        # Create the policy if necessary
        if create_policy:
            log.info(f"Creating Policy [{name}]")
            policy_request_data = {
                'Class': POLICY_CLASS,
                'ObjectDN': name
            }
            # TODO: Change _post() with post(args)
            status, resp_data = self._post(URLS.POLICY_CREATE, data=policy_request_data)
            if status != HTTPStatus.OK:
                raise VenafiError(f"Failed to create policy [{name}]. Status {status}")

        # Set attributes to policy
        if tpp_policy.contact:
            self._set_policy_attr(name, SPA.TPP_CONTACT, tpp_policy.contact, True)
        if tpp_policy.approver:
            self._set_policy_attr(name, SPA.TPP_APPROVER, tpp_policy.approver, True)

        # Reset all values for existing policy before setting the new ones.
        # This way, values that do not get updated will be inherited from parent.
        if policy_exists:
            self._reset_policy(name)

        if tpp_policy.domain_suffix_whitelist:
            self._set_policy_attr(name, SPA.TPP_DOMAIN_SUFFIX_WHITELIST, tpp_policy.domain_suffix_whitelist, True)
        if tpp_policy.cert_authority:
            self._set_policy_attr(name, SPA.TPP_CERT_AUTHORITY, [tpp_policy.cert_authority], False)
        if tpp_policy.org:
            self._set_policy_attr(name, SPA.TPP_ORGANIZATION, [tpp_policy.org.value], tpp_policy.org.locked)
        if tpp_policy.org_unit:
            self._set_policy_attr(name, SPA.TPP_ORG_UNIT, [tpp_policy.org_unit.value], tpp_policy.org_unit.locked)
        if tpp_policy.city:
            self._set_policy_attr(name, SPA.TPP_CITY, [tpp_policy.city.value], tpp_policy.city.locked)
        if tpp_policy.state:
            self._set_policy_attr(name, SPA.TPP_STATE, [tpp_policy.state.value], tpp_policy.state.locked)
        if tpp_policy.country:
            self._set_policy_attr(name, SPA.TPP_COUNTRY, [tpp_policy.country.value], tpp_policy.state.locked)
        if tpp_policy.key_algo:
            self._set_policy_attr(name, SPA.TPP_KEY_ALGORITHM, [tpp_policy.key_algo.value], tpp_policy.key_algo.locked)
        if tpp_policy.key_bit_str:
            self._set_policy_attr(name, SPA.TPP_KEY_BIT_STR, [tpp_policy.key_bit_str.value],
                                  tpp_policy.key_bit_str.locked)
        if tpp_policy.elliptic_curve:
            self._set_policy_attr(name, SPA.TPP_ELLIPTIC_CURVE, [tpp_policy.elliptic_curve.value],
                                  tpp_policy.elliptic_curve.locked)
        if tpp_policy.management_type:
            self._set_policy_attr(name, SPA.TPP_MANAGEMENT_TYPE, [tpp_policy.management_type.value],
                                  tpp_policy.management_type.locked)

        if tpp_policy.wildcards_allowed is not None:
            int_val = get_int_value(not tpp_policy.wildcards_allowed)
            self._set_policy_attr(name, SPA.TPP_PROHIBIT_WILDCARD, [int_val], False)
        if tpp_policy.service_generated is not None:
            int_val = get_int_value(not tpp_policy.service_generated)
            self._set_policy_attr(name, SPA.TPP_MANUAL_CSR, [int_val], tpp_policy.service_generated.locked)
        if tpp_policy.allow_private_key_reuse is not None:
            int_val = get_int_value(tpp_policy.allow_private_key_reuse)
            self._set_policy_attr(name, SPA.TPP_ALLOWED_PRIVATE_KEY_REUSE, [int_val], True)
        if tpp_policy.want_renewal is not None:
            int_val = get_int_value(tpp_policy.want_renewal)
            self._set_policy_attr(name, SPA.TPP_WANT_RENEWAL, [int_val], True)

        prohibited_sans = tpp_policy.get_prohibited_sans()
        if len(prohibited_sans) > 0:
            self._set_policy_attr(name, SPA.TPP_PROHIBITED_SAN_TYPES, prohibited_sans, False)

        return

    def request_ssh_cert(self, request):
        """

        :param SSHCertRequest request:
        :rtype: bool
        """
        json_request = build_tpp_request(request)
        log.info(f"Requesting SSH Certificate with id {request.key_id}")
        # TODO: Change _post() with post(args)
        status, data = self._post(URLS.SSH_CERTIFICATE_REQUEST, json_request)

        if status == HTTPStatus.OK:
            response_object = SSHResponse(data['Response'])
            if response_object.success:
                cert_req_response = SSHCertResponse(data)
                request.pickup_id = cert_req_response.dn
                request.guid = cert_req_response.guid
                return True
            else:
                raise VenafiError(f"An error occurred with status {response_object.error_code}. "
                                  f"Message: {response_object.error_msg}")
        else:
            raise ServerUnexptedBehavior(f"Server returns {status} status on requesting SSH certificate.")

    def retrieve_ssh_cert(self, request):
        """

        :param SSHCertRequest request:
        :rtype: SSHRetrieveResponse
        """
        json_request = build_tpp_retrieve_request(request)
        log.info(f"Retrieving SSH Certificate with id {request.pickup_id}")

        time_start = time.time()
        while True:
            try:
                # TODO: Change _post() with post(args)
                status, data = self._post(URLS.SSH_CERTIFICATE_RETRIEVE, json_request)
            except VenafiError:
                log.debug(f"SSH Certificate with id {request.pickup_id} not found")
                status = 0

            if status == HTTPStatus.OK:
                response_object = SSHResponse(data['Response'])
                if response_object.success:
                    return SSHRetrieveResponse(data)
                else:
                    log.info(f"Failed to retrieve certificate with following details:"
                             f"\nDN: {json_request['DN']}"
                             f"\nGuid: {json_request['Guid']}"
                             f"\nErrorCode: {response_object.error_code}"
                             f"\nErrorMessage: {response_object.error_msg}")

            if (time.time() - time_start) < request.timeout:
                log.debug("Waiting for certificate...")
                time.sleep(2)
            else:
                raise RetrieveCertificateTimeoutError(f"Operation timed out at {request.timeout} seconds while "
                                                      f"retrieving SSH certificate with id {request.pickup_id}")

    def retrieve_ssh_config(self, ca_request):
        """

        :param SSHCATemplateRequest ca_request:
        :rtype: SSHConfig
        """
        key = None
        value = None
        if ca_request.template:
            key = 'DN'
            value = ca_request.template
            if not value.startswith(PATH_SEPARATOR):
                value = f"{PATH_SEPARATOR}{value}"
            if not value.startswith(CA_ROOT_PATH):
                value = f"{CA_ROOT_PATH}{value}"
        elif ca_request.guid:
            key = 'guid'
            value = ca_request.guid
        else:
            raise ClientBadData("CA Guid or CA template must be provided to retrieve SSH config.")

        value = url_parse.quote(value)
        query = f"{key}={value}"
        url = f"{URLS.SSH_CA_PUBLIC_KEY}?{query}"

        args = {
            self.ARG_URL: url,
            self.ARG_CHECK_TOKEN: False,
            self.ARG_INCLUDE_TOKEN_HEADER: False
        }
        status, data = self.get(args=args)
        if status == HTTPStatus.OK:
            ssh_config_response = SSHConfig()
            ssh_config_response.ca_public_key = data
            if self._is_valid_auth():
                details = self._retrieve_ssh_ca_details(ca_request)
                ssh_config_response.ca_principals = details.access_control.default_principals
            return ssh_config_response
        else:
            raise ServerUnexptedBehavior(f"Server returns {status} status on requesting "
                                         f"SSH CA Public Key Data for {key} = {value}")

    def get(self, args):
        """

        :param dict args:
        :rtype: tuple[Any, Any]
        """
        raise NotImplementedError

    def post(self, args):
        """

        :param dict args:
        :rtype: tuple[Any, Any]
        """
        raise NotImplementedError

    # ======================================== API IMPLEMENTATION ENDS ======================================== #
    # ========================================================================================================= #

    def _policy_exists(self, zone):
        """
        :param str zone:
        :rtype bool:
        """
        req_data = {'ObjectDN': zone}
        # TODO: Change _post() with post(args)
        status, data = self._post(URLS.POLICY_IS_VALID, data=req_data)

        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior(f"Could not complete request. Status {status}. {data}")

        if data['Result'] == 1 and data['Object']['TypeName'] == POLICY_CLASS:
            return True
        elif data['Result'] == 400 and 'Error' in data:
            return False

        log.error(f"Unknown error while executing. Status: {status}.Data: {data}.")
        raise VenafiError

    def _set_policy_attr(self, zone, attr_name, attr_values, locked):
        """
        :param str zone: The policy name
        :param str attr_name: The name of the attribute to be set
        :param any attr_values: The values assigned to the attr_name
        :param bool locked: Whether the attribute should be policy locked
        :rtype: tuple[str, SetAttrResponse]
        """
        data = {
            'Locked': locked,
            'ObjectDN': zone,
            'Class': POLICY_ATTR_CLASS,
            'AttributeName': attr_name,
            'Values': attr_values
        }

        # TODO: Change _post() with post(args)
        status, response = self._post(URLS.POLICY_SET_ATTRIBUTE, data=data)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior(f"Got status {status} from server")

        response = self._parse_attr_response(response)

        if response.error:
            raise VenafiError(f"Error while setting attribute [{attr_name}] in policy [{zone}]")

        return status, response

    def _reset_policy_attr(self, zone, attr_name):
        """
        :param str zone:
        :param str attr_name:
        :rtype: tuple[str, SetAttrResponse]
        """
        data = {
            'ObjectDN': zone,
            'Class':  POLICY_ATTR_CLASS,
            'AttributeName': attr_name,
        }

        # TODO: Change _post() with post(args)
        status, response = self._post(URLS.POLICY_CLEAR_ATTRIBUTE, data=data)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior(f"Got status {status} from server")

        response = self._parse_attr_response(response)

        if response.error:
            raise VenafiError(f"Error while setting attribute [{attr_name}] in policy [{zone}]")

        return status, response

    def _reset_policy(self, zone):
        atrr_list = [SPA.TPP_DOMAIN_SUFFIX_WHITELIST, SPA.TPP_PROHIBIT_WILDCARD, SPA.TPP_CERT_AUTHORITY,
                     SPA.TPP_ORGANIZATION, SPA.TPP_ORG_UNIT, SPA.TPP_CITY, SPA.TPP_STATE, SPA.TPP_COUNTRY,
                     SPA.TPP_KEY_ALGORITHM, SPA.TPP_KEY_BIT_STR, SPA.TPP_ELLIPTIC_CURVE, SPA.TPP_MANUAL_CSR,
                     SPA.TPP_PROHIBITED_SAN_TYPES, SPA.TPP_ALLOWED_PRIVATE_KEY_REUSE, SPA.TPP_WANT_RENEWAL,
                     SPA.TPP_MANAGEMENT_TYPE]
        for attr in atrr_list:
            self._reset_policy_attr(zone, attr)

    @staticmethod
    def _parse_attr_response(response):
        """
        :param dict response:
        :rtype: SetAttrResponse
        """
        if not response:
            raise VenafiError('Response is empty')

        err = response['Error'] if 'Error' in response else None
        result = response['Result'] if 'Result' in response else None

        return SetAttrResponse(result, err)

    @staticmethod
    def _normalize_zone(zone):
        if zone is None:
            log.error("Zone argument is empty")
            raise ClientBadData
        if not re.match(r"^((\\[^\\<]+)|([^\\<]+))+$", zone):
            log.error(f"Bad zone format: {zone}")
            raise ClientBadData

        if zone.startswith("\\VED\\Policy"):
            return zone
        elif zone.startswith("VED\\Policy"):
            return f"\\{zone}"
        elif zone.startswith("\\"):
            return f"\\VED\\Policy{zone}"
        else:
            return f"\\VED\\Policy\\{zone}"

    @staticmethod
    def _get_policy_parent(zone):
        """
        :param str zone:
        """
        if zone is None:
            raise ClientBadData("Zone is empty")
        index = zone.rindex('\\')
        # Return a substring of zone that starts at 0 and ends at index. Zone here is treated as an slice
        # zone[0:index] returns the same result
        return zone[:index]

    def wrap_alt_names(self, request):
        """

        :param CertificateRequest request:
        :rtype: list[dict]
        """
        items = []
        for value in request.user_principal_names:
            items.append(self._create_san_item(0, value))
        for value in request.email_addresses:
            items.append(self._create_san_item(1, value))
        for value in request.san_dns:
            items.append(self._create_san_item(2, value))
        for value in request.uniform_resource_identifiers:
            items.append(self._create_san_item(6, value))
        for value in request.ip_addresses:
            items.append(self._create_san_item(7, value))
        return items

    @staticmethod
    def _create_san_item(san_type, value):
        """

        :param int san_type:
        :param str value:
        :return: dict
        """
        return {
            'Type': san_type,
            'Name': value
        }

    def search_by_thumbprint(self, thumbprint):
        """
        :param str thumbprint:
        :rtype: str
        """
        thumbprint = re.sub(r'[^\dabcdefABCDEF]', "", thumbprint)
        thumbprint = thumbprint.upper()
        # TODO: Change _post() with post(args)
        status, data = self._get(URLS.CERTIFICATE_SEARCH, params={"Thumbprint": thumbprint})
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior

        if not data['Certificates']:
            raise ClientBadData("Certificate not found by thumbprint")
        return data['Certificates'][0]['DN']

    @staticmethod
    def _parse_zone_config_to_policy(data):
        # todo: parse over values to regexps (dont forget tests!)
        p = data['Policy']
        if p['KeyPair']['KeyAlgorithm']['Locked']:
            if p['KeyPair']['KeyAlgorithm']['Value'] == 'RSA':
                if p['KeyPair']['KeySize']['Locked']:
                    key_types = [KeyType(KeyType.RSA, p['KeyPair']['KeySize']['Value'])]
                else:
                    key_types = [KeyType(KeyType.RSA, x) for x in KeyType.ALLOWED_SIZES]
            elif p['KeyPair']['KeyAlgorithm']['Value'] == 'ECC':
                if p['KeyPair']['EllipticCurve']['Locked']:
                    key_types = [KeyType(KeyType.ECDSA, p['KeyPair']['EllipticCurve']['Value'])]
                else:
                    key_types = [KeyType(KeyType.ECDSA, x) for x in KeyType.ALLOWED_CURVES]
            else:
                raise ServerUnexptedBehavior
        else:
            key_types = []
            if p['KeyPair'].get('KeySize', {}).get('Locked'):
                key_types += [KeyType(KeyType.RSA, p['KeyPair']['KeySize']['Value'])]
            else:
                key_types += [KeyType(KeyType.RSA, x) for x in KeyType.ALLOWED_SIZES]
            if p['KeyPair'].get('EllipticCurve', {}).get('Locked'):
                key_types += [KeyType(KeyType.ECDSA, p['KeyPair']['EllipticCurve']['Value'])]
            else:
                key_types += [KeyType(KeyType.ECDSA, x) for x in KeyType.ALLOWED_CURVES]
        return Policy(key_types=key_types)

    @staticmethod
    def _parse_zone_data_to_object(data):
        s = data['Policy']['Subject']
        ou = s['OrganizationalUnit'].get('Values')
        policy = AbstractTPPConnection._parse_zone_config_to_policy(data)
        if data['Policy']['KeyPair']['KeyAlgorithm']['Value'] == 'RSA':
            key_type = KeyType(KeyType.RSA, data['Policy']['KeyPair']['KeySize']['Value'])
        elif data['Policy']['KeyPair']['KeyAlgorithm']['Value'] == 'ECC':
            key_type = KeyType(KeyType.ECDSA, data['Policy']['KeyPair']['EllipticCurve']['Value'])
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

    def _get_certificate_details(self, cert_guid):
        # TODO: Change _get() with get(args)
        status, data = self._get(URLS.CERTIFICATE_SEARCH + cert_guid)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("")
        return data

    def _is_valid_auth(self):
        raise NotImplementedError

    def _retrieve_ssh_ca_details(self, ca_request):
        """

        :param SSHCATemplateRequest ca_request:
        :rtype: SSHTPPCADetails
        """
        json_request = dict()
        if ca_request.template:
            value = ca_request.template
            if not value.startswith(PATH_SEPARATOR):
                value = f"{PATH_SEPARATOR}{value}"
            if not value.startswith(CA_ROOT_PATH):
                value = f"{CA_ROOT_PATH}{value}"
            json_request['DN'] = value
        elif ca_request.guid:
            json_request['Guid'] = ca_request.guid
        else:
            raise ClientBadData("CA Guid or CA template must be provided to retrieve SSH CA details.")

        args = {
            self.ARG_URL: URLS.SSH_CA_DETAILS,
            self.ARG_DATA: json_request
        }
        status, data = self.post(args=args)
        if status == HTTPStatus.OK:
            response_object = SSHResponse(data['Response'])
            if response_object.success:
                return SSHTPPCADetails(data)
            else:
                raise VenafiError(f"An error occurred with status {response_object.error_code}. "
                                  f"Message: {response_object.error_msg}")
        else:
            raise ServerUnexptedBehavior(f"Server returns {status} status on requesting SSH CA details")
