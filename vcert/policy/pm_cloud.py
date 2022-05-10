#
# Copyright 2021 Venafi, Inc.
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
from vcert.common import Policy as Cit, KeyType
from vcert.errors import VenafiError
from vcert.policy import RPA, DEFAULT_CA
from vcert.policy.policy_spec import (Policy, Subject, KeyPair, DefaultSubject, DefaultKeyPair, PolicySpecification,
                                      Defaults, SubjectAltNames)
from vcert.vaas_utils import AppDetails

supported_rsa_key_sizes = [1024, 2048, 3072, 4096]
supported_elliptic_curves = ["P256", "P384", "P521", "ED25519"]
CA_TYPE_DIGICERT = 'DIGICERT'
CA_TYPE_ENTRUST = 'ENTRUST'
REQUESTER_NAME = 'Venafi Cloud Service'
REQUESTER_EMAIL = 'no-reply@venafi.cloud'
REQUESTER_PHONE = '801-555-0123'
ipv4 = "v4"
ipv6 = "v6"
ipv4_private = "v4private"
ipv6_private = "v6private"
re_allow_all = '.*'
re_allow_all_email = '.*@.*'
re_ipv4 = "\\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|$)){4}\\b"
re_ipv6 = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]" \
          "{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|" \
          "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|" \
          "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%" \
          "[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|" \
          "(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.)" \
          "{3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
re_ipv4_private = "^(172\\.(1[6-9]\\.|2[0-9]\\.|3[0-1]\\.)|192\\.168\\.|10\\.).*"
re_ipv6_private = "^(::1$)|([fF][cCdD]).*"
supported_ip_protocols = {
    ipv4: re_ipv4,
    ipv6: re_ipv6,
    ipv4_private: re_ipv4_private,
    ipv6_private: re_ipv6_private
}
DEFAULT_MAX_VALID_DAYS = 365
DEFAULT_HASH_ALGORITHM = 'SHA256'

default_error_msg = 'Default value does not match with policy values.' \
                    '\nAttribute: {}\nDefault value:{}\nPolicy values:{}'


def build_policy_spec(cit, ca_info, subject_cn_to_str=True):
    """
    :param Cit cit:
    :param CertificateAuthorityInfo ca_info:
    :param bool subject_cn_to_str: Indicates whether or not to remove the regex pattern from the Common Name values
    :rtype: PolicySpecification
    """
    if not cit:
        raise VenafiError("Certificate issuing template is empty")

    ps = PolicySpecification()
    p = Policy()
    p.wildcard_allowed = is_wildcard_allowed(cit.SubjectCNRegexes)
    if len(cit.SubjectCNRegexes) > 0:
        if subject_cn_to_str:
            domains = convert_to_string(cit.SubjectCNRegexes, p.wildcard_allowed)
            p.domains = domains
        else:
            p.domains = cit.SubjectCNRegexes
    else:
        p.domains = None

    if cit.validity_period:
        # getting days in format P#D
        days = cit.validity_period[1:len(cit.validity_period)-1]
        int_value = int(days)
        p.max_valid_days = int_value

    if ca_info:
        ca = f"{ca_info.ca_type}\\{ca_info.ca_account_key}\\{ca_info.vendor_name}"
        p.certificate_authority = ca

    s = Subject()
    create_subject = False
    if len(cit.SubjectORegexes) > 0:
        create_subject = True
        s.orgs = cit.SubjectORegexes
    if len(cit.SubjectOURegexes) > 0:
        create_subject = True
        s.org_units = cit.SubjectOURegexes
    if len(cit.SubjectLRegexes) > 0:
        create_subject = True
        s.localities = cit.SubjectLRegexes
    if len(cit.SubjectSTRegexes) > 0:
        create_subject = True
        s.states = cit.SubjectSTRegexes
    if len(cit.SubjectCRegexes) > 0:
        create_subject = True
        s.countries = cit.SubjectCRegexes

    p.subject = s if create_subject else None

    kp = KeyPair()
    create_kp = False
    if len(cit.key_types) > 0:
        key_types = []
        rsa_key_sizes = []
        elliptic_curves = []
        for kt in cit.key_types:
            if kt.key_type.upper() == KeyType.RSA.upper():
                rsa_key_sizes.append(kt.option)
            elif kt.key_type.upper() == KeyType.ECDSA.upper():
                elliptic_curves.append(kt.option)
            # Only include one instance of the KeyType
            if kt.key_type.upper() not in key_types:
                key_types.append(kt.key_type.upper())
        create_kp = True
        kp.key_types = key_types
        kp.rsa_key_sizes = rsa_key_sizes
        kp.elliptic_curves = elliptic_curves

    kp.reuse_allowed = cit.key_reuse
    if cit.key_generated_by_venafi_allowed is True and cit.csr_upload_allowed is True:
        kp.service_generated = None
    elif cit.key_generated_by_venafi_allowed:
        kp.service_generated = True
        create_kp = True
    elif cit.csr_upload_allowed:
        kp.service_generated = False
        create_kp = True

    p.key_pair = kp if create_kp else None

    sans = SubjectAltNames(False, False, False, False, False)
    create_sans = False
    if cit.SANRegexes:
        sans.dns_allowed = True
        create_sans = True

    if cit.email_regexes and len(cit.email_regexes) > 0:
        sans.email_allowed = True
        create_sans = True

    if cit.ip_constraints_regexes and len(cit.ip_constraints_regexes) > 0:
        sans.ip_allowed = True
        create_sans = True
        sans.ip_constraints = resolve_ip_constraints(cit.ip_constraints_regexes)

    if cit.uri_regexes and len(cit.uri_regexes) > 0:
        sans.uri_allowed = True
        create_sans = True
        sans.uri_protocols = resolve_uri_protocols(cit.uri_regexes)

    p.subject_alt_names = sans if create_sans else None

    ps.policy = p

    rs = cit.recommended_settings
    if rs:
        d = Defaults()
        ds = DefaultSubject()
        create_ds = False
        if rs.subjectOValue:
            ds.org = rs.subjectOValue
            create_ds = True
        if rs.subjectOUValue:
            ds.org_units = [rs.subjectOUValue]
            create_ds = True
        if rs.subjectLValue:
            ds.locality = rs.subjectLValue
            create_ds = True
        if rs.subjectSTValue:
            ds.state = rs.subjectSTValue
            create_ds = True
        if rs.subjectCValue:
            ds.country = rs.subjectCValue
            create_ds = True

        d.subject = ds if create_ds else None

        kt = rs.keyType
        if kt:
            dkp = DefaultKeyPair()
            create_dkp = False
            if kt.key_type:
                create_dkp = True
                dkp.key_type = kt.key_type.upper()
                if kt.key_type == KeyType.RSA:
                    dkp.rsa_key_size = kt.option
                elif kt.key_type == KeyType.ECDSA:
                    dkp.elliptic_curve = kt.option

            d.key_pair = dkp if create_dkp else None

        ps.defaults = d
    return ps


def validate_policy_spec(policy_spec):
    """
    :param PolicySpecification policy_spec:
    """
    # validate policy values
    if policy_spec.policy:
        p = policy_spec.policy

        # validate key pair values
        if policy_spec.policy.key_pair:
            key_types = _get_key_types_lowercase(policy_spec.policy.key_pair.key_types)

            if len(key_types) > 2:
                raise VenafiError("Key Type values exceeded. Only RSA and EC Key Types are allowed by VaaS")

            if key_types:
                for kt in key_types:
                    if kt not in [KeyType.RSA, KeyType.ECDSA]:
                        raise VenafiError(f"Key Type [{kt}] is not supported by VaaS")

            if KeyType.RSA in key_types and len(policy_spec.policy.key_pair.rsa_key_sizes) > 0:
                invalid_value = get_invalid_cloud_rsa_key_size_value(policy_spec.policy.key_pair.rsa_key_sizes)
                if invalid_value:
                    raise VenafiError(f"The Key Size [{invalid_value}] is not supported by VaaS")

            if KeyType.ECDSA in key_types and len(policy_spec.policy.key_pair.elliptic_curves) > 0:
                invalid_value = get_invalid_cloud_ec_value(policy_spec.policy.key_pair.elliptic_curves)
                if invalid_value:
                    raise VenafiError(f"The Elliptic Curve [{invalid_value}] is not supported by VaaS")

        # validate subject CN and SAN regexes
        if p.subject_alt_names:
            sans = get_sans(policy_spec.policy.subject_alt_names)
            if len(sans) > 0:
                for k, v in sans.items():
                    if v is True and (k == RPA.TPP_UPN_ALLOWED):
                        raise VenafiError(f"Subject Alt name [{k}] is not allowed by VaaS")
                    if v is True and (k == RPA.TPP_URI_ALLOWED):
                        if len(p.subject_alt_names.uri_protocols) == 0:
                            raise VenafiError(f"'uriAllowed' attribute is True but 'uriProtocols' list is empty")
                    if v is True and (k == RPA.TPP_IP_ALLOWED):
                        ip_constraints = p.subject_alt_names.ip_constraints
                        if ip_constraints and len(ip_constraints) > 0:
                            invalid_value = get_invalid_ip_constraint(ip_constraints)
                            if invalid_value:
                                raise VenafiError(f"The IP constraint [{invalid_value}] is not supported by VaaS")

        # validate default subject values against policy values
        if policy_spec.defaults and policy_spec.defaults.subject and policy_spec.policy.subject:
            ds = policy_spec.defaults.subject
            s = policy_spec.policy.subject

            if ds.org and len(s.orgs) > 0:
                if not is_valid_policy_value(s.orgs, ds.org):
                    raise VenafiError(default_error_msg.format('Organization', ds.org, s.orgs))

            if ds.org_units and len(ds.org_units) > 0 and len(s.org_units) > 0:
                if not member_of(ds.org_units, s.org_units):
                    raise VenafiError(default_error_msg.format('Org Units', ds.org_units, s.org_units))

            if ds.locality and len(s.localities) > 0:
                if not is_valid_policy_value(s.localities, ds.locality):
                    raise VenafiError(default_error_msg.format('Localities', ds.locality, s.localities))

            if ds.state and len(s.states) > 0:
                if not is_valid_policy_value(s.states, ds.state):
                    raise VenafiError(default_error_msg.format('States', ds.state, s.states))

            if ds.country and len(s.countries) > 0:
                if not is_valid_policy_value(s.countries, ds.country):
                    raise VenafiError(default_error_msg.format('Countries', ds.country, s.countries))

        # validate default key pair values against policy values
        if policy_spec.defaults and policy_spec.defaults.key_pair and policy_spec.policy.key_pair:
            dkp = policy_spec.defaults.key_pair
            kp = policy_spec.policy.key_pair

            if dkp.key_type and len(kp.key_types) > 0:
                if dkp.key_type not in kp.key_types:
                    raise VenafiError(default_error_msg.format('Key Types', dkp.key_type, kp.key_types))

            if dkp.rsa_key_size and len(kp.rsa_key_sizes) > 0:
                if dkp.rsa_key_size not in kp.rsa_key_sizes:
                    raise VenafiError(default_error_msg.format('RSA Key Sizes', dkp.rsa_key_size, kp.rsa_key_sizes))

            if dkp.elliptic_curve and len(kp.elliptic_curves) > 0:
                if dkp.elliptic_curve not in kp.elliptic_curves:
                    raise VenafiError(default_error_msg.format('Elliptic Curves', dkp.elliptic_curve,
                                                               kp.elliptic_curves))

            if dkp.service_generated is not None and kp.service_generated is not None:
                if dkp.service_generated != kp.service_generated:
                    raise VenafiError(
                        default_error_msg.format('Service Generated', dkp.service_generated, kp.service_generated))
    else:
        policy_spec.policy = Policy()

    # validate default values regardless of policy being defined
    if policy_spec.defaults and policy_spec.defaults.key_pair:
        dkp = policy_spec.defaults.key_pair

        if dkp.key_type and dkp.key_type.lower() not in [KeyType.RSA, KeyType.ECDSA]:
            raise VenafiError(f"Default Key Type [{dkp.key_type}] is not supported by VaaS")

        if dkp.rsa_key_size:
            invalid_value = get_invalid_cloud_rsa_key_size_value([dkp.rsa_key_size])
            if invalid_value:
                raise VenafiError(f"Default RSA Key Size [{invalid_value}] is not supported by VaaS")

        if dkp.elliptic_curve:
            invalid_value = get_invalid_cloud_ec_value([dkp.elliptic_curve])
            if invalid_value:
                raise VenafiError(f"Default Elliptic Curve [{invalid_value}] is not supported by VaaS")


def _get_key_types_lowercase(key_types):
    lower_kt = []
    if key_types:
        for kt in key_types:
            lower_kt.append(kt.lower())

    return lower_kt


def get_invalid_cloud_rsa_key_size_value(rsa_keys):
    """
    :param list[int] rsa_keys:
    :rtype: int
    """
    for v in rsa_keys:
        if v not in supported_rsa_key_sizes:
            return v
    return None


def get_invalid_cloud_ec_value(elliptic_curves):
    """

    :param list[str] elliptic_curves:
    :rtype: str
    """
    for v in elliptic_curves:
        if v not in supported_elliptic_curves:
            return v

    return None


def get_sans(names):
    """
    :param SubjectAltNames names:
    :rtype: dict[str, bool]
    """
    sans = dict()
    if names.dns_allowed is not None:
        sans[RPA.TPP_DNS_ALLOWED] = names.dns_allowed
    if names.ip_allowed is not None:
        sans[RPA.TPP_IP_ALLOWED] = names.ip_allowed
    if names.email_allowed is not None:
        sans[RPA.TPP_EMAIL_ALLOWED] = names.email_allowed
    if names.upn_allowed is not None:
        sans[RPA.TPP_UPN_ALLOWED] = names.upn_allowed
    if names.uri_allowed is not None:
        sans[RPA.TPP_URI_ALLOWED] = names.uri_allowed

    return sans


def get_invalid_ip_constraint(ip_list):
    """

    :param list[str] ip_list:
    :rtype: str
    """
    for ip_value in ip_list:
        if ip_value not in supported_ip_protocols.keys():
            return ip_value

    return None


def is_valid_policy_value(policy_values, default_value):
    """
    :param list[str] policy_values:
    :param str default_value:
    :rtype: bool
    """
    if len(policy_values) == 1 and policy_values[0] == re_allow_all:
        return True
    return True if default_value in policy_values else False


def member_of(sub_list, collection):
    """
    Tests that all the elements of the sublist are present in the collection

    :param list[str] sub_list:
    :param list[str] collection:
    :rtype: bool
    """
    if len(sub_list) == 1 and sub_list[0] == re_allow_all:
        return True
    return all(x in collection for x in sub_list)


def get_ca_info(ca_name):
    """
    :param str ca_name:
    :rtype: CertificateAuthorityInfo
    """
    data = ca_name.split("\\")
    if len(data) < 3:
        raise VenafiError(f"Certificate Authority name invalid [{ca_name}]")

    return CertificateAuthorityInfo(data[0], data[1], data[2])


def build_cit_request(ps, ca_details):
    """
    :param PolicySpecification ps:
    :param CertificateAuthorityDetails ca_details:
    :rtype: dict
    """
    request = dict()

    if ps.policy and ps.policy.certificate_authority:
        ca_str = ps.policy.certificate_authority
    else:
        ca_str = DEFAULT_CA

    cert_auth = get_ca_info(ca_str)

    request['certificateAuthority'] = cert_auth.ca_type
    request['certificateAuthorityProductOptionId'] = ca_details.product_option_id

    if ps.policy and ps.policy.max_valid_days:
        validity = ps.policy.max_valid_days
    else:
        validity = DEFAULT_MAX_VALID_DAYS

    product = {
        'certificateAuthority': cert_auth.ca_type,
        'productName': cert_auth.vendor_name,
        'validityPeriod': f"P{validity}D"
    }

    if cert_auth.ca_type == CA_TYPE_DIGICERT:
        product['hashAlgorithm'] = DEFAULT_HASH_ALGORITHM
        product['autoRenew'] = False
        product['organizationId'] = ca_details.organization_id
    elif cert_auth.ca_type == CA_TYPE_ENTRUST:
        tracking_data = {
            'certificateAuthority': CA_TYPE_ENTRUST,
            'requesterName': REQUESTER_NAME,
            'requesterEmail': REQUESTER_EMAIL,
            'requesterPhone': REQUESTER_PHONE
        }
        request['trackingData'] = tracking_data

    request['product'] = product

    if ps.policy and len(ps.policy.domains) > 0:
        regex_value = convert_to_regex(ps.policy.domains, ps.policy.wildcard_allowed)
        request['subjectCNRegexes'] = regex_value
        sans = ps.policy.subject_alt_names
        if sans and sans.dns_allowed is not None:
            if sans.dns_allowed:
                request['sanRegexes'] = regex_value
        else:
            request['sanRegexes'] = regex_value

        if sans and sans.email_allowed:
            email_regex_list = convert_to_email_regex(ps.policy.domains)
            request['sanRfc822NameRegexes'] = email_regex_list

        if sans and sans.uri_allowed:
            uri_regex_list = convert_to_uri_regex(sans.uri_protocols, ps.policy.domains)
            request['sanUniformResourceIdentifierRegexes'] = uri_regex_list

    # sanIpAddressRegexes

    else:
        request['subjectCNRegexes'] = [re_allow_all]
        request['sanRegexes'] = [re_allow_all]
        if ps.policy:
            sans = ps.policy.subject_alt_names
            if sans and sans.email_allowed:
                request['sanRfc822NameRegexes'] = [re_allow_all_email]
            if sans and sans.uri_allowed:
                uri_regex_list = convert_to_uri_regex(sans.uri_protocols, [re_allow_all])
                request['sanUniformResourceIdentifierRegexes'] = uri_regex_list
            if sans and sans.ip_allowed:
                request['sanIpAddressRegexes'] = []

    if ps.policy and ps.policy.subject_alt_names and ps.policy.subject_alt_names.ip_allowed:
        if ps.policy.subject_alt_names.ip_constraints and len(ps.policy.subject_alt_names.ip_constraints) > 0:
            request['sanIpAddressRegexes'] = resolve_ip_regexes(ps.policy.subject_alt_names.ip_constraints)
        else:
            request['sanIpAddressRegexes'] = [re_ipv4, re_ipv6]

    if ps.policy and ps.policy.subject and len(ps.policy.subject.orgs) > 0:
        request['subjectORegexes'] = ps.policy.subject.orgs
    else:
        request['subjectORegexes'] = [re_allow_all]

    if ps.policy and ps.policy.subject and len(ps.policy.subject.org_units) > 0:
        request['subjectOURegexes'] = ps.policy.subject.org_units
    else:
        request['subjectOURegexes'] = [re_allow_all]

    if ps.policy and ps.policy.subject and len(ps.policy.subject.localities) > 0:
        request['subjectLRegexes'] = ps.policy.subject.localities
    else:
        request['subjectLRegexes'] = [re_allow_all]

    if ps.policy and ps.policy.subject and len(ps.policy.subject.states) > 0:
        request['subjectSTRegexes'] = ps.policy.subject.states
    else:
        request['subjectSTRegexes'] = [re_allow_all]

    if ps.policy and ps.policy.subject and len(ps.policy.subject.countries) > 0:
        request['subjectCValues'] = ps.policy.subject.countries
    else:
        request['subjectCValues'] = [re_allow_all]

    key_types = []
    if ps.policy and ps.policy.key_pair and len(ps.policy.key_pair.key_types) > 0:
        kt_lowercase = _get_key_types_lowercase(ps.policy.key_pair.key_types)

        if KeyType.RSA in kt_lowercase:
            rsa_kt = dict()
            rsa_kt['keyType'] = KeyType.RSA.upper()

            if ps.policy and ps.policy.key_pair and len(ps.policy.key_pair.rsa_key_sizes) > 0:
                rsa_kt['keyLengths'] = ps.policy.key_pair.rsa_key_sizes
            elif ps.defaults and ps.defaults.key_pair and ps.defaults.key_pair.rsa_key_size:
                rsa_kt['keyLengths'] = [ps.defaults.key_pair.rsa_key_size]
            else:
                rsa_kt['keyLengths'] = [2048]

            key_types.append(rsa_kt)

        if KeyType.ECDSA in kt_lowercase:
            ec_kt = dict()
            ec_kt['keyType'] = KeyType.ECDSA.upper()

            if ps.policy and ps.policy.key_pair and len(ps.policy.key_pair.elliptic_curves) > 0:
                ec_kt['keyCurves'] = ps.policy.key_pair.elliptic_curves
            elif ps.defaults and ps.defaults.key_pair and ps.defaults.key_pair.elliptic_curve:
                ec_kt['keyCurves'] = [ps.defaults.key_pair.elliptic_curve]
            else:
                ec_kt['keyCurves'] = ['P256']

            key_types.append(ec_kt)

    request['keyTypes'] = key_types

    if ps.policy and ps.policy.key_pair and ps.policy.key_pair.reuse_allowed:
        request['keyReuse'] = ps.policy.key_pair.reuse_allowed
    else:
        request['keyReuse'] = False

    if ps.policy and ps.policy.key_pair and ps.policy.key_pair.service_generated is not None:
        is_serv_gen = ps.policy.key_pair.service_generated
        request['csrUploadAllowed'] = not is_serv_gen
        request['keyGeneratedByVenafiAllowed'] = is_serv_gen
    else:
        request['csrUploadAllowed'] = True
        request['keyGeneratedByVenafiAllowed'] = True

    r_settings = dict()
    if ps.defaults and ps.defaults.subject:
        if ps.defaults.subject.org:
            r_settings['subjectOValue'] = ps.defaults.subject.org
        if ps.defaults.subject.org_units:
            r_settings['subjectOUValue'] = ps.defaults.subject.org_units[0]
        if ps.defaults.subject.locality:
            r_settings['subjectLValue'] = ps.defaults.subject.locality
        if ps.defaults.subject.state:
            r_settings['subjectSTValue'] = ps.defaults.subject.state
        if ps.defaults.subject.country:
            r_settings['subjectCValue'] = ps.defaults.subject.country

    r_key = dict()
    if ps.defaults and ps.defaults.key_pair:
        default_kp = ps.defaults.key_pair
        if default_kp.key_type:
            default_kt = default_kp.key_type.upper()
            if default_kt == KeyType.RSA.upper():
                if default_kp.rsa_key_size:
                    r_key['length'] = default_kp.rsa_key_size
                else:
                    r_key['length'] = 2048
            elif default_kt == KeyType.ECDSA.upper():
                if default_kp.elliptic_curve:
                    r_key['curve'] = default_kp.elliptic_curve
                else:
                    r_key['curve'] = 'P256'

            r_key['type'] = default_kt

    if r_key:
        r_settings['key'] = r_key

    if r_settings:
        request['recommendedSettings'] = r_settings

    return request


domain_regex = '[a-z]{1}[a-z0-9.-]*\\.'
domain_regex_wildcard = '[*a-z]{1}[a-z0-9.-]*\\.'
email_prefix_regex = '.*@{}'
uri_protocols_regex = "({})://.*\\."


def convert_to_regex(domains, wildcard_allowed):
    """
    :param list[str] domains:
    :param bool wildcard_allowed:
    :rtype: list[str]
    """
    regex_list = []
    for d in domains:
        current = d.replace('.', '\\.')
        if wildcard_allowed:
            current = domain_regex_wildcard + current
        else:
            current = domain_regex + current
        regex_list.append(current)
    return regex_list


def convert_to_email_regex(emails_list):
    """

    :param list[str] emails_list:
    :rtype: list[str]
    """
    regex_list = []
    for email in emails_list:
        current = email.replace('.', '\\.')
        current = email_prefix_regex.format(current)
        regex_list.append(current)

    return regex_list


def convert_to_uri_regex(uri_protocols, domains_list):
    """

    :param list[str] uri_protocols:
    :param list[str] domains_list:
    :rtype: list[str]
    """
    protocol_expr = "|".join(uri_protocols)
    protocol_expr = uri_protocols_regex.format(protocol_expr)

    regex_list = []
    for d in domains_list:
        current = d.replace('.', '\\.')
        current = f"{protocol_expr}{current}"
        regex_list.append(current)

    return regex_list


def resolve_ip_regexes(ip_protocols):
    """

    :param list[str] ip_protocols:
    :rtype: list[str]
    """
    ip_regexes = list()
    for ip_str in ip_protocols:
        regex = supported_ip_protocols.get(ip_str)
        if regex:
            ip_regexes.append(regex)

    return ip_regexes


def resolve_ip_constraints(ip_constraints_list):
    """

    :param list[str] ip_constraints_list:
    :rtype: list[str]
    """
    ip_list = list()
    for ip_regex in ip_constraints_list:
        for k, v in supported_ip_protocols.items():
            if ip_regex == v:
                ip_list.append(k)
                break
    return ip_list


def resolve_uri_protocols(uri_regexes_list):
    """

    :param list[str] uri_regexes_list:
    :rtype: list[str]
    """
    protocols_list = list()
    for uri_regex in uri_regexes_list:
        index = uri_regex.index(')://')
        sub_str = uri_regex[1:index]
        current_protocols = sub_str.split("|")
        for p in current_protocols:
            if p not in protocols_list:
                protocols_list.append(p)

    return protocols_list


def convert_to_string(regexes, wildcard_allowed):
    """
    :param list[str] regexes:
    :param bool wildcard_allowed:
    :return list[str]:
    """
    pattern = domain_regex_wildcard if wildcard_allowed else domain_regex
    string_list = []
    for r in regexes:
        if r.startswith(pattern):
            r = r.replace(pattern, '')
        r = r.replace('\\.', '.')
        string_list.append(r)
    return string_list


def is_wildcard_allowed(san_regexes):
    """
    :param list[str] san_regexes:
    :rtype: bool
    """
    if not san_regexes:
        return False
    for val in san_regexes:
        if not val.startswith('[*a'):
            return False

    return True


def build_app_update_request(app_details, cit_map):
    """
    :param AppDetails app_details:
    :param dict cit_map:
    :rtype: dict
    """
    app_request = {'ownerIdsAndTypes': app_details.owner_ids_and_types, 'name': app_details.name,
                   'description': app_details.description, 'fqdns': app_details.fq_dns,
                   'internalFqdns': app_details.internal_fq_dns, 'internalIpRanges': app_details.internal_ip_ranges,
                   'externalIpRanges': app_details.external_ip_ranges, 'internalPorts': app_details.internal_ports,
                   'fullyQualifiedDomainNames': app_details.fully_qualified_domain_names,
                   'ipRanges': app_details.ip_ranges, 'ports': app_details.ports,
                   'organizationalUnitId': app_details.org_unit_id, 'certificateIssuingTemplateAliasIdMap': cit_map}
    return app_request


def build_owner_json(owners_list):
    owner_list = list()
    for user in owners_list:
        owner = {
            'ownerId': user.owner_id,
            'ownerType': user.owner_type
        }
        owner_list.append(owner)
    return owner_list


def build_app_create_request(app_name, owners_list, cit_data):
    """

    :param list[OwnerIdsAndTypes] owners_list:
    :param str app_name:
    :param dict cit_data:
    """
    owner_list = build_owner_json(owners_list)
    cit_id, cit_name = get_cit_data_from_response(cit_data)

    app_issuing_template = {
        cit_name: cit_id
    }

    app_request = {
        'ownerIdsAndTypes': owner_list,
        'name': app_name,
        'certificateIssuingTemplateAliasIdMap': app_issuing_template
    }
    return app_request


def get_cit_data_from_response(data):
    """
    Returns the issuing template id and name from the response after creation

    :param dict data:
    :rtype: (str, str)
    """
    cit_id = None
    cit_name = None
    if 'certificateIssuingTemplates' in data:
        cit_list = data['certificateIssuingTemplates']
        if cit_list and len(cit_list) > 0:
            cit_id = data['certificateIssuingTemplates'][0]['id']
            cit_name = data['certificateIssuingTemplates'][0]['name']
    elif 'id' in data:
        cit_id = data['id']
        cit_name = data['name']

    if cit_name and cit_id:
        return cit_id, cit_name
    else:
        raise VenafiError('Error while creating Application request. CIT name or id not found.')


class CertificateAuthorityInfo:
    def __init__(self, ca_type=None, ca_acc_key=None, vendor_name=None):
        """
        :param str ca_type:
        :param str ca_acc_key:
        :param str vendor_name:
        """
        self.ca_type = ca_type
        self.ca_account_key = ca_acc_key
        self.vendor_name = vendor_name


class CertificateAuthorityDetails:
    def __init__(self, product_option_id=None, organization_id=None):
        """
        :param str product_option_id:
        :param int organization_id:
        """
        self.product_option_id = product_option_id
        self.organization_id = organization_id


class AccountDetails:
    def __init__(self, account, product_options):
        """
        :param Account account:
        :param list[ProductOption] product_options:
        """
        self.account = account
        self.product_options = product_options


class Account:
    def __init__(self, account_id, key, certificate_authority):
        """
        :param str account_id:
        :param str key:
        """
        self.id = account_id
        self.key = key
        self.certificate_authority = certificate_authority


class ProductOption:
    def __init__(self, name, product_id, details=None):
        """
        :param str name:
        :param str product_id:
        :param ProductDetails details:
        """
        self.product_name = name
        self.product_id = product_id
        self.details = details


class ProductDetails:
    def __init__(self, product_template=None):
        """
        :param ProductTemplate product_template:
        """
        self.product_template = product_template


class ProductTemplate:
    def __init__(self, organization_id):
        """
        :param int organization_id:
        """
        self.organization_id = organization_id


class UserDetails:
    def __init__(self, user=None, company=None, api_key=None):
        """
        :param user:
        :param company:
        :param api_key:
        """
        self.user = user
        self.company = company
        self.api_key = api_key


class User:
    def __init__(self, username=None, user_id=None, company_id=None, email=None, user_type=None, user_acc_type=None,
                 status=None, creation_date=None):
        """
        :param str username:
        :param str user_id:
        :param str company_id:
        :param str email:
        :param str user_type:
        :param str user_acc_type:
        :param str status:
        :param str creation_date:
        """
        self.username = username
        self.user_id = user_id
        self.company_id = company_id
        self.email = email
        self.user_type = user_type
        self.user_account_type = user_acc_type
        self.status = status
        self.creation_date = creation_date


class Team:
    def __init__(self, team_id=None, name=None, role=None, company_id=None):
        """
        :param str team_id:
        :param str name:
        :param str role:
        :param str company_id:
        """
        self.team_id = team_id
        self.name = name
        self.role = role
        self.company_id = company_id


class Company:
    def __init__(self, company_id, name, company_type=None, active=None, creation_date=None, domains=None):
        """
        :param str company_id:
        :param str name:
        :param str company_type:
        :param bool active:
        :param str creation_date:
        :param list[str] domains:
        """
        self.company_id = company_id
        self.name = name
        self.company_type = company_type
        self.active = active
        self.creation_date = creation_date
        self.domains = domains


class ApiKey:
    def __init__(self, username=None, api_types=None, api_version=None, apikey_status=None, creation_date=None,
                 validity_start_date=None, validity_end_date=None):
        """
        :param string username:
        :param list[str] api_types:
        :param str api_version:
        :param str apikey_status:
        :param str creation_date:
        :param str validity_start_date:
        :param str validity_end_date:
        """
        self.username = username
        self.api_types = api_types
        self.api_version = api_version
        self.apikey_status = apikey_status
        self.creation_date = creation_date
        self.validity_start_date = validity_start_date
        self.validity_end_date = validity_end_date


def build_user(data):
    """
    :param dict data:
    """
    return User(
        username=data['username'] if 'username' in data else None,
        user_id=data['id'] if 'id' in data else None,
        company_id=data['companyId'] if 'companyId' in data else None,
        email=data['emailAddress'] if 'emailAddress' in data else None,
        user_type=data['userType'] if 'userType' in data else None,
        user_acc_type=data['userAccountType'] if 'userAccountType' in data else None,
        status=data['userStatus'] if 'userStatus' in data else None,
        creation_date=data['creationDate'] if 'creationDate' in data else None
        )


def build_team(data):
    """
    :param dict data:
    """
    return Team(
        team_id=data['id'] if 'id' in data else None,
        name=data['name'] if 'name' in data else None,
        role=data['role'] if 'role' in data else None,
        company_id=data['company_id'] if 'company_id' in data else None
    )


def build_company(data):
    """
    :param dict data:
    """
    return Company(
        company_id=data['id'] if 'id' in data else None,
        name=data['name'] if 'name' in data else None,
        company_type=data['companyType'] if 'companyType' in data else None,
        active=data['active'] if 'active' in data else None,
        creation_date=data['creationDate'] if 'creationDate' in data else None,
        domains=data['domains'] if 'domains' in data else None,
    )


def build_apikey(data):
    """
    :param dict data:
    """
    return ApiKey(
        username=data['username'] if 'username' in data else None,
        api_types=data['apitypes'] if 'apitypes' in data else None,
        api_version=data['apiVersion'] if 'apiVersion' in data else None,
        apikey_status=data['apiKeyStatus'] if 'apiKeyStatus' in data else None,
        creation_date=data['creationDate'] if 'creationDate' in data else None,
        validity_start_date=data['validityStartDate'] if 'validityStartDate' in data else None,
        validity_end_date=data['validityEndDate'] if 'validityEndDate' in data else None,
    )


def build_account_details(data):
    """
    :param dict data:
    :rtype: AccountDetails
    """
    a = 'account'
    if not data or a not in data:
        return

    account = Account(data[a]['id'], data[a]['key'], data[a]['certificateAuthority'])
    po_list = []
    for po in data['productOptions']:
        product = build_product_option(po)
        po_list.append(product)

    ad = AccountDetails(account, po_list)
    return ad


def build_product_option(data):
    """
    :param dict data:
    :rtype: ProductOption
    """
    d = 'productDetails'
    t = 'productTemplate'
    if d in data and t in data[d]:
        org_id = data[d][t]['organizationId'] if 'organizationId' in data[d][t] else None
        p_template = ProductTemplate(org_id)
        p_details = ProductDetails(p_template)
        p_option = ProductOption(data['productName'], data['id'], p_details)
        return p_option
