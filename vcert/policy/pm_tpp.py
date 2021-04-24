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
from pprint import pprint

from vcert.common import CertField
from vcert.errors import VenafiError
from vcert.policy import SPA
from vcert.policy.policy_spec import PolicySpecification, Policy, Subject, DefaultSubject, KeyPair, \
    DefaultKeyPair, Defaults, SubjectAltNames


too_many_error_msg = "attribute [%s] has more than one value"
unsupported_error_msg = "one or more values in attribute [%s] are not supported.\nExpected: %s\nGot: %s"
no_match_error_msg = "default value does not mach with policy value for [%s].\nDefault: %s\nPolicy value:%s"

supported_key_types = ["RSA", "ECDSA"]
supported_rsa_key_sizes = [512, 1024, 2048, 3072, 4096]
supported_elliptic_curves = ["P256", "P384", "P521"]
user_generated_csr = 'UserProvided'
mt_provisioning = "Provisioning"
mt_enrollment = "Enrollment"

class TPPPolicy:
    def __init__(self):
        self.name = ""
        self.contact = None
        self.approver = None
        self.wildcards_allowed = None
        self.domain_suffix_whitelist = None
        self.cert_authority = ""
        # Locked Attr
        self.org = None
        self.org_unit = None
        self.city = None
        self.state = None
        self.country = None
        self.key_algo = None
        self.key_bit_str = None
        self.elliptic_curve = None
        self.service_generated = None
        self.management_type = None
        # End locked Attr

        self.dns_allowed = None
        self.email_allowed = None
        self.ip_allowed = None
        self.upn_allowed = None
        self.uri_allowed = None

        self.allow_private_key_reuse = None
        self.want_renewal = None

    def to_policy_spec(self):
        """
        :rtype: PolicySpecification
        """
        # Building Policy > Subject object
        s = Subject()
        create_subject = False
        ds = DefaultSubject()
        create_default_subject = False

        if self.org:
            if self.org.locked:
                create_subject = True
                s.orgs = [self.org.value]
            else:
                create_default_subject = True
                ds.org = self.org.value

        # Most likely org units value will always be a list , even when only one value exists.
        # So, no list created for the var.
        if self.org_unit:
            if self.org_unit.locked:
                create_subject = True
                s.org_units = self.org_unit.value
            else:
                create_default_subject = True
                ds.org_units = self.org_unit.value

        if self.city:
            if self.city.locked:
                create_subject = True
                s.localities = [self.city.value]
            else:
                create_default_subject = True
                ds.locality = self.city.value

        if self.state:
            if self.state.locked:
                create_subject = True
                s.states = [self.state.value]
            else:
                create_default_subject = True
                ds.state = self.state.value

        if self.country:
            if self.country.locked:
                create_subject = True
                s.countries = [self.country.value]
            else:
                create_default_subject = True
                ds.country = self.country.value

        # Building Policy > KeyPair object
        kp = KeyPair()
        create_kp = False
        dkp = DefaultKeyPair()
        create_default_kp = False

        if self.key_algo:
            if self.key_algo.locked:
                create_kp = True
                kp.key_types = [self.key_algo.value]
            else:
                create_default_kp = True
                dkp.key_type = self.key_algo.value

        if self.key_bit_str:
            int_val = int(self.key_bit_str.value)
            if self.key_bit_str.locked:
                create_kp = True
                kp.rsa_key_sizes = [int_val]
            else:
                create_default_kp = True
                dkp.rsa_key_size = int_val

        if self.elliptic_curve:
            if self.elliptic_curve.locked:
                create_kp = True
                kp.key_types = [self.elliptic_curve.value]
            else:
                create_default_kp = True
                dkp.elliptic_curve = self.elliptic_curve.value

        if self.service_generated:
            if self.service_generated.locked:
                create_kp = True
                kp.service_generated = self.service_generated.value
            else:
                create_default_kp = True
                dkp.service_generated = self.service_generated.value

        kp.reuse_allowed = self.allow_private_key_reuse

        # Building Policy object
        p = Policy()
        p.domains = self.domain_suffix_whitelist
        p.certificate_authority = self.cert_authority
        p.wildcard_allowed = self.wildcards_allowed
        p.auto_installed = self._resolve_management_type()

        if create_subject:
            p.subject = s
        if create_kp:
            p.key_pair = kp

        sans = self._resolve_sans()
        if sans:
            p.subject_alt_names = sans

        # Building Defaults object
        d = Defaults()
        if create_default_subject:
            d.subject = ds
        if create_default_kp:
            d.key_pair = dkp

        # Building Policy Specification
        ps = PolicySpecification()
        ps.users = self.contact
        ps.approvers = self.approver
        ps.policy = p
        ps.defaults = d

        return ps

    @staticmethod
    def build_tpp_policy(ps):
        """
        :param PolicySpecification ps: The PolicySpecification object to convert to TPPPolicy object
        :rtype: TPPPolicy
        """
        tpp_policy = TPPPolicy()
        tpp_policy.contact = ps.users
        tpp_policy.approver = ps.approvers

        policy = ps.policy
        defaults = ps.defaults

        subject = policy.subject if policy else None
        d_subject = defaults.subject if defaults else None

        if policy:
            tpp_policy.domain_suffix_whitelist = policy.domains

        if policy and policy.wildcard_allowed is not None:
            tpp_policy.wildcards_allowed = policy.wildcard_allowed

        if policy and policy.certificate_authority:
            tpp_policy.cert_authority = policy.certificate_authority

        if policy and policy.auto_installed is not None:
            val = get_management_type(policy.auto_installed)
            tpp_policy.management_type = CertField(val, True)
        elif defaults and defaults.auto_installed is not None:
            val = get_management_type(defaults.auto_installed)
            tpp_policy.management_type = CertField(val, False)

        if policy and subject and len(subject.orgs) > 0 and subject.orgs[0]:
            tpp_policy.org = CertField(subject.orgs[0], True)
        elif defaults and d_subject and d_subject.org:
            tpp_policy.org = CertField(d_subject.org, False)

        if policy and subject and len(subject.org_units) > 0 and subject.org_units[0]:
            tpp_policy.org_unit = CertField(subject.org_units[0], True)
        elif defaults and d_subject and len(d_subject.org_units) > 0 and d_subject.org_units[0]:
            tpp_policy.org_unit = CertField(d_subject.org_units[0], False)

        if policy and subject and len(subject.localities) > 0 and subject.localities[0]:
            tpp_policy.city = CertField(subject.localities[0], True)
        elif defaults and d_subject and d_subject.locality:
            tpp_policy.city = CertField(d_subject.locality, False)

        if policy and subject and len(subject.states) > 0 and subject.states[0]:
            tpp_policy.state = CertField(subject.states[0], True)
        elif defaults and d_subject and d_subject.state:
            tpp_policy.state = CertField(d_subject.state, False)

        if policy and subject and len(subject.countries) > 0 and subject.countries[0]:
            tpp_policy.country = CertField(subject.countries[0], True)
        elif defaults and d_subject and d_subject.country:
            tpp_policy.country = CertField(d_subject.country, False)

        kp = policy.key_pair if policy else None
        d_kp = defaults.key_pair if defaults else None

        if policy and kp and len(kp.key_types) > 0 and kp.key_types[0]:
            tpp_policy.key_algo = CertField(kp.key_types[0], True)
        elif defaults and d_kp and d_kp.key_type:
            tpp_policy.key_algo = CertField(d_kp.key_type, False)

        if policy and kp and len(kp.rsa_key_sizes) > 0 and kp.rsa_key_sizes[0]:
            tpp_policy.key_bit_str = CertField(kp.rsa_key_sizes[0], True)
        elif defaults and d_kp and d_kp.rsa_key_size:
            tpp_policy.key_bit_str = CertField(d_kp.rsa_key_size,  False)

        if policy and kp and len(kp.elliptic_curves) > 0 and kp.elliptic_curves[0]:
            tpp_policy.elliptic_curve = CertField(kp.elliptic_curves[0], True)
        elif defaults and d_kp and d_kp.elliptic_curve:
            tpp_policy.elliptic_curve = CertField(d_kp.elliptic_curve, False)

        if policy and kp and kp.service_generated is not None:
            tpp_policy.service_generated = CertField(kp.service_generated, True)
        elif defaults and d_kp and d_kp.service_generated is not None:
            tpp_policy.service_generated = CertField(d_kp.service_generated, False)

        if policy and kp and kp.reuse_allowed is not None:
            bool_val = get_bool_value(kp.reuse_allowed)
            tpp_policy.allow_private_key_reuse = bool_val
            tpp_policy.want_renewal = bool_val

        if policy and policy.subject_alt_names:
            sans = policy.subject_alt_names
            tpp_policy.dns_allowed = sans.dns_allowed
            tpp_policy.email_allowed = sans.email_allowed
            tpp_policy.ip_allowed = sans.ip_allowed
            tpp_policy.upn_allowed = sans.upn_allowed
            tpp_policy.uri_allowed = sans.uri_allowed

        return tpp_policy

    def _resolve_sans(self):
        """
        :rtype SubjectAltNames:
        """
        sans = SubjectAltNames()
        sans.dns_allowed = self.dns_allowed
        sans.ip_allowed = self.ip_allowed
        sans.email_allowed = self.email_allowed
        sans.uri_allowed = self.uri_allowed
        sans.upn_allowed = self.upn_allowed

        return sans

    def get_prohibited_sans(self):
        """
        :rtype: list
        """
        prohibited_sans = []
        if not self.dns_allowed:
            prohibited_sans.append(SPA.TPP_DNS)
        if not self.email_allowed:
            prohibited_sans.append(SPA.TPP_EMAIL)
        if not self.ip_allowed:
            prohibited_sans.append(SPA.TPP_IP)
        if not self.upn_allowed:
            prohibited_sans.append(SPA.TPP_UPN)
        if not self.uri_allowed:
            prohibited_sans.append(SPA.TPP_URI)

        return prohibited_sans

    def _resolve_management_type(self):
        """
        :rtype: bool
        """
        if self.management_type == mt_enrollment:
            return False
        elif self.management_type == mt_provisioning:
            return True


class SetAttrResponse:
    def __init__(self, result=None, error=None):
        """
        :param int result:
        :param str error:
        """
        self.result = result
        self.error = error


def is_service_generated_csr(csr_generation):
    """
    :param str csr_generation:
    :param:
    :rtype: CertField
    """
    if not csr_generation:
        raise VenafiError('csr generation value cannot be empty')

    if csr_generation == user_generated_csr:
        return False
    else:
        return True


def get_bool_value(str_val):
    int_val = int(str_val)
    if int_val == 0:
        return False
    else:
        return True


def get_int_value(bool_val):
    if bool_val:
        return 1
    else:
        return 0


def validate_policy_spec(policy_spec):
    """
    :param PolicySpecification policy_spec:
    :rtype: bool
    """
    if policy_spec.policy:
        validate_policy_subject(policy_spec)
        validate_key_pair(policy_spec)

    validate_default_subject(policy_spec)
    validate_default_key_pair_with_policy_subject(policy_spec)
    validate_default_key_pair(policy_spec)

    d = policy_spec.defaults
    p = policy_spec.policy

    if not d or not p:
        return

    if p.auto_installed is not None:
        if p.auto_installed != d.auto_installed:
            raise VenafiError(no_match_error_msg % ('autoinstalled', d.auto_installed, p.auto_installed))

    return True


def validate_policy_subject(policy_spec):
    """
    :param PolicySpecification policy_spec:
    """
    if not policy_spec.policy.subject:
        raise VenafiError('Subject structure is empty')

    s = policy_spec.policy.subject
    if len(s.orgs) > 1:
        raise VenafiError(too_many_error_msg, 'organizations')
    if len(s.org_units) > 1:
        raise VenafiError(too_many_error_msg, 'organizational units')
    if len(s.localities) > 1:
        raise VenafiError(too_many_error_msg, 'localities')
    if len(s.states) > 1:
        raise VenafiError(too_many_error_msg, 'states')
    if len(s.countries) > 1:
        raise VenafiError(too_many_error_msg, 'countries')


def validate_key_pair(policy_spec):
    """
    :param PolicySpecification policy_spec:
    """
    if not policy_spec.policy.key_pair:
        raise VenafiError('Key Pair structure is empty')

    kp = policy_spec.policy.key_pair

    # validate key algorithm
    if len(kp.key_types) > 1:
        raise VenafiError(too_many_error_msg, 'key types')
    if len(kp.key_types) > 0 and not member_of(kp.key_types, supported_key_types):
        raise VenafiError(unsupported_error_msg % ('key types', pprint(supported_key_types), pprint(kp.key_types)))

    # validate key bit strength
    if len(kp.rsa_key_sizes) > 1:
        raise VenafiError(too_many_error_msg, 'key bit strength')
    if len(kp.rsa_key_sizes) > 0 and not member_of(kp.rsa_key_sizes, supported_rsa_key_sizes):
        raise VenafiError(unsupported_error_msg
                          % ('key bit strength', pprint(supported_rsa_key_sizes), pprint(kp.rsa_key_sizes)))

    # validate elliptic curve
    if len(kp.elliptic_curves) > 1:
        raise VenafiError(too_many_error_msg, 'elliptic curve')
    if len(kp.elliptic_curves) > 0 and not member_of(kp.elliptic_curves, supported_elliptic_curves):
        raise VenafiError(unsupported_error_msg
                          % ('elliptic_curve', pprint(supported_elliptic_curves), pprint(kp.elliptic_curves)))

    # validate generation type
    # if kp.generation_type and kp.generation_type not in ["0", "1"]:
    #     raise VenafiError(unsupported_error_msg % ('generation type', "[\"0\", \"1\"]", kp.generation_type))


def validate_default_subject(policy_spec):
    """
    :param PolicySpecification policy_spec:
    """
    if not policy_spec.defaults or not policy_spec.defaults.subject:
        return

    ds = policy_spec.defaults.subject

    if len(ds.org_units) > 1:
        raise VenafiError(too_many_error_msg, 'org units')

    if not policy_spec.policy or not policy_spec.policy.subject:
        return

    s = policy_spec.policy.subject

    if s.orgs and s.orgs[0] and ds.org:
        if s.orgs[0] != ds.org:
            raise VenafiError(no_match_error_msg % ('organizations', ds.org, s.orgs[0]))

    if s.org_units and s.org_units[0] and len(ds.org_units) > 0 and ds.org_units[0]:
        if s.org_units[0] != ds.org_units[0]:
            raise VenafiError(no_match_error_msg % ('orgUnits', ds.org_units[0], s.org_units[0]))

    if s.localities and s.localities[0] and ds.locality:
        if s.localities[0] != ds.locality:
            raise VenafiError(no_match_error_msg % ('localities', ds.locality, s.localities[0]))

    if s.states and s.states[0] and ds.state:
        if s.states[0] != ds.state:
            raise VenafiError(no_match_error_msg % ('states', ds.state, s.states[0]))

    if s.countries and s.countries and ds.country:
        if s.countries[0] != ds.country:
            raise VenafiError(no_match_error_msg % ('countries', ds.country, s.countries[0]))


def validate_default_key_pair_with_policy_subject(policy_spec):
    """
    :param PolicySpecification policy_spec:
    """
    if not policy_spec.defaults or not policy_spec.defaults.key_pair or not policy_spec.policy \
            or not policy_spec.policy.key_pair:
        return

    kp = policy_spec.policy.key_pair
    dkp = policy_spec.defaults.key_pair

    if kp.key_types and kp.key_types[0] and dkp.key_type:
        if kp.key_types[0] != dkp.key_type:
            raise VenafiError(no_match_error_msg % ('key types', dkp.key_type, kp.key_types[0]))

    if kp.rsa_key_sizes and kp.rsa_key_sizes[0] and dkp.rsa_key_size:
        if kp.rsa_key_sizes[0] != dkp.rsa_key_size:
            raise VenafiError(no_match_error_msg % ('rsa key sizes', dkp.rsa_key_size, kp.rsa_key_sizes[0]))

    if kp.elliptic_curves and kp.elliptic_curves[0] and dkp.elliptic_curve:
        if kp.elliptic_curves[0] != dkp.elliptic_curve:
            raise VenafiError(no_match_error_msg % ('elliptic curves', dkp.elliptic_curve, kp.elliptic_curves[0]))

    if kp.service_generated and dkp.service_generated:
        if kp.service_generated != dkp.service_generated:
            raise VenafiError(no_match_error_msg % ('generation type', dkp.service_generated, kp.service_generated))


def validate_default_key_pair(policy_spec):
    """
    :param PolicySpecification policy_spec:
    """
    if not policy_spec.defaults or not policy_spec.defaults.key_pair:
        return

    dkp = policy_spec.defaults.key_pair

    if dkp.key_type and not member_of([dkp.key_type], supported_key_types):
        raise VenafiError(unsupported_error_msg % ('key type', pprint(supported_key_types), dkp.key_type))

    if dkp.rsa_key_size and not member_of([dkp.rsa_key_size], supported_rsa_key_sizes):
        raise VenafiError(unsupported_error_msg % ('rsa key size', pprint(supported_rsa_key_sizes), dkp.rsa_key_size))

    if dkp.elliptic_curve and not member_of([dkp.elliptic_curve], supported_elliptic_curves):
        raise VenafiError(unsupported_error_msg % ('elliptic curve', pprint(supported_elliptic_curves),
                                                   dkp.elliptic_curve))

    # if dkp.generation_type and dkp.generation_type not in ["0", "1"]:
    #     raise VenafiError(unsupported_error_msg % ('generation type', pprint(["0", "1"]), dkp.generation_type))


def member_of(user_values, supported_values):
    """
    :param list user_values: The values to test membership of
    :param list supported_values: The member values
    :rtype: bool
    """
    return all(x in supported_values for x in user_values)


def get_management_type(autoinstalled):
    """
    :param bool autoinstalled:
    :rtype: str
    """
    if autoinstalled is None:
        return
    elif autoinstalled is True:
        return mt_provisioning
    elif autoinstalled is False:
        return mt_enrollment
