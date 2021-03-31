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


class PolicySpecification:
    def __init__(self, owners, users, user_access, approvers, policy, defaults):
        """
        :param list[str] owners:
        :param list[str] users:
        :param str user_access:
        :param list[str] approvers:
        :param Policy policy:
        :param Defaults defaults:
        """
        self.owners = owners
        self.users = users
        self.user_access = user_access
        self.approvers = approvers
        self.policy = policy
        self.defaults = defaults


class Policy:
    def __init__(self, domains, wildcard_allowed, max_valid_days, ca, subject, key_pair, subject_alt_names):
        """
        :param list[str] domains:
        :param bool wildcard_allowed:
        :param int max_valid_days:
        :param str ca:
        :param Subject subject:
        :param KeyPair key_pair:
        :param SubjectAltNames subject_alt_names:
        """
        self.domains = domains
        self.wildcard_allowed = wildcard_allowed
        self.max_valid_days = max_valid_days
        self.ca = ca
        self.subject = subject
        self.key_pair = key_pair
        self.subject_alt_names = subject_alt_names


class Subject:
    def __init__(self, orgs, org_units, localities, states, countries):
        """
        :param list[str] orgs:
        :param list[str] org_units:
        :param list[str] localities:
        :param list[str] states:
        :param list[str] countries:
        """
        self.orgs = orgs
        self.org_units = org_units
        self.localities = localities
        self.states = states
        self.countries = countries


class KeyPair:
    def __init__(self, key_types, rsa_key_sizes, elliptic_curves, generation_type, reuse_allowed):
        """
        :param list[str] key_types:
        :param list[int] rsa_key_sizes:
        :param list[str] elliptic_curves:
        :param str generation_type:
        :param bool reuse_allowed:
        """
        self.key_types = key_types
        self.rsa_key_sizes = rsa_key_sizes
        self.elliptic_curves = elliptic_curves
        self.generation_type = generation_type
        self.reuse_allowed = reuse_allowed


class SubjectAltNames:
    def __init__(self, dns_allowed, ip_allowed, email_allowed, uri_allowed, upn_allowed):
        """
        :param bool dns_allowed:
        :param bool ip_allowed:
        :param bool email_allowed:
        :param bool uri_allowed:
        :param bool upn_allowed:
        """
        self.dns_allowed = dns_allowed
        self.ip_allowed = ip_allowed
        self.email_allowed = email_allowed
        self.uri_allowed = uri_allowed
        self.upn_allowed = upn_allowed


class Defaults:
    def __init__(self, d_domain, d_subject, d_key_pair):
        """
        :param str d_domain:
        :param DefaultSubject d_subject:
        :param DefaultKeyPair d_key_pair:
        """
        self.domain = d_domain
        self.subject = d_subject
        self.key_pair = d_key_pair


class DefaultSubject:
    def __init__(self, org, org_units, locality, state, country):
        """
        :param str org:
        :param list[str] org_units:
        :param str locality:
        :param str state:
        :param str country:
        """
        self.org = org
        self.org_units = org_units
        self.locality = locality
        self.state = state
        self.country = country


class DefaultKeyPair:
    def __init__(self, key_type, rsa_key_size, elliptic_curve, generation_type):
        """
        :param str key_type:
        :param int rsa_key_size:
        :param str elliptic_curve:
        :param str generation_type:
        """
        self.key_type = ""
        self.rsa_key_size = ""
        self.elliptic_curve = ""
        self.generation_type = ""
