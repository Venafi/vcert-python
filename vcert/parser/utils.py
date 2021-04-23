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

import logging as log
import os

from vcert.errors import VenafiParsingError
from vcert.parser import *
from vcert.policy.policy_spec import Subject, KeyPair, SubjectAltNames, Policy, DefaultSubject, DefaultKeyPair, \
    Defaults, PolicySpecification


def load_file(file_path):
    """
    :param str file_path: the path of the file to be loaded
    :rtype str:
    """
    if not file_path:
        log.error('file path is empty')
        raise

    path = os.path.abspath(file_path)
    f = open(path, 'r')
    data = f.read()
    f.close()
    return data


def parse_data(data):
    """
    :param dict data: The data to build the PolicySpecification structure
    :rtype PolicySpecification:
    """

    if not data:
        log.error('Data dictionary is empty')
        raise VenafiParsingError

    policy = Policy()
    subject = Subject()
    key_pair = KeyPair()
    subject_alt_names = SubjectAltNames()

    if FIELD_POLICY in data:
        p = data[FIELD_POLICY]
        policy.domains = p[FIELD_DOMAINS] if FIELD_DOMAINS in p else None
        policy.wildcard_allowed = p[FIELD_WILDCARD_ALLOWED] if FIELD_WILDCARD_ALLOWED in p else None
        policy.max_valid_days = p[FIELD_MAX_VALID_DAYS] if FIELD_MAX_VALID_DAYS in p else None
        policy.certificate_authority = p[FIELD_CERTIFICATE_AUTHORITY] if FIELD_CERTIFICATE_AUTHORITY in p else None
        policy.autoinstalled = p[FIELD_AUTOINSTALLED] if FIELD_AUTOINSTALLED in p else None

        if FIELD_SUBJECT in p:
            s = p[FIELD_SUBJECT]
            subject.orgs = s[FIELD_ORGS] if FIELD_ORGS in s else None
            subject.org_units = s[FIELD_ORG_UNITS] if FIELD_ORG_UNITS in s else None
            subject.localities = s[FIELD_LOCALITIES] if FIELD_LOCALITIES in s else None
            subject.states = s[FIELD_STATES] if FIELD_STATES in s else None
            subject.countries = s[FIELD_COUNTRIES] if FIELD_COUNTRIES in s else None

        if FIELD_KEY_PAIR in p:
            kp = p[FIELD_KEY_PAIR]
            key_pair.key_types = kp[FIELD_KEY_TYPES] if FIELD_KEY_TYPES in kp else None
            key_pair.rsa_key_sizes = kp[FIELD_RSA_KEY_SIZES] if FIELD_RSA_KEY_SIZES in kp else None
            key_pair.elliptic_curves = kp[FIELD_ELLIPTIC_CURVES] if FIELD_ELLIPTIC_CURVES in kp else None
            key_pair.service_generated = kp[FIELD_SERVICE_GENERATED] if FIELD_SERVICE_GENERATED in kp else None
            key_pair.reuse_allowed = kp[FIELD_REUSE_ALLOWED] if FIELD_REUSE_ALLOWED in kp else None

        if FIELD_SUBJECT_ALT_NAMES in p:
            sans = p[FIELD_SUBJECT_ALT_NAMES]
            subject_alt_names.dns_allowed = sans[FIELD_DNS_ALLOWED] if FIELD_DNS_ALLOWED in sans else None
            subject_alt_names.email_allowed = sans[FIELD_EMAIL_ALLOWED] if FIELD_EMAIL_ALLOWED in sans else None
            subject_alt_names.ip_allowed = sans[FIELD_IP_ALLOWED] if FIELD_IP_ALLOWED in sans else None
            subject_alt_names.upn_allowed = sans[FIELD_UPN_ALLOWED] if FIELD_UPN_ALLOWED in sans else None
            subject_alt_names.uri_allowed = sans[FIELD_URI_ALLOWED] if FIELD_URI_ALLOWED in sans else None

    policy.subject = subject
    policy.key_pair = key_pair
    policy.subject_alt_names = subject_alt_names

    defaults = Defaults()
    default_subject = DefaultSubject()
    default_key_pair = DefaultKeyPair()

    if FIELD_DEFAULTS in data:
        d = data[FIELD_DEFAULTS]
        defaults.domain = d[FIELD_DEFAULT_DOMAIN] if FIELD_DEFAULT_DOMAIN in d else None
        defaults.autoinstalled = d[FIELD_DEFAULT_AUTOINSTALLED] if FIELD_DEFAULT_AUTOINSTALLED in d else None

        if FIELD_DEFAULT_SUBJECT in d:
            ds = d[FIELD_DEFAULT_SUBJECT]
            default_subject.org = ds[FIELD_DEFAULT_ORG] if FIELD_DEFAULT_ORG in ds else None
            default_subject.org_units = ds[FIELD_DEFAULT_ORG_UNITS] if FIELD_DEFAULT_ORG_UNITS in ds else None
            default_subject.locality = ds[FIELD_DEFAULT_LOCALITY] if FIELD_DEFAULT_LOCALITY in ds else None
            default_subject.state = ds[FIELD_DEFAULT_STATE] if FIELD_DEFAULT_STATE in ds else None
            default_subject.country = ds[FIELD_DEFAULT_COUNTRY] if FIELD_DEFAULT_COUNTRY in ds else None

        if FIELD_DEFAULT_KEY_PAIR in d:
            dkp = d[FIELD_DEFAULT_KEY_PAIR]
            default_key_pair = DefaultKeyPair(dkp[FIELD_DEFAULT_KEY_TYPE],
                                              dkp[FIELD_DEFAULT_RSA_KEY_SIZE],
                                              dkp[FIELD_DEFAULT_ELLIPTIC_CURVE],
                                              dkp[FIELD_DEFAULT_SERVICE_GENERATED])
            default_key_pair.key_type = dkp[FIELD_DEFAULT_KEY_TYPE] if FIELD_DEFAULT_KEY_TYPE in dkp else None
            default_key_pair.rsa_key_size = \
                dkp[FIELD_DEFAULT_RSA_KEY_SIZE] if FIELD_DEFAULT_RSA_KEY_SIZE in dkp else None
            default_key_pair.elliptic_curve = \
                dkp[FIELD_DEFAULT_ELLIPTIC_CURVE] if FIELD_DEFAULT_ELLIPTIC_CURVE in dkp else None
            default_key_pair.service_generated = \
                dkp[FIELD_DEFAULT_SERVICE_GENERATED] if FIELD_DEFAULT_SERVICE_GENERATED in dkp else None

    defaults.subject = default_subject
    defaults.key_pair = default_key_pair

    owners = data[FIELD_OWNERS] if FIELD_OWNERS in data else None
    users = data[FIELD_USERS] if FIELD_USERS in data else None
    user_access = data[FIELD_USER_ACCESS] if FIELD_USER_ACCESS in data else None
    approvers = data[FIELD_APPROVERS] if FIELD_APPROVERS in data else None

    policy_spec = PolicySpecification(owners, users, user_access, approvers, policy, defaults)

    return policy_spec


def parse_policy_spec(policy_spec):
    """
    Returns a dictionary with all the policy specification values. Used for serialization.

    :param PolicySpecification policy_spec:
    :rtype: dict
    """
    subject = policy_spec.policy.subject
    s_data = dict()
    if subject:
        s_data = {
            FIELD_ORGS: subject.orgs,
            FIELD_ORG_UNITS: subject.org_units,
            FIELD_LOCALITIES: subject.localities,
            FIELD_STATES: subject.states,
            FIELD_COUNTRIES: subject.countries
        }
    key_pair = policy_spec.policy.key_pair
    kp_data = dict()
    if key_pair:
        kp_data = {
            FIELD_KEY_TYPES: key_pair.key_types,
            FIELD_RSA_KEY_SIZES: key_pair.rsa_key_sizes,
            FIELD_ELLIPTIC_CURVES: key_pair.elliptic_curves,
            FIELD_SERVICE_GENERATED: key_pair.service_generated,
            FIELD_REUSE_ALLOWED: key_pair.reuse_allowed
        }
    sans = policy_spec.policy.subject_alt_names
    sans_data = dict()
    if sans:
        sans_data = {
            FIELD_DNS_ALLOWED: sans.dns_allowed,
            FIELD_EMAIL_ALLOWED: sans.email_allowed,
            FIELD_IP_ALLOWED: sans.ip_allowed,
            FIELD_UPN_ALLOWED: sans.upn_allowed,
            FIELD_URI_ALLOWED: sans.uri_allowed
        }
    d_subject = policy_spec.defaults.subject
    ds_data = dict()
    if d_subject:
        ds_data = {
            FIELD_DEFAULT_ORG: d_subject.org,
            FIELD_DEFAULT_ORG_UNITS: d_subject.org_units,
            FIELD_DEFAULT_LOCALITY: d_subject.locality,
            FIELD_DEFAULT_STATE: d_subject.state,
            FIELD_DEFAULT_COUNTRY: d_subject.country
        }
    d_key_pair = policy_spec.defaults.key_pair
    dkp_data = dict()
    if d_key_pair:
        dkp_data = {
            FIELD_DEFAULT_KEY_TYPE: d_key_pair.key_type,
            FIELD_DEFAULT_RSA_KEY_SIZE: d_key_pair.rsa_key_size,
            FIELD_DEFAULT_ELLIPTIC_CURVE: d_key_pair.elliptic_curve,
            FIELD_DEFAULT_SERVICE_GENERATED: d_key_pair.service_generated
        }

    data = {
        FIELD_OWNERS: policy_spec.owners,
        FIELD_USERS: policy_spec.users,
        FIELD_USER_ACCESS: policy_spec.user_access,
        FIELD_APPROVERS: policy_spec.approvers,
        FIELD_POLICY: {
            FIELD_DOMAINS: policy_spec.policy.domains,
            FIELD_WILDCARD_ALLOWED: policy_spec.policy.wildcard_allowed,
            FIELD_MAX_VALID_DAYS: policy_spec.policy.max_valid_days,
            FIELD_CERTIFICATE_AUTHORITY: policy_spec.policy.certificate_authority,
            FIELD_SUBJECT: s_data,
            FIELD_KEY_PAIR: kp_data,
            FIELD_SUBJECT_ALT_NAMES: sans_data
        },
        FIELD_DEFAULTS: {
            FIELD_DEFAULT_DOMAIN: policy_spec.defaults.domain,
            FIELD_DEFAULT_SUBJECT: ds_data,
            FIELD_DEFAULT_KEY_PAIR: dkp_data
        }
    }
    new_data = delete_empty_values(data)
    return new_data


def delete_empty_values(data):
    """
    Deletes entries whose value is None/empty or equivalent

    :param dict data:
    :rtype: dict
    """
    for k, v in data.items():
        if v is None:
            del data[k]
        elif (isinstance(v, dict) or isinstance(v, list)) and len(v) == 0:
            del data[k]
        elif isinstance(v, dict):
            delete_empty_values(v)
    return data
