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

    if not data[FIELD_POLICY]:
        log.error('Data structure does not have a %s field' % FIELD_POLICY)
        raise VenafiParsingError

    p = data[FIELD_POLICY]

    s = p[FIELD_SUBJECT]
    if not s:
        log.error("Policy structure does not have a %s field" % FIELD_SUBJECT)
        raise VenafiParsingError

    subject = Subject(s[FIELD_ORGS], s[FIELD_ORG_UNITS], s[FIELD_LOCALITIES],
                      s[FIELD_STATES], s[FIELD_COUNTRIES])

    kp = p[FIELD_KEY_PAIR]
    if not kp:
        log.error("Policy structure does not have a %s field" % FIELD_KEY_PAIR)
        raise VenafiParsingError

    key_pair = KeyPair(kp[FIELD_KEY_TYPES], kp[FIELD_RSA_KEY_SIZES],
                       kp[FIELD_ELLIPTIC_CURVES], kp[FIELD_SERVICE_GENERATED],
                       kp[FIELD_REUSE_ALLOWED])

    sans = p[FIELD_SUBJECT_ALT_NAMES]
    if not sans:
        log.error("Policy structure does not have a %s field" % FIELD_SUBJECT_ALT_NAMES)
        raise VenafiParsingError

    subject_alt_names = SubjectAltNames(sans[FIELD_DNS_ALLOWED], sans[FIELD_IP_ALLOWED],
                                        sans[FIELD_EMAIL_ALLOWED], sans[FIELD_URI_ALLOWED],
                                        sans[FIELD_UPN_ALLOWED])

    policy = Policy(p[FIELD_DOMAINS], p[FIELD_WILDCARD_ALLOWED], p[FIELD_MAX_VALID_DAYS],
                    p[FIELD_CERTIFICATE_AUTHORITY], subject, key_pair, subject_alt_names)

    if data[FIELD_DEFAULTS]:
        defaults_data = data[FIELD_DEFAULTS]
        domain = defaults_data[FIELD_DEFAULT_DOMAIN]

        ds = defaults_data[FIELD_DEFAULT_SUBJECT]
        if ds:
            default_subject = DefaultSubject(ds[FIELD_DEFAULT_ORG],
                                             ds[FIELD_DEFAULT_ORG_UNITS],
                                             ds[FIELD_DEFAULT_LOCALITY],
                                             ds[FIELD_DEFAULT_STATE],
                                             ds[FIELD_DEFAULT_COUNTRY])
        dkp = defaults_data[FIELD_DEFAULT_KEY_PAIR]
        if dkp:
            default_key_pair = DefaultKeyPair(dkp[FIELD_DEFAULT_KEY_TYPE],
                                              dkp[FIELD_DEFAULT_RSA_KEY_SIZE],
                                              dkp[FIELD_DEFAULT_ELLIPTIC_CURVE],
                                              dkp[FIELD_DEFAULT_SERVICE_GENERATED])
        defaults = Defaults(domain, default_subject, default_key_pair)

    owners = data[FIELD_OWNERS]
    users = data[FIELD_USERS]
    user_access = data[FIELD_USER_ACCESS]
    approvers = data[FIELD_APPROVERS]

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
            FIELD_ORGS: subject.organizations,
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
            FIELD_DEFAULT_ORG: d_subject.organization,
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
