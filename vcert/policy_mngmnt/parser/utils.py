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
from vcert.policy_mngmnt.parser import *
from vcert.policy_mngmnt.policy_spec import Subject, KeyPair, SubjectAltNames, Policy, DefaultSubject, DefaultKeyPair, \
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

    policy_data = data[FIELD_POLICY]

    subject_data = policy_data[FIELD_SUBJECT]
    if not subject_data:
        log.error("Policy structure does not have a %s field" % FIELD_SUBJECT)
        raise VenafiParsingError

    subject = Subject(subject_data[FIELD_ORGS], subject_data[FIELD_ORG_UNITS], subject_data[FIELD_LOCALITIES],
                      subject_data[FIELD_STATES], subject_data[FIELD_COUNTRIES])

    key_pair_data = policy_data[FIELD_KEY_PAIR]
    if not key_pair_data:
        log.error("Policy structure does not have a %s field" % FIELD_KEY_PAIR)
        raise VenafiParsingError

    key_pair = KeyPair(key_pair_data[FIELD_KEY_TYPES], key_pair_data[FIELD_RSA_KEY_SIZES],
                       key_pair_data[FIELD_ELLIPTIC_CURVES], key_pair_data[FIELD_GENERATION_TYPE],
                       key_pair_data[FIELD_REUSE_ALLOWED])

    san_data = policy_data[FIELD_SUBJECT_ALT_NAMES]
    if not san_data:
        log.error("Policy structure does not have a %s field" % FIELD_SUBJECT_ALT_NAMES)
        raise VenafiParsingError

    subject_alt_names = SubjectAltNames(san_data[FIELD_DNS_ALLOWED], san_data[FIELD_IP_ALLOWED],
                                        san_data[FIELD_EMAIL_ALLOWED], san_data[FIELD_URI_ALLOWED],
                                        san_data[FIELD_UPN_ALLOWED])

    policy = Policy(policy_data[FIELD_DOMAINS], policy_data[FIELD_WILDCARD_ALLOWED], policy_data[FIELD_MAX_VALID_DAYS],
                    policy_data[FIELD_CERTIFICATE_AUTHORITY], subject, key_pair, subject_alt_names)

    if data[FIELD_DEFAULTS]:
        defaults_data = data[FIELD_DEFAULTS]
        domain = defaults_data[FIELD_DEFAULT_DOMAIN]

        default_subject_data = defaults_data[FIELD_DEFAULT_SUBJECT]
        if default_subject_data:
            default_subject = DefaultSubject(default_subject_data[FIELD_DEFAULT_ORG],
                                             default_subject_data[FIELD_DEFAULT_ORG_UNIT],
                                             default_subject_data[FIELD_DEFAULT_LOCALITY],
                                             default_subject_data[FIELD_DEFAULT_STATE],
                                             default_subject_data[FIELD_DEFAULT_COUNTRY])
        default_key_pair_data = defaults_data[FIELD_DEFAULT_KEY_PAIR]
        if default_key_pair_data:
            default_key_pair = DefaultKeyPair(default_key_pair_data[FIELD_DEFAULT_KEY_TYPE],
                                              default_key_pair_data[FIELD_DEFAULT_RSA_KEY_SIZE],
                                              default_key_pair_data[FIELD_DEFAULT_ELLIPTIC_CURVE],
                                              default_key_pair_data[FIELD_DEFAULT_GENERATION_TYPE])
        defaults = Defaults(domain, default_subject, default_key_pair)

    owners = data[FIELD_OWNERS]
    users = data[FIELD_USERS]
    user_access = data[FIELD_USER_ACCESS]
    approvers = data[FIELD_APPROVERS]

    policy_spec = PolicySpecification(owners, users, user_access, approvers, policy, defaults)

    return policy_spec
