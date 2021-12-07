#!/usr/bin/env python3
#
# Copyright 2022 Venafi, Inc.
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

import io
import re
import zipfile

from nacl.public import PublicKey
from nacl.encoding import Base64Encoder

from .common import CHAIN_OPTION_FIRST, CHAIN_OPTION_LAST


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


class EdgeEncryptionKey:
    def __init__(self, data):
        """

        :param dict data:
        """
        self.public_key = PublicKey(data['key'], encoder=Base64Encoder) if 'key' in data else None  # type:PublicKey


def zip_to_pem(data, chain_option):
    """

    :param data:
    :param str chain_option:
    :rtype: tuple[str, list, str]
    """
    zip_data = zipfile.ZipFile(io.BytesIO(data))
    private_key = None
    chain = []
    certificate = None
    for info in zip_data.infolist():
        if info.filename.endswith('.key'):
            f = zip_data.open(info)
            private_key = f.read().decode("utf-8").strip()
            f.close()
        elif info.filename.endswith('_root-first.pem'):
            f = zip_data.open(info)
            certs = f.read().decode("utf-8").strip().split('\n\n')
            f.close()
            for i in range(len(certs)):
                if i < len(certs) - 1:
                    if chain_option == CHAIN_OPTION_FIRST:
                        chain.append(certs[i])
                    elif chain_option == CHAIN_OPTION_LAST:
                        chain.insert(0, certs[i])
                    else:
                        continue
                else:
                    certificate = certs[i]
    return certificate, chain, private_key


def value_matches_regex(value, pattern_list):
    """

    :param str value:
    :param list[str] pattern_list:
    :rtype: bool
    """
    return any((re.match(pattern, value) is not None) for pattern in pattern_list)
