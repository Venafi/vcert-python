#!/usr/bin/env python3
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
import unittest
from os import environ
from pprint import pprint

from common import TPP_TOKEN_URL, USER, PASSWORD, TOKEN, CLOUDURL, TPP_ACCESS_TOKEN
from vcert import TPPTokenConnection, CloudConnection
from vcert.parser import json_parser, yaml_parser
from vcert.parser.utils import parse_policy_spec
from vcert.policy.policy_spec import Policy, Subject, KeyPair, SubjectAltNames, Defaults, DefaultSubject, \
    DefaultKeyPair, PolicySpecification

POLICY_SPEC_JSON = './resources/policy_specification.json'
POLICY_SPEC_YAML = './resources/policy_specification.yaml'


class TestParsers(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, user=USER, password=PASSWORD,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestParsers, self).__init__(*args, **kwargs)

    def test_json_parsing(self):
        data = json_parser.parse_file(POLICY_SPEC_JSON)
        pprint(data.__dict__)

    def test_yaml_11_parsing(self):
        pass

    def test_yaml_12_parsing(self):
        data = yaml_parser.parse_file(POLICY_SPEC_YAML)
        pprint(data.__dict__)

    def test_yaml_serialization(self):
        ps = PolicySpecification(policy=_get_policy_obj(set_tpp_ca=True), defaults=_get_defaults_obj())
        yaml_parser.serialize(ps, 'test_serialize.yaml')


class TestTPPTokenPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, access_token=TPP_ACCESS_TOKEN,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestTPPTokenPolicyManagement, self).__init__(*args, **kwargs)

    def test_read_policy(self):
        ps = self.tpp_conn.get_policy(self.tpp_zone)
        data = parse_policy_spec(ps)
        pprint(data)

    def test_create_policy_from_json(self):
        ps = json_parser.parse_file(POLICY_SPEC_JSON)
        self._create_policy_tpp(policy_spec=ps)

    def test_create_policy_yaml(self):
        ps = yaml_parser.parse_file(POLICY_SPEC_YAML)
        self._create_policy_tpp(policy_spec=ps)

    def test_create_policy_full(self):
        self._create_policy_tpp(policy=_get_policy_obj(set_tpp_ca=True), defaults=_get_defaults_obj())

    def test_create_policy_empty(self):
        self._create_policy_tpp()

    def test_create_policy_no_policy(self):
        self._create_policy_tpp(defaults=_get_defaults_obj())

    def test_create_policy_no_defaults(self):
        self._create_policy_tpp(policy=_get_policy_obj(set_tpp_ca=True))

    def _create_policy_tpp(self, policy_spec=None, policy=None, defaults=None):
        create_policy(self.tpp_conn, self.tpp_zone, policy_spec, policy, defaults)


class TestCloudPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.cloud_zone = environ['CLOUD_ZONE']
        self.cloud_conn = CloudConnection(token=TOKEN, url=CLOUDURL)
        super(TestCloudPolicyManagement, self).__init__(*args, **kwargs)

    def test_read_policy(self):
        ps = self.cloud_conn.get_policy("vcert-amoo-0004\\vcert-policy-creator-31")
        json_parser.serialize(ps, "test_cloud_pm.json")

    def test_create_policy_from_json(self):
        ps = json_parser.parse_file(POLICY_SPEC_JSON)
        self._create_policy_cloud(policy_spec=ps)

    def test_create_policy_yaml(self):
        ps = yaml_parser.parse_file(POLICY_SPEC_YAML)
        self._create_policy_cloud(policy_spec=ps)

    def test_create_policy_full(self):
        self._create_policy_cloud(policy=_get_policy_obj(), defaults=_get_defaults_obj())

    def test_create_policy_empty(self):
        self._create_policy_cloud()

    def test_create_policy_no_policy(self):
        self._create_policy_cloud(defaults=_get_defaults_obj())

    def test_create_policy_no_defaults(self):
        self._create_policy_cloud(policy=_get_policy_obj())

    def _create_policy_cloud(self, policy_spec=None, policy=None, defaults=None):
        create_policy(self.cloud_conn, self.cloud_zone, policy_spec, policy, defaults)


def create_policy(connector, zone, policy_spec=None, policy=None, defaults=None):
    if not policy_spec:
        policy_spec = PolicySpecification()
    if policy:
        policy_spec.policy = policy
    if defaults:
        policy_spec.defaults = defaults

    connector.set_policy(zone, policy_spec)
    resp = connector.get_policy(zone)
    data = parse_policy_spec(resp)
    pprint(data)
    return resp


DEFAULT_CA_TPP = '\\VED\\Policy\\Certificate Authorities\\Microsoft CA\\QA Venafi CA - Server 2 Years'


def _get_policy_obj(set_tpp_ca=False):
    policy = Policy(
        subject=Subject(
            orgs=['Treat or Trick, Inc.'],
            org_units=['Customer Support', 'Professional Services'],
            localities=['Richland'],
            states=['Washington'],
            countries=['US']),
        key_pair=KeyPair(
            key_types=['RSA'],
            rsa_key_sizes=[4096],
            elliptic_curves=['P521'],
            reuse_allowed=True),
        subject_alt_names=SubjectAltNames(
            dns_allowed=True,
            ip_allowed=False,
            email_allowed=False,
            uri_allowed=False,
            upn_allowed=False),
        cert_auth=DEFAULT_CA_TPP if set_tpp_ca else None,
        domains=['treatortrick.com', 'ryantreat.com', 'supertreat.xyz'],
        wildcard_allowed=True,
        auto_installed=False)

    return policy


def _get_defaults_obj():
    defaults = Defaults(
        d_subject=DefaultSubject(
            org='Treat or Trick, Inc.',
            org_units=['Customer Support', 'Professional Services'],
            locality='Richland',
            state='Washington',
            country='US'),
        d_key_pair=DefaultKeyPair(
            key_type='RSA',
            rsa_key_size=4096,
            elliptic_curve='P521'),
        auto_installed=False)
    return defaults
