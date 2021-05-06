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
from pprint import pprint

from future.backports.datetime import datetime

from test_env import TPP_TOKEN_URL, CLOUD_APIKEY, CLOUD_URL, TPP_ACCESS_TOKEN, TPP_PM_ROOT, \
    CLOUD_ENTRUST_CA_NAME, \
    CLOUD_DIGICERT_CA_NAME, TPP_CA_NAME
from vcert import TPPTokenConnection, CloudConnection
from vcert.parser import json_parser, yaml_parser
from vcert.parser.utils import parse_policy_spec
from vcert.policy.pm_cloud import CA_TYPE_DIGICERT, CA_TYPE_ENTRUST
from vcert.policy.policy_spec import Policy, Subject, KeyPair, SubjectAltNames, Defaults, DefaultSubject, \
    DefaultKeyPair, PolicySpecification

POLICY_SPEC_JSON = './resources/policy_specification.json'
POLICY_SPEC_YAML = './resources/policy_specification.yaml'
CA_TYPE_TPP = 'TPP'


class TestParsers(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestParsers, self).__init__(*args, **kwargs)

    def test_json_parsing(self):
        data = json_parser.parse_file(POLICY_SPEC_JSON)
        pprint(data.__dict__)

    def test_json_serialization(self):
        ps = PolicySpecification(policy=_get_policy_obj(), defaults=_get_defaults_obj())
        json_parser.serialize(ps, 'test_json_serialization.json')

    def test_yaml_11_parsing(self):
        pass

    def test_yaml_12_parsing(self):
        data = yaml_parser.parse_file(POLICY_SPEC_YAML)
        pprint(data.__dict__)

    def test_yaml_serialization(self):
        ps = PolicySpecification(policy=_get_policy_obj(), defaults=_get_defaults_obj())
        yaml_parser.serialize(ps, 'test_yaml_serialization.yaml')


class TestTPPPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, access_token=TPP_ACCESS_TOKEN,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestTPPPolicyManagement, self).__init__(*args, **kwargs)

    def test_create_policy_from_json(self):
        ps = json_parser.parse_file(POLICY_SPEC_JSON)
        self._create_policy_tpp(policy_spec=ps)

    def test_create_policy_yaml(self):
        ps = yaml_parser.parse_file(POLICY_SPEC_YAML)
        self._create_policy_tpp(policy_spec=ps)

    def test_create_policy_full(self):
        self._create_policy_tpp(policy=_get_policy_obj(ca_type=CA_TYPE_TPP), defaults=_get_defaults_obj())

    def test_create_policy_empty(self):
        self._create_policy_tpp()

    def test_create_policy_no_policy(self):
        self._create_policy_tpp(defaults=_get_defaults_obj())

    def test_create_policy_no_defaults(self):
        self._create_policy_tpp(policy=_get_policy_obj(ca_type=CA_TYPE_TPP))

    def _create_policy_tpp(self, policy_spec=None, policy=None, defaults=None):
        zone = '%s\\%s' % (TPP_PM_ROOT, _get_tpp_policy_name())
        create_policy(self.tpp_conn, zone, policy_spec, policy, defaults)


class TestCloudPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.cloud_conn = CloudConnection(token=CLOUD_APIKEY, url=CLOUD_URL)
        super(TestCloudPolicyManagement, self).__init__(*args, **kwargs)

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

    def test_create_policy_entrust(self):
        self._create_policy_cloud(policy=_get_policy_obj(ca_type=CA_TYPE_ENTRUST), defaults=_get_defaults_obj())

    def test_create_policy_digicert(self):
        self._create_policy_cloud(policy=_get_policy_obj(ca_type=CA_TYPE_DIGICERT), defaults=_get_defaults_obj())

    def _create_policy_cloud(self, policy_spec=None, policy=None, defaults=None):
        zone = self._get_random_zone()
        create_policy(self.cloud_conn, zone, policy_spec, policy, defaults)

    @staticmethod
    def _get_random_zone():
        return _get_app_name() + '\\' + _get_cit_name()


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


def _get_policy_obj(ca_type=None):
    policy = Policy(
        subject=Subject(
            orgs=['OSS Venafi, Inc.'],
            org_units=['Customer Support', 'Professional Services'],
            localities=['Salt Lake City'],
            states=['Utah'],
            countries=['US']),
        key_pair=KeyPair(
            key_types=['RSA'],
            rsa_key_sizes=[4096],
            elliptic_curves=['P521'],
            reuse_allowed=False),
        subject_alt_names=SubjectAltNames(
            dns_allowed=True,
            ip_allowed=False,
            email_allowed=False,
            uri_allowed=False,
            upn_allowed=False),
        domains=['vfidev.com', 'vfidev.net', 'venafi.example'],
        wildcard_allowed=True,
        auto_installed=False)

    ca_str = None
    if ca_type:
        if ca_type == CA_TYPE_TPP:
            ca_str = TPP_CA_NAME
        elif ca_type == CA_TYPE_DIGICERT:
            ca_str = CLOUD_DIGICERT_CA_NAME
        elif ca_type == CA_TYPE_ENTRUST:
            ca_str = CLOUD_ENTRUST_CA_NAME
    if ca_str:
        policy.certificate_authority = ca_str

    return policy


def _get_defaults_obj():
    defaults = Defaults(
        d_subject=DefaultSubject(
            org='OSS Venafi, Inc.',
            org_units=['Customer Support', 'Professional Services'],
            locality='Salt Lake City',
            state='Utah',
            country='US'),
        d_key_pair=DefaultKeyPair(
            key_type='RSA',
            rsa_key_size=4096,
            elliptic_curve='P521'),
        auto_installed=False)
    return defaults


def _get_timestamp():
    return datetime.today().strftime('%Y.%m.%d-%Hh%Mm%Ss')


def _get_app_name():
    name = 'vcert-python-%s' % _get_timestamp()
    return name


def _get_cit_name():
    cit_name = 'vcert-python-cit-%s' % _get_timestamp()
    return cit_name


def _get_tpp_policy_name():
    return _get_app_name()
