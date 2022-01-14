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
import os
import unittest
from pprint import pformat

from test_env import (TPP_TOKEN_URL, CLOUD_APIKEY, CLOUD_URL, TPP_PM_ROOT, CLOUD_ENTRUST_CA_NAME,CLOUD_DIGICERT_CA_NAME,
                      TPP_CA_NAME, TPP_USER, TPP_PASSWORD)
from test_utils import timestamp
from vcert import TPPTokenConnection, CloudConnection, Authentication, SCOPE_PM, logger
from vcert.parser import json_parser, yaml_parser
from vcert.parser.utils import parse_policy_spec
from vcert.policy import (Policy, Subject, KeyPair, SubjectAltNames, Defaults, DefaultSubject, DefaultKeyPair,
                          PolicySpecification)
from vcert.policy.pm_cloud import CA_TYPE_DIGICERT, CA_TYPE_ENTRUST

POLICY_SPEC_JSON = 'resources/policy_specification.json'
POLICY_SPEC_YAML = 'resources/policy_specification.yaml'
CA_TYPE_TPP = 'TPP'

log = logger.get_child("test-pm")


class TestParsers(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestParsers, self).__init__(*args, **kwargs)
        self.json_file = _resolve_resources_path(POLICY_SPEC_JSON)
        self.yaml_file = _resolve_resources_path(POLICY_SPEC_YAML)

    def test_json_parsing(self):
        # data = json_parser.parse_file(self.json_file)
        # print_data = parse_policy_spec(data)
        # pprint(print_data)
        pass

    def test_json_serialization(self):
        ps = PolicySpecification(policy=_get_policy_obj(), defaults=_get_defaults_obj())
        json_parser.serialize(ps, 'test_json_serialization.json')

    def test_yaml_11_parsing(self):
        pass

    def test_yaml_12_parsing(self):
        # data = yaml_parser.parse_file(self.yaml_file)
        # print_data = parse_policy_spec(data)
        # pprint(print_data)
        pass

    def test_yaml_serialization(self):
        ps = PolicySpecification(policy=_get_policy_obj(), defaults=_get_defaults_obj())
        yaml_parser.serialize(ps, 'test_yaml_serialization.yaml')


class TestTPPPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, http_request_kwargs={'verify': "/tmp/chain.pem"})
        auth = Authentication(user=TPP_USER, password=TPP_PASSWORD, scope=SCOPE_PM)
        self.tpp_conn.get_access_token(auth)
        self.json_file = _resolve_resources_path(POLICY_SPEC_JSON)
        self.yaml_file = _resolve_resources_path(POLICY_SPEC_YAML)
        super(TestTPPPolicyManagement, self).__init__(*args, **kwargs)

    def test_create_policy_from_json(self):
        # ps = json_parser.parse_file(self.json_file)
        # self._create_policy_tpp(policy_spec=ps)
        pass

    def test_create_policy_yaml(self):
        # ps = yaml_parser.parse_file(self.yaml_file)
        # self._create_policy_tpp(policy_spec=ps)
        pass

    def test_create_policy_full(self):
        policy = _get_policy_obj(ca_type=CA_TYPE_TPP)
        policy.key_pair.rsa_key_sizes = [2048]
        self._create_policy_tpp(policy=policy, defaults=_get_defaults_obj())

    def test_create_policy_empty(self):
        self._create_policy_tpp()

    def test_create_policy_no_policy(self):
        self._create_policy_tpp(defaults=_get_defaults_obj())

    def test_create_policy_no_defaults(self):
        policy = _get_policy_obj(ca_type=CA_TYPE_TPP)
        policy.key_pair.rsa_key_sizes = [2048]
        self._create_policy_tpp(policy=policy)

    def _create_policy_tpp(self, policy_spec=None, policy=None, defaults=None):
        zone = f"{TPP_PM_ROOT}\\{_get_tpp_policy_name()}"
        create_policy(self.tpp_conn, zone, policy_spec, policy, defaults)


class TestCloudPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.cloud_conn = CloudConnection(token=CLOUD_APIKEY, url=CLOUD_URL)
        self.json_file = _resolve_resources_path(POLICY_SPEC_JSON)
        self.yaml_file = _resolve_resources_path(POLICY_SPEC_YAML)
        super(TestCloudPolicyManagement, self).__init__(*args, **kwargs)

    def test_create_policy_from_json(self):
        # ps = json_parser.parse_file(self.json_file)
        # self._create_policy_cloud(policy_spec=ps)
        pass

    def test_create_policy_yaml(self):
        # ps = yaml_parser.parse_file(self.yaml_file)
        # self._create_policy_cloud(policy_spec=ps)
        pass

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

    def test_validate_domains(self):
        policy = self._create_policy_cloud(policy=_get_policy_obj())
        self.assertListEqual(policy.policy.domains, POLICY_DOMAINS)

    def _create_policy_cloud(self, policy_spec=None, policy=None, defaults=None):
        zone = self._get_random_zone()
        response = create_policy(self.cloud_conn, zone, policy_spec, policy, defaults)
        return response

    @staticmethod
    def _get_random_zone():
        return _get_zone()


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
    log.debug(f"Created Policy at {zone}")
    log.debug(pformat(data))
    return resp


POLICY_DOMAINS = ['vfidev.com', 'vfidev.net', 'venafi.example']


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
            rsa_key_sizes=[2048, 4096],
            elliptic_curves=['P521'],
            reuse_allowed=False),
        subject_alt_names=SubjectAltNames(
            dns_allowed=True,
            ip_allowed=False,
            email_allowed=False,
            uri_allowed=False,
            upn_allowed=False),
        domains=POLICY_DOMAINS,
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
            rsa_key_size=2048,
            elliptic_curve='P521'),
        auto_installed=False)
    return defaults


def _get_app_name():
    name = 'vcert-python-app-{}'
    return name


def _get_cit_name():
    cit_name = 'vcert-python-cit-{}'
    return cit_name


def _get_zone():
    time = timestamp()
    zone = f"{_get_app_name().format(time)}\\{_get_cit_name().format(time)}"
    return zone


def _get_tpp_policy_name():
    time = timestamp()
    return f"{_get_app_name().format(time)}"


def _resolve_resources_path(path):
    resources_dir = os.path.dirname(__file__)
    log.debug(f"Testing root folder: [{resources_dir}]")
    resolved_path = f"./{path}" if resources_dir.endswith('tests') else f"./tests/{path}"
    log.debug(f"resolved path: [{resolved_path}]")
    return resolved_path
