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
from pprint import pformat

from test_env import (TPP_TOKEN_URL, CLOUD_APIKEY, CLOUD_URL, TPP_PM_ROOT, CLOUD_ENTRUST_CA_NAME,
                      CLOUD_DIGICERT_CA_NAME, TPP_CA_NAME, TPP_USER, TPP_PASSWORD)
from test_utils import get_tpp_policy_name, get_vaas_zone
from vcert import TPPTokenConnection, CloudConnection, Authentication, SCOPE_PM, logger, VenafiError, KeyType
from vcert.parser import json_parser, yaml_parser
from vcert.parser.utils import parse_policy_spec
from vcert.policy import (Policy, Subject, KeyPair, SubjectAltNames, Defaults, DefaultSubject, DefaultKeyPair,
                          PolicySpecification)
from vcert.policy.pm_cloud import (CA_TYPE_DIGICERT, CA_TYPE_ENTRUST, validate_policy_spec as validate_ps_vaas,
                                   get_ca_info, default_error_msg)
from vcert.policy.pm_tpp import (is_service_generated_csr, validate_policy_spec as validate_ps_tpp, no_match_error_msg,
                                 too_many_error_msg, unsupported_error_msg, supported_key_types,
                                 supported_rsa_key_sizes, supported_elliptic_curves)

# This values are loaded from the project root which is vcert-python, not tests folder
POLICY_SPEC_JSON = './tests/resources/policy_specification.json'
POLICY_SPEC_YAML = './tests/resources/policy_specification.yaml'
CA_TYPE_TPP = 'TPP'

log = logger.get_child("test-pm")


class TestParsers(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestParsers, self).__init__(*args, **kwargs)
        self.json_file = POLICY_SPEC_JSON
        self.yaml_file = POLICY_SPEC_YAML

    def test_json_parsing(self):
        ps = json_parser.parse_file(self.json_file)
        self._assert_policy_spec(ps)

    def test_json_serialization(self):
        ps = PolicySpecification(policy=get_policy_obj(), defaults=get_defaults_obj())
        json_parser.serialize(ps, 'test_json_serialization.json')

    def test_yaml_11_parsing(self):
        pass

    def test_yaml_12_parsing(self):
        ps = yaml_parser.parse_file(self.yaml_file)
        self._assert_policy_spec(ps)

    def test_yaml_serialization(self):
        ps = PolicySpecification(policy=get_policy_obj(), defaults=get_defaults_obj())
        yaml_parser.serialize(ps, 'test_yaml_serialization.yaml')

    def _assert_policy_spec(self, ps):
        """

        :param vcert.policy.PolicySpecification ps:
        :return:
        """
        self.assertIsNotNone(ps)
        self.assertIn("venafi.com", ps.policy.domains)
        self.assertIn("kwan.com", ps.policy.domains)
        self.assertIn("venafi.com", ps.policy.subject.orgs)
        self.assertTrue(len(ps.policy.subject.orgs) == 1)
        self.assertIn("DevOps", ps.policy.subject.org_units)
        self.assertTrue(len(ps.policy.subject.org_units) == 1)
        self.assertIn("Merida", ps.policy.subject.localities)
        self.assertTrue(len(ps.policy.subject.localities) == 1)
        self.assertIn("RSA", ps.policy.key_pair.key_types)
        self.assertTrue(len(ps.policy.key_pair.key_types) == 1)
        self.assertIn(2048, ps.policy.key_pair.rsa_key_sizes)
        self.assertTrue(len(ps.policy.key_pair.rsa_key_sizes) == 1)


class TestTPPPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, http_request_kwargs={'verify': "/tmp/chain.pem"})
        auth = Authentication(user=TPP_USER, password=TPP_PASSWORD, scope=SCOPE_PM)
        self.tpp_conn.get_access_token(auth)
        self.json_file = POLICY_SPEC_JSON
        self.yaml_file = POLICY_SPEC_YAML
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
        policy = get_policy_obj(ca_type=CA_TYPE_TPP)
        policy.key_pair.rsa_key_sizes = [2048]
        self._create_policy_tpp(policy=policy, defaults=get_defaults_obj())

    def test_create_policy_empty(self):
        self._create_policy_tpp()

    def test_create_policy_no_policy(self):
        self._create_policy_tpp(defaults=get_defaults_obj())

    def test_create_policy_no_defaults(self):
        policy = get_policy_obj(ca_type=CA_TYPE_TPP)
        policy.key_pair.rsa_key_sizes = [2048]
        self._create_policy_tpp(policy=policy)

    def _create_policy_tpp(self, policy_spec=None, policy=None, defaults=None):
        zone = f"{TPP_PM_ROOT}\\{get_tpp_policy_name()}"
        create_policy(self.tpp_conn, zone, policy_spec, policy, defaults)


class TestCloudPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.cloud_conn = CloudConnection(token=CLOUD_APIKEY, url=CLOUD_URL)
        self.json_file = POLICY_SPEC_JSON
        self.yaml_file = POLICY_SPEC_YAML
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
        self._create_policy_cloud(policy=get_policy_obj(), defaults=get_defaults_obj())

    def test_create_policy_empty(self):
        self._create_policy_cloud()

    def test_create_policy_no_policy(self):
        self._create_policy_cloud(defaults=get_defaults_obj())

    def test_create_policy_no_defaults(self):
        self._create_policy_cloud(policy=get_policy_obj())

    def test_create_policy_entrust(self):
        self._create_policy_cloud(policy=get_policy_obj(ca_type=CA_TYPE_ENTRUST), defaults=get_defaults_obj())

    def test_create_policy_digicert(self):
        self._create_policy_cloud(policy=get_policy_obj(ca_type=CA_TYPE_DIGICERT), defaults=get_defaults_obj())

    def test_validate_domains(self):
        policy = self._create_policy_cloud(policy=get_policy_obj())
        self.assertListEqual(policy.policy.domains, POLICY_DOMAINS)

    def test_csr_attributes_service(self):
        cit = self._create_csr_attributes_policy(service_generated_csr=True)

        self.assertFalse(cit.csr_upload_allowed, "csrUploadAllowed attribute is not False")
        self.assertTrue(cit.key_generated_by_venafi_allowed, "keyGeneratedByVenafiAllowed is not True")

    def test_csr_attributes_local(self):
        cit = self._create_csr_attributes_policy(service_generated_csr=False)

        self.assertTrue(cit.csr_upload_allowed, "csrUploadAllowed attribute is not True")
        self.assertFalse(cit.key_generated_by_venafi_allowed, "keyGeneratedByVenafiAllowed is not False")

    def test_csr_attributes_not_specified(self):
        cit = self._create_csr_attributes_policy()

        self.assertTrue(cit.csr_upload_allowed, "csrUploadAllowed attribute is not True")
        self.assertTrue(cit.key_generated_by_venafi_allowed, "keyGeneratedByVenafiAllowed is not True")

    def test_ec_key_pair(self):
        policy = get_policy_obj()
        kp = KeyPair(
            key_types=['EC'],
            rsa_key_sizes=[2048, 4096],
            elliptic_curves=['P521', 'P384'],
            reuse_allowed=False)
        policy.key_pair = kp

        defaults = get_defaults_obj()
        defaults.key_pair = DefaultKeyPair(
            key_type='EC',
            rsa_key_size=2048,
            elliptic_curve='P521')

        ps = self._create_policy_cloud(policy=policy, defaults=defaults)
        self.assertEqual(ps.policy.key_pair.key_types[0].upper(), KeyType.ECDSA.upper(), "Policy Key Type is not EC")
        self.assertTrue(len(ps.policy.key_pair.elliptic_curves) == 2,
                        f"Expected 2 accepted Elliptic Curves. Got {len(ps.policy.key_pair.elliptic_curves)}")
        self.assertIn('P521', ['P521', 'P384'], "[P521] is not in the allowed Elliptic Curves list")
        self.assertIn('P384', ['P521', 'P384'], "[P384] is not in the allowed Elliptic Curves list")

    def _create_policy_cloud(self, policy_spec=None, policy=None, defaults=None):
        zone = get_vaas_zone()
        response = create_policy(self.cloud_conn, zone, policy_spec, policy, defaults)
        return response

    def _create_csr_attributes_policy(self, service_generated_csr=None):
        """

        :param bool service_generated_csr:
        :rtype: common.Policy
        """
        policy = get_policy_obj()
        policy.key_pair.service_generated = service_generated_csr
        zone = get_vaas_zone()
        create_policy(connector=self.cloud_conn, zone=zone, policy_spec=None, policy=policy)
        cit = self.cloud_conn._get_template_by_id(zone)

        return cit


class TestLocalMethods(unittest.TestCase):
    def test_exceptions_tpp(self):
        try:
            is_service_generated_csr("")
        except VenafiError as err:
            self.assertEqual(err.args[0], "csr generation value cannot be empty")

        ps = PolicySpecification(policy=Policy(), defaults=Defaults())
        ps.policy.auto_installed = True
        ps.defaults.auto_installed = False

        # Testing Subject structure
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], "Subject structure is empty")

        s = Subject(orgs=["foo", "bar"],
                    org_units=["QA Venafi"],
                    localities=["foo", "bar"],
                    states=["foo", "bar"],
                    countries=["foo", "bar"])
        ps.policy.subject = s

        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], too_many_error_msg.format('organizations'))
        ps.policy.subject.orgs = ["Venafi"]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], too_many_error_msg.format('localities'))
        ps.policy.subject.localities = ["Salt Lake City"]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], too_many_error_msg.format('states'))
        ps.policy.subject.states = ["Utah"]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], too_many_error_msg.format('countries'))
        ps.policy.subject.countries = ["USA"]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], "country code [USA] does not match ISO Alpha-2 specification")
        ps.policy.subject.countries = ["US"]

        # Testing KeyPair object
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], "Key Pair structure is empty")

        kp = KeyPair(key_types=["foo", "bar"],
                     rsa_key_sizes=[123, 456],
                     elliptic_curves=["foo", "bar"],
                     service_generated=False)
        ps.policy.key_pair = kp

        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], too_many_error_msg.format('key types'))
        ps.policy.key_pair.key_types = ["foo"]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = unsupported_error_msg.format('key types', supported_key_types, kp.key_types)
            self.assertEqual(err.args[0], msg)
        ps.policy.key_pair.key_types = ["RSA"]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], too_many_error_msg.format('key bit strength'))
        ps.policy.key_pair.rsa_key_sizes = [256]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = unsupported_error_msg.format('key bit strength', supported_rsa_key_sizes, kp.rsa_key_sizes)
            self.assertEqual(err.args[0], msg)
        ps.policy.key_pair.rsa_key_sizes = [4096]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], too_many_error_msg.format('elliptic curve'))
        ps.policy.key_pair.elliptic_curves = ["foo"]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = unsupported_error_msg.format('elliptic curve', supported_elliptic_curves, kp.elliptic_curves)
            self.assertEqual(err.args[0], msg)
        ps.policy.key_pair.elliptic_curves = ["P521"]

        # Testing DefaultSubject structure
        ds = DefaultSubject(org="Foo",
                            org_units=["foo", "bar"],
                            locality="foo",
                            state="foo",
                            country="foo")
        ps.defaults.subject = ds

        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('organizations', ds.org, s.orgs[0])
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.org = s.orgs[0]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('orgUnits', ds.org_units[0], s.org_units[0])
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.org_units = s.org_units
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('localities', ds.locality, s.localities[0])
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.locality = s.localities[0]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('states', ds.state, s.states[0])
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.state = s.states[0]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('countries', ds.country, s.countries[0])
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.country = s.countries[0]

        # Testing DefaultKeyPair against Policy KeyPair
        dkp = DefaultKeyPair(key_type="foo",
                             rsa_key_size=256,
                             elliptic_curve="foo",
                             service_generated=True)
        ps.defaults.key_pair = dkp

        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('key types', dkp.key_type, kp.key_types[0])
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.key_type = kp.key_types[0]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('rsa key sizes', dkp.rsa_key_size, kp.rsa_key_sizes[0])
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.rsa_key_size = kp.rsa_key_sizes[0]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('elliptic curves', dkp.elliptic_curve, kp.elliptic_curves[0])
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.elliptic_curve = kp.elliptic_curves[0]
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = no_match_error_msg.format('generation type', dkp.service_generated, kp.service_generated)
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.service_generated = kp.service_generated

        # Testing DefaultKeyPair
        dkp2 = DefaultKeyPair(key_type="foo",
                              rsa_key_size=256,
                              elliptic_curve="foo",
                              service_generated=False)
        ps.policy = None
        ps.defaults.key_pair = dkp2

        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = unsupported_error_msg.format('key type', supported_key_types, dkp2.key_type)
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.key_type = "RSA"
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = unsupported_error_msg.format('rsa key size', supported_rsa_key_sizes, dkp2.rsa_key_size)
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.rsa_key_size = 4096
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            msg = unsupported_error_msg.format('elliptic curve', supported_elliptic_curves, dkp2.elliptic_curve)
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.elliptic_curve = "P521"

        # Testing autoinstalled option
        ps.policy = Policy(subject=s, key_pair=kp, auto_installed=True)
        try:
            validate_ps_tpp(ps)
        except VenafiError as err:
            self.assertEqual(err.args[0], no_match_error_msg.format('autoinstalled', False, True))
        ps.defaults.auto_installed = True

    def test_exceptions_vaas(self):
        try:
            get_ca_info("foo\\bar")
        except VenafiError as err:
            self.assertEqual(err.args[0], f"Certificate Authority name invalid [foo\\bar]")

        ps = PolicySpecification(policy=Policy(), defaults=Defaults())
        kp = KeyPair(key_types=["foo", "bar"],
                     rsa_key_sizes=[256],
                     elliptic_curves=["asd"],
                     service_generated=True)
        ps.policy.key_pair = kp
        ps.policy.subject_alt_names = SubjectAltNames(dns_allowed=True,  email_allowed=True)
        s = Subject(orgs=["Venafi"],
                    org_units=["QA Venafi"],
                    localities=["Salt Lake City"],
                    states=["Utah"],
                    countries=["US"])
        ps.policy.subject = s
        ds = DefaultSubject(org="Foo",
                            org_units=["Bar"],
                            locality="Kwan",
                            state="Merida",
                            country="MX")
        ps.defaults.subject = ds
        dkp = DefaultKeyPair(key_type="foo",
                             rsa_key_size=256,
                             elliptic_curve="bar",
                             service_generated=False)
        ps.defaults.key_pair = dkp

        # validate key pair values
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = "Key Type values exceeded. Only one Key Type is allowed by VaaS"
            self.assertEqual(err.args[0], msg)
        ps.policy.key_pair.key_types = ["foo"]
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = f"Key Type [{ps.policy.key_pair.key_types[0]}] is not supported by VaaS"
            self.assertEqual(err.args[0], msg)
        ps.policy.key_pair.key_types = ["RSA"]
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = f"The Key Size [{256}] is not supported by VaaS"
            self.assertEqual(err.args[0], msg)
        ps.policy.key_pair.rsa_key_sizes = [4096]

        # validate subject CN and SAN regexes
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = "Subject Alt name [SubjAltNameEmailAllowed] is not allowed by VaaS"
            self.assertEqual(err.args[0], msg)
        ps.policy.subject_alt_names.email_allowed = False

        # validate default subject values against policy values
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('Organization', ds.org, s.orgs)
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.org = s.orgs[0]
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('Org Units', ds.org_units, s.org_units)
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.org_units = s.org_units
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('Localities', ds.locality, s.localities)
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.locality = s.localities[0]
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('States', ds.state, s.states)
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.state = s.states[0]
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('Countries', ds.country, s.countries)
            self.assertEqual(err.args[0], msg)
        ps.defaults.subject.country = s.countries[0]

        # validate default key pair values against policy values
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('Key Types', dkp.key_type, kp.key_types)
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.key_type = kp.key_types[0]
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('RSA Key Sizes', dkp.rsa_key_size, kp.rsa_key_sizes)
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.rsa_key_size = kp.rsa_key_sizes[0]
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('Elliptic Curves', dkp.elliptic_curve, kp.elliptic_curves)
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.elliptic_curve = kp.elliptic_curves[0]
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = default_error_msg.format('Service Generated', dkp.service_generated, kp.service_generated)
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.service_generated = kp.service_generated

        # validate default values when policy is not defined
        ps.policy = None
        dkp2 = DefaultKeyPair(key_type="foo",
                              rsa_key_size=256,
                              elliptic_curve="bar",
                              service_generated=False)
        ps.defaults.key_pair = dkp2

        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = f"Default Key Type [{dkp2.key_type}] is not supported by VaaS"
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.key_type = "RSA"
        try:
            validate_ps_vaas(ps)
        except VenafiError as err:
            msg = f"Default Key Size [{256}] is not supported by VaaS"
            self.assertEqual(err.args[0], msg)
        ps.defaults.key_pair.rsa_key_size = 4096


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


def get_policy_obj(ca_type=None):
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


def get_defaults_obj():
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
