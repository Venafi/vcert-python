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

from tests import TPP_TOKEN_URL, USER, PASSWORD, TOKEN, CLOUDURL, TPP_ACCESS_TOKEN
from vcert import TPPTokenConnection, CloudConnection
from vcert.parser import json_parser
from vcert.parser.yaml_parser import parse_yaml_file

POLICY_SPEC_JSON = './assets/policy_specification.json'
POLICY_SPEC_YAML = './assets/policy_specification.yaml'


class TestPolicySpecificationParsing(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, user=USER, password=PASSWORD,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestPolicySpecificationParsing, self).__init__(*args, **kwargs)

    def test_json_parsing(self):
        data = json_parser.parse_json_file(POLICY_SPEC_JSON)
        pprint(data.__dict__)

    def test_yaml_11_parsing(self):
        pass

    def test_yaml_12_parsing(self):
        data = parse_yaml_file(POLICY_SPEC_YAML)
        pprint(data.__dict__)


class TestTPPTokenPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, access_token=TPP_ACCESS_TOKEN,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestTPPTokenPolicyManagement, self).__init__(*args, **kwargs)

    def test_read_policy_spec(self):
        ps = self.tpp_conn.get_policy_specification(self.tpp_zone)
        json_parser.to_json_file(ps, "test_tpp_pm.json")
        # pprint(data)

    def test_create_policy(self):
        ps = json_parser.parse_json_file(POLICY_SPEC_JSON)
        created_ps = self.tpp_conn.set_policy("Amoo\\rvela", ps)
        pprint(created_ps)


class TestCloudPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.cloud_zone = environ['CLOUD_ZONE']
        self.cloud_conn = CloudConnection(token=TOKEN, url=CLOUDURL)
        super(TestCloudPolicyManagement, self).__init__(*args, **kwargs)

    def test_read_policy_spec(self):
        ps = self.cloud_conn.get_policy_specification("vcert-amoo-0004\\vcert-policy-creator-31")
        json_parser.to_json_file(ps, "test_cloud_pm.json")

    def test_create_policy_spec(self):
        ps = json_parser.parse_json_file(POLICY_SPEC_JSON)
        self.cloud_conn.set_policy("amoo\\vcert-rvela", ps)
        pass
