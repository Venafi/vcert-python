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

from tests import TPP_TOKEN_URL, USER, PASSWORD, TOKEN, CLOUDURL
from vcert import TPPTokenConnection, CloudConnection
from vcert.policy_mngmnt.parser.json_parser import parse_json_file
from vcert.policy_mngmnt.parser.yaml_parser import parse_yaml_file

POLICY_SPEC_JSON = './assets/policy_specification.json'
POLICY_SPEC_YAML = './assets/policy_specification.yaml'


class TestPolicySpecificationParsing(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, user=USER, password=PASSWORD,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestPolicySpecificationParsing, self).__init__(*args, **kwargs)

    def test_json_parsing(self):
        data = parse_json_file(POLICY_SPEC_JSON)
        pprint(data.__dict__)

    def test_yaml_11_parsing(self):
        pass

    def test_yaml_12_parsing(self):
        data = parse_yaml_file(POLICY_SPEC_YAML)
        pprint(data.__dict__)


class TestTPPPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, user=USER, password=PASSWORD,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestTPPPolicyManagement, self).__init__(*args, **kwargs)


class TestCloudPolicyManagement(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.cloud_zone = environ['CLOUD_ZONE']
        self.cloud_conn = CloudConnection(token=TOKEN, url=CLOUDURL)
        super(TestCloudPolicyManagement, self).__init__(*args, **kwargs)
