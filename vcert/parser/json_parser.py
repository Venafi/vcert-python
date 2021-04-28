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

import json
import logging as log
import os

from vcert.errors import VenafiParsingError
from vcert.parser.utils import load_file, parse_data, parse_policy_spec
from vcert.policy.policy_spec import PolicySpecification


def unmarshal_file(json_file_path):
    """
    :param str json_file_path: the path to the json file to be parsed
    :rtype PolicySpecification:
    """
    if not json_file_path:
        log.error('File path is empty')

    log.info('Loading Policy Specification from %s', json_file_path)
    json_str = load_file(json_file_path)

    return unmarshal(json_str)


def unmarshal(json_str):
    """
    :param str json_str:
    :rtype PolicySpecification:
    """
    if not json_str:
        log.error('Json string is empty')
        raise VenafiParsingError

    data = json.loads(json_str)
    policy_spec = parse_data(data)

    return policy_spec


def marshal(policy_spec, file_path):
    """
    Serializes the policy_spec object into the specified file_path

    :param PolicySpecification policy_spec:
    :param str file_path:
    """
    if not file_path:
        log.error('File path is empty')

    abs_path = os.path.abspath(file_path)
    data = parse_policy_spec(policy_spec)
    f = open(abs_path, 'w')
    json.dump(data, f, indent=4)
    f.close()
