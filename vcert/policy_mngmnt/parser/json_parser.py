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

from vcert.errors import VenafiParsingError
from vcert.policy_mngmnt.policy_spec import PolicySpecification
from vcert.policy_mngmnt.parser.utils import parse_data, load_file


def parse_json_file(json_file_path):
    """
    :param str json_file_path: the path to the json file to be parsed
    :rtype PolicySpecification:
    """
    if not json_file_path:
        log.error('File path is empty')

    json_str = load_file(json_file_path)

    return parse_json_str(json_str)


def parse_json_str(json_str):
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


def to_json(policy_spec):
    """
    :param PolicySpecification policy_spec:
    :rtype str:
    """

    pass
