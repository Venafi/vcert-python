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

from ruamel.yaml import YAML

from vcert.errors import VenafiParsingError
from vcert.policy_mngmnt.parser.utils import parse_data, load_file


def parse_yaml_file(yaml_file_path):
    """
    :param str yaml_file_path: The path of the yaml file to be parsed
    :rtype PolicySpecification:
    """
    if not yaml_file_path:
        log.error('Yaml file path is empty')

    yaml_str = load_file(yaml_file_path)

    return parse_yaml(yaml_str)


def parse_yaml(yaml_string):
    """
    Parse the yaml string into a Policy Specification object

    :param str yaml_string: the Policy Configuration data in yaml format
    :rtype PolicySpecification:
    """
    if not yaml_string:
        log.error('yaml string is empty')
        raise VenafiParsingError

    yaml = YAML(typ='unsafe')
    data = yaml.load(yaml_string)
    policy = parse_data(data)

    return policy


def to_yaml(policy_spec):
    """
    :param PolicySpecification policy_spec:
    :rtype str:
    """
    pass
