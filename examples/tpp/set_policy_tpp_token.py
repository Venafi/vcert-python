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
from pprint import pprint

from parser import json_parser, yaml_parser
from parser.utils import parse_policy_spec
from policy.policy_spec import PolicySpecification, Policy, Subject, KeyPair, SubjectAltNames, Defaults, \
    DefaultSubject, DefaultKeyPair
from vcert import venafi_connection
from vcert.common import Authentication, SCOPE_PM
import logging
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # Get credentials from environment variables
    url = environ.get('TPP_TOKEN_URL')
    user = environ.get('TPP_USER')
    password = environ.get('TPP_PASSWORD')
    zone = environ.get('TPP_ZONE')
    server_trust_bundle = environ.get('TPP_TRUST_BUNDLE')

    # Get connector object.
    # The default state of this connection only allows for certificate management.
    connector = venafi_connection(url=url, user=user, password=password,
                                  http_request_kwargs={"verify": server_trust_bundle})

    # Create Authentication object with required scope for policy management.
    auth = Authentication(user=user, password=password, scope=SCOPE_PM)
    # Additionally, change the client id for a custom one.
    # Make sure this id has been registered on the TPP instance beforehand.
    auth.client_id = 'vcert-tpp-demo'

    # Request access token with values specified in auth object.
    # After the request is successful, subsequent api calls will use the same token.
    connector.get_access_token(auth)

    # Define policy specification object to create a new policy
    ps = PolicySpecification()
    # Alternatively, the parser utilities can be used to read a json/yaml file into a PolicySpecification object
    # ps = json_parser.parse_file('path/to/file.json')
    # ps = yaml_parser.parse_file('path/to/file.yaml')

    # All of the following values can be omitted to create a Policy with inherited (TPP) or recommended (Cloud) settings
    ps.policy = Policy(
        subject=Subject(
            orgs=['OSS Venafi, Inc.'],
            org_units=['Customer Support', 'Professional Services'],
            localities=['Salt Lake City'],
            states=['Utah'],
            countries=['US']
        ),
        key_pair=KeyPair(
            key_types=['RSA'],
            rsa_key_sizes=[4096],
            elliptic_curves=['P521'],
            reuse_allowed=True
        ),
        subject_alt_names=SubjectAltNames(
            dns_allowed=True,
            ip_allowed=False,
            email_allowed=False,
            uri_allowed=False,
            upn_allowed=False
        ),
        cert_auth=None,
        domains=['vfidev.com', 'vfidev.net', 'venafi.example'],
        wildcard_allowed=True,
        auto_installed=False
    )
    ps.defaults = Defaults(
        d_subject=DefaultSubject(
            org='OSS Venafi, Inc.',
            org_units=['Customer Support', 'Professional Services'],
            locality='Salt Lake City',
            state='Utah',
            country='US'
        ),
        d_key_pair=DefaultKeyPair(
            key_type='RSA',
            rsa_key_size=4096,
            elliptic_curve='P521'
        ),
        auto_installed=False
    )

    # Create the new policy in the path specified by zone
    # If the policy already exists, it will be updated instead with the new settings
    connector.set_policy(zone, ps)

    # Retrieve the Policy from the Venafi Platform
    response = connector.get_policy(zone)

    # Transform the PolicySpecification object to a serializable form
    data = parse_policy_spec(response)
    # Print the transformed data
    pprint(data)
    # Alternatively the parser utilities can be used to serialize the PolicySpecification object to a json/yaml file
    # json_parser.serialize(response, 'path/to/file.json')
    # yaml_parser.serialize(response, 'path/to/file.yaml')


if __name__ == '__main__':
    main()
