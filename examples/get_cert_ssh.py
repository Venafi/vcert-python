#!/usr/bin/env python3
#
# Copyright 2019 Venafi, Inc.
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

from __future__ import print_function

from ssh_utils import SSHCertRequest, generate_ssh_keypair
from vcert import venafi_connection
import string
import random
import logging
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # Get credentials from environment variables
    access_token = environ.get("TPP_ACCESS_TOKEN")
    url = environ.get('TPP_URL')

    conn = venafi_connection(url=url, access_token=access_token, http_request_kwargs={"verify": False})
    # If your TPP server certificate signed with your own CA, or available only via proxy,
    # you can specify a trust bundle using requests vars:
    # conn = venafi_connection(url=url, api_key=api_key, access_token=access_token,
    #                          http_request_kwargs={"verify": "/path-to/bundle.pem"})

    # Generate an SSH key pair for use. The passphrase can be omitted if encryption is not required
    # IMPORTANT: Save the private key on a secure location and do not share it with anyone.
    #            There is no way to decrypt the certificates generated with the public key
    #            without the corresponding private key
    pub_key, priv_key = generate_ssh_keypair(key_size=4096, passphrase="foobar")
    # The path to the SSH CA in the TPP instance
    cadn = "\\VED\\Certificate Authority\\SSH\\Templates\\open-source-test-cit"
    # The id of the SSH certificate
    key_id = "vcert-python-%s" % random_word(12)

    # Create the request object
    request = SSHCertRequest(cadn=cadn, key_id=key_id)
    # Add any additional info for the certificate, like:
    request.validity_period = "4h"
    request.source_addresses = ["test.com"]
    request.extensions = {
        "permit-pty": ""
    }
    # Include the locally-generated public key. If not set, the server will generate one for the certificate
    request.public_key_data = pub_key

    # Request the certificate from TPP instance
    success = conn.request_ssh_cert(request)
    if success:
        # Retrieve the certificate from TPP instance
        response = conn.retrieve_ssh_cert(request)
        pass


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
