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
import logging
import random
import string
from os import environ

from vcert import venafi_connection, Authentication, SCOPE_SSH, SSHKeyPair, SSHCertRequest, write_ssh_files

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # Get credentials from environment variables
    url = environ.get('TPP_URL')
    user = environ.get('TPP_USER')
    password = environ.get('TPP_PASSWORD')

    connector = venafi_connection(url=url, user=user, password=password, http_request_kwargs={'verify': False})
    # If your TPP server certificate is signed with your own CA, or available only via proxy,
    # you can specify a trust bundle using requests vars:
    # connector = venafi_connection(url=url, api_key=api_key, access_token=access_token,
    #                          http_request_kwargs={"verify": "/path-to/bundle.pem"})

    # Create an Authentication object to request a token with the proper scope to manage SSH certificates
    auth = Authentication(user=user, password=password, scope=SCOPE_SSH)
    # Additionally, you may change the default client id for a custom one
    # Make sure this id has been registered on the TPP instance beforehand
    # Also, the user (TTP_USER) should be allowed to use this application
    # And the application should have the ssh permissions enabled
    auth.client_id = 'vcert-ssh-demo'
    # Request access token
    # After the request is successful, subsequent api calls will use the same token
    connector.get_access_token(auth)

    # Generate an SSH key pair for use. The passphrase can be omitted if encryption is not required
    # IMPORTANT: Save the private key on a secure location and do not share it with anyone.
    #            There is no way to decrypt the certificates generated with the public key
    #            without the corresponding private key
    ssh_kp = SSHKeyPair()
    ssh_kp.generate(key_size=4096, passphrase="foobar")
    # The path to the SSH CA in the TPP instance
    # This is a placeholder. Make sure an SSH CA already exists on your TPP instance
    cadn = "\\VED\\Certificate Authority\\SSH\\Templates\\my-ca"
    # The id of the SSH certificate
    key_id = f"vcert-python-{random_word(12)}"

    # Create the request object
    request = SSHCertRequest(cadn=cadn, key_id=key_id)
    # Add any additional info for the certificate, like:
    request.validity_period = "4h"
    request.source_addresses = ["test.com"]
    request.extensions = {
        'permit-pty': ""
    }
    # Include the locally-generated public key. If not set, the server will generate one for the certificate
    request.set_public_key_data(ssh_kp.public_key())

    # Request the certificate from TPP instance
    success = connector.request_ssh_cert(request)
    if success:
        # Retrieve the certificate from TPP instance
        response = connector.retrieve_ssh_cert(request)
        # Save the certificate to a file
        # The private and public key are optional values.
        write_ssh_files("/path/to/ssh/cert/folder", response.certificate_details.key_id, response.certificate_data,
                        ssh_kp.private_key(),
                        ssh_kp.public_key())


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
