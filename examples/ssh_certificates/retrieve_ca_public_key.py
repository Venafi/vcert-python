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

from vcert import venafi_connection, Authentication, SCOPE_SSH, SSHKeyPair, SSHCertRequest, write_ssh_files, \
    VenafiPlatform, SSHCATemplateRequest

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # Get credentials from environment variables.
    url = environ.get('TPP_URL')
    ca_dn = environ.get('TPP_SSH_CADN')
    ca_guid = environ.get('TPP_SSH_CA_GUID')
    # Authentication is required for retrieving the CA principals only.
    user = environ.get("TPP_USER")
    password = environ.get("TPP_PASSWORD")

    # A Connector can be instantiated with no values by using the platform argument.
    # url argument is always required for TPP.
    connector = venafi_connection(platform=VenafiPlatform.TPP, url=url, http_request_kwargs={"verify": False})
    # Optionally, the connector can be instantiated passing the specific arguments:
    # connector = venafi_connection(url=url, user=user, password=password, http_request_kwargs={"verify": False})

    # If your TPP server certificate is signed with your own CA, or available only via proxy,
    # you can specify a trust bundle using requests vars:
    # connector = venafi_connection(url=url, api_key=api_key, access_token=access_token,
    #                          http_request_kwargs={"verify": "/path-to/bundle.pem"})

    # Create an SSHCATemplateRequest to pass the identifier of the SSH Certificate Authority to retrieve.
    # Either CADN or Guid can be used as identifiers.
    request = SSHCATemplateRequest(ca_template=ca_dn)
    # request = SSHCATemplateRequest(ca_guid=ca_guid)

    # Retrieve the public key.
    # No Authentication is provided to the Connector so, only the public key is available.
    ssh_config = connector.retrieve_ssh_config(ca_request=request)
    pub_key_data = ssh_config.ca_public_key
    with open("./ca-pub.key", 'w') as ca_file:
        ca_file.write(pub_key_data)

    # To retrieve the CA principals create an Authentication object with the proper scope to manage SSH certificates.
    auth = Authentication(user=user, password=password, scope=SCOPE_SSH)
    # Additionally, you may change the default client id for a custom one.
    # Make sure this id has been registered on the TPP instance beforehand.
    # Also, the user (TTP_USER) should be allowed to use this application
    # and the application should have the ssh permissions enabled.
    auth.client_id = 'vcert-ssh-ca-pubkey-demo'
    # Request an access token.
    # After the request is successful, subsequent api calls will use the same token
    connector.get_access_token(auth)
    # Retrieve SSH Certificate Authority public key and principals
    ssh_config = connector.retrieve_ssh_config(ca_request=request)
    with open("./ca2-pub.key", 'w') as ca_file:
        ca_file.write(pub_key_data)

    print("CA principals:\n")
    print(ssh_config.ca_principals)


if __name__ == '__main__':
    main()