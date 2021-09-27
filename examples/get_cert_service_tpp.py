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

from vcert import (CertificateRequest, venafi_connection, CSR_ORIGIN_SERVICE, CHAIN_OPTION_FIRST)
import string
import random
import logging
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # Get credentials from environment variables
    url = environ.get('TPP_TOKEN_URL')
    user = environ.get('TPP_USER')
    password = environ.get('TPP_PASSWORD')
    zone = environ.get("TPP_ZONE")
    server_trust_bundle = environ.get('TPP_TRUST_BUNDLE')

    # Connection will be chosen automatically based on which arguments are passed.
    # If token is passed Venafi Cloud connection will be used.
    # If user, password, and URL Venafi Platform (TPP) will be used.
    # If your TPP server certificate signed with your own CA, or available only via proxy, you can specify
    # a trust bundle using http_request_kwargs.
    conn = venafi_connection(url=url, user=user, password=password, http_request_kwargs={"verify": server_trust_bundle})

    # Build a Certificate request
    request = CertificateRequest(common_name=random_word(10) + ".venafi.example.com")
    # Set the request to use a service generated CSR
    request.csr_origin = CSR_ORIGIN_SERVICE
    # Include some Subject Alternative Names
    request.san_dns = ["www.dns.venafi.example.com", "ww1.dns.venafi.example.com"]
    request.email_addresses = ["email1@venafi.example.com", "email2@venafi.example.com"]
    request.ip_addresses = ["127.0.0.1", "192.168.1.1"]
    request.uniform_resource_identifiers = ["http://wgtest.uri.com","https://ragnartest.uri.com"]
    request.user_principal_names = ["upn1@venafi.example.com", "upn2@venafi.example.com"]
    # Specify ordering certificates in chain. Root can be CHAIN_OPTION_FIRST ("first")
    # or CHAIN_OPTION_LAST ("last"). By default it is CHAIN_OPTION_LAST.
    # You can also specify CHAIN_OPTION_IGNORE ("ignore") to ignore chain (supported only for TPP).
    # request.chain_option = CHAIN_OPTION_FIRST
    # To set Custom Fields for the certificate, specify an array of CustomField objects as name-value pairs
    # request.custom_fields = [
    #    CustomField(name="Cost Center", value="ABC123"),
    #    CustomField(name="Environment", value="Production"),
    #    CustomField(name="Environment", value="Staging")
    # ]
    #
    # Update certificate request from zone.
    zone_config = conn.read_zone_conf(zone)
    request.update_from_zone_config(zone_config)
    # Request the certificate.
    conn.request_cert(request, zone)

    # Wait for the certificate to be retrieved.
    # This operation may take some time to return, as it waits until the certificate is ISSUED or it timeout.
    # Timeout is 180s by default. Can be changed using:
    # request.timeout = 300
    cert = conn.retrieve_cert(request)

    # Print the certificate
    print(cert.full_chain)
    # Save it into a file
    f = open("./cert.pem", "w")
    f.write(cert.full_chain)
    f.close()

    print("Trying to renew certificate")
    new_request = CertificateRequest(cert_id=request.id)
    # The renewal request should use a service generated CSR as well
    # This may not be necessary and depends entirely on the settings of your Policy/Zone
    new_request.csr_origin = CSR_ORIGIN_SERVICE
    conn.renew_cert(new_request)
    new_cert = conn.retrieve_cert(new_request)
    print(new_cert.cert)
    fn = open("./new_cert.pem", "w")
    fn.write(new_cert.cert)
    fn.close()


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
