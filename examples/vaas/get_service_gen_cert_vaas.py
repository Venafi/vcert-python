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
from vcert import (CertificateRequest, venafi_connection, CSR_ORIGIN_SERVICE, CHAIN_OPTION_FIRST)
import string
import random
import logging
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # Get credentials from environment variables
    url = environ.get('VAAS_URL')  # Optional, only use when connecting to a specific VaaS server
    api_key = environ.get('VAAS_APIKEY')
    zone = environ.get("VAAS_ZONE")

    # Connection will be chosen automatically based on which arguments are passed.
    # If api_key is passed, Venafi Cloud connection will be used.
    # url attribute is no required when connecting to production VaaS platform
    conn = venafi_connection(url=url, api_key=api_key)

    # Build a Certificate request
    request = CertificateRequest(common_name=random_word(10) + ".venafi.example.com")
    # Set the request to use a service generated CSR
    request.csr_origin = CSR_ORIGIN_SERVICE
    # A password should be defined for the private key to be generated.
    request.key_password = 'Foo.Bar.Pass.123!'
    # Include some Subject Alternative Names
    request.san_dns = ["www.dns.venafi.example.com", "ww1.dns.venafi.example.com"]
    # Additional CSR attributes can be included:
    request.organization = "Venafi, Inc."
    request.organizational_unit = ["Product Management"]
    request.locality = "Salt Lake City"
    request.province = "Utah"  # This is the same as state
    request.country = "US"

    # Specify ordering certificates in chain. Root can be CHAIN_OPTION_FIRST ("first")
    # or CHAIN_OPTION_LAST ("last"). By default it is CHAIN_OPTION_LAST.
    # request.chain_option = CHAIN_OPTION_FIRST
    #
    # To set Custom Fields for the certificate, specify an array of CustomField objects as name-value pairs
    # request.custom_fields = [
    #    CustomField(name="Cost Center", value="ABC123"),
    #    CustomField(name="Environment", value="Production"),
    #    CustomField(name="Environment", value="Staging")
    # ]
    #
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


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
