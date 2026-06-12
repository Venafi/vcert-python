#!/usr/bin/env python3
#
# Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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
from vcert import (CertificateRequest, venafi_connection, VenafiPlatform)
import string
import random
import logging
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # Get credentials from environment variables.
    # NGTS (Palo Alto Networks Next-Gen Trust Security) authenticates with Strata Cloud Manager
    # OAuth2 client credentials issued by a service account. Both the API base URL and the token
    # URL differ per environment (dev/prod), so both must be supplied.
    url = environ.get('NGTS_URL')                    # NGTS API base URL (e.g. https://api.sase.paloaltonetworks.com/ngts)
    token_url = environ.get('NGTS_TOKEN_URL')        # OAuth2 token endpoint (different FQDN, env-specific)
    client_id = environ.get('NGTS_CLIENT_ID')        # Service-account client id
    client_secret = environ.get('NGTS_CLIENT_SECRET')  # Service-account client secret
    tsg_id = environ.get('NGTS_TSG_ID')              # Tenant service group id (used to build the scope)
    scope = environ.get('NGTS_SCOPE')                # Optional: a ready "tsg_id:<TSG_ID>" scope
    zone = environ.get('NGTS_ZONE')                  # Certificate Issuing Template alias (CIT-only)

    # The connection is chosen automatically: when token_url + client_id + client_secret are
    # present, an NGTS connection is built. The platform can also be set explicitly:
    #   conn = venafi_connection(platform=VenafiPlatform.NGTS, ...)
    conn = venafi_connection(url=url, token_url=token_url, client_id=client_id, client_secret=client_secret,
                             tsg_id=tsg_id, scope=scope)

    # Build a Certificate request
    request = CertificateRequest(common_name=f"{random_word(10)}.venafi.example.com")
    request.san_dns = ["www.dns.venafi.example.com", "ww1.dns.venafi.example.com"]

    # Request the certificate.
    conn.request_cert(request, zone)
    # Wait for the certificate to be retrieved (until ISSUED or timeout, 180s by default).
    cert = conn.retrieve_cert(request)

    # Print the certificate
    print(cert.full_chain)
    # Save it into a file
    with open("./cert.pem", "w") as f:
        f.write(cert.full_chain)


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
