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
# Example: enroll a certificate from NGTS (Palo Alto Networks Strata Cloud Manager) with a locally
# generated key + CSR, and save BOTH the certificate chain and the private key to disk.
#
# Run it (a non-production tenant is shown; for production omit NGTS_URL and NGTS_TOKEN_URL):
#
#   export NGTS_CLIENT_ID='svc-account@1234567890.iam.panserviceaccount.com'
#   export NGTS_CLIENT_SECRET='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
#   export NGTS_TSG_ID='1234567890'                        # builds scope "tsg_id:1234567890"
#   export NGTS_ZONE='my-issuing-template'                 # CIT alias ONLY (see note below)
#   export NGTS_URL='https://dev.api.sase.paloaltonetworks.com/ngts'                     # non-prod only
#   export NGTS_TOKEN_URL='https://auth.dev.appsvc.paloaltonetworks.com/auth/v1/oauth2/access_token'  # non-prod only
#   python examples/ngts/get_cert_ngts.py
#
from vcert import (CertificateRequest, venafi_connection)
import string
import random
import logging
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # --- NGTS connection -------------------------------------------------------------------------
    # NGTS authenticates with OAuth2 client-credentials issued to a Strata Cloud Manager service
    # account. venafi_connection() selects the NGTS backend automatically when client_id +
    # client_secret are supplied (to select it explicitly instead, import VenafiPlatform from
    # vcert and pass platform=VenafiPlatform.NGTS).
    #
    #   * url / token_url default to the Palo Alto PRODUCTION endpoints ("api.strata..." /
    #     "auth.apps..."). A non-production tenant (dev/staging) MUST set BOTH -- its hosts differ
    #     (e.g. the "dev.api.sase..." / "auth.dev.appsvc..." forms shown above); otherwise the
    #     production defaults are used and every call 401s.
    #   * scope must be "tsg_id:<TSG_ID>"; passing tsg_id builds it for you.
    #   * NGTS_ZONE is the Certificate Issuing Template (CIT) ALIAS ONLY -- e.g.
    #     "my-issuing-template". NGTS has NO Application layer, so do NOT use the VaaS
    #     "Application\\IssuingTemplate" (backslash) form here.
    url = environ.get('NGTS_URL')                        # optional; set for non-production tenants
    token_url = environ.get('NGTS_TOKEN_URL')            # optional; set for non-production tenants
    client_id = environ.get('NGTS_CLIENT_ID')            # service-account client id
    client_secret = environ.get('NGTS_CLIENT_SECRET')    # service-account client secret
    tsg_id = environ.get('NGTS_TSG_ID')                  # tenant service group id -> scope "tsg_id:<id>"
    scope = environ.get('NGTS_SCOPE')                    # optional ready-made "tsg_id:<TSG_ID>" scope
    zone = environ.get('NGTS_ZONE')                      # CIT alias only (no "App\\CIT")

    conn = venafi_connection(url=url, token_url=token_url, client_id=client_id,
                             client_secret=client_secret, tsg_id=tsg_id, scope=scope)

    # --- Build the request (locally generated key + CSR) -----------------------------------------
    # csr_origin defaults to local: vcert generates the private key and the CSR on this host.
    # (Service-generated CSR on NGTS is also supported, but that additionally requires a VSatellite
    # provisioned in the tenant and a CIT that permits system-generated keys.)
    request = CertificateRequest(common_name=f"{random_word(10)}.venafi.example.com")
    request.san_dns = ["www.dns.venafi.example.com", "ww1.dns.venafi.example.com"]

    # --- Enroll + retrieve -----------------------------------------------------------------------
    conn.request_cert(request, zone)
    # Poll until the certificate is ISSUED (or timeout, 180s by default).
    cert = conn.retrieve_cert(request)

    # --- Persist the results ---------------------------------------------------------------------
    # IMPORTANT: write the private key too. For a locally generated key it lives in
    # request.private_key_pem (retrieve_cert also mirrors it onto cert.key). A certificate written
    # without its matching private key is unusable.
    print(cert.full_chain)
    with open("./cert.pem", "w") as f:
        f.write(cert.full_chain)
    with open("./cert.key", "w") as f:
        f.write(request.private_key_pem)
    print("Saved certificate chain to ./cert.pem and private key to ./cert.key")


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
