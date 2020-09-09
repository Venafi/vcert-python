#!/usr/bin/env python3
#
# Copyright 2020 Venafi, Inc.
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
from vcert import (CertificateRequest, Connection, FakeConnection, TPPConnection, RevocationRequest, KeyType,
                   token_connection, TPPTokenConnection)
import string
import random
import logging
import time
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    # Get credentials from environment variables
    user = environ.get('TPP_USER')
    password = environ.get('TPP_PASSWORD')
    url = environ.get('TPP_TOKEN_URL')
    zone = environ.get("ZONE")
    fake = environ.get('FAKE')

    if fake:
        # If fake is true, test connection will be used.
        conn = Connection(fake=True)
    else:
        # If user and password are passed, you can get a new token from them.
        # If access_token and refresh_token are passed, there is no need for the username and password.
        # If only access_token is passed, the Connection will fail when token expires, as there is no way to refresh it.
        conn = token_connection(url=url, user=user, password=password, http_request_kwargs={"verify": False})
        # If your TPP server certificate signed with your own CA, or available only via proxy, you can specify
        # a trust bundle using requests vars:
        # conn = token_connection(url=url, user=user, password=password,
        #                         http_request_kwargs={"verify": "/path-to/bundle.pem"})

    request = CertificateRequest(common_name=random_word(10) + ".venafi.example.com")
    request.san_dns = ["www.client.venafi.example.com", "ww1.client.venafi.example.com"]
    request.email_addresses = ["e1@venafi.example.com", "e2@venafi.example.com"]
    request.ip_addresses = ["127.0.0.1", "192.168.1.1"]
    # Specify ordering certificates in chain. Root can be "first" or "last". By default its last. You also can
    # specify "ignore" to ignore chain (supported only for Platform).

    # configure key type, RSA example
    # request.key_type = KeyType(KeyType.RSA, 4096)
    # or set it to ECDSA
    request.key_type = KeyType(KeyType.ECDSA, "p521")
    # Update certificate request from zone
    zone_config = conn.read_zone_conf(zone)
    request.update_from_zone_config(zone_config)
    conn.request_cert(request, zone)

    # and wait for signing
    t = time.time() + 300
    while time.time() < t:
        cert = conn.retrieve_cert(request)
        if cert:
            break
        else:
            time.sleep(5)

    # after that print cert and key
    print(cert.full_chain, request.private_key_pem, sep="\n")
    # and save into file
    f = open("/tmp/cert.pem", "w")
    f.write(cert.full_chain)
    f = open("/tmp/cert.key", "w")
    f.write(request.private_key_pem)
    f.close()

    if not isinstance(conn, FakeConnection):
        # fake connection doesn`t support certificate renewing
        print("Trying to renew certificate")
        new_request = CertificateRequest(
            cert_id=request.id,
        )
        conn.renew_cert(new_request)
        while True:
            new_cert = conn.retrieve_cert(new_request)
            if new_cert:
                break
            else:
                time.sleep(5)
        print(new_cert.cert, new_request.private_key_pem, sep="\n")
        fn = open("/tmp/new_cert.pem", "w")
        fn.write(new_cert.cert)
        fn = open("/tmp/new_cert.key", "w")
        fn.write(new_request.private_key_pem)
        fn.close()
    if isinstance(conn, (TPPConnection or TPPTokenConnection)):
        revocation_req = RevocationRequest(req_id=request.id, comments="Just for test")
        print("Revoke", conn.revoke_cert(revocation_req))

    print("Trying to sign CSR")
    csr_pem = open("example-csr.pem", "rb").read()
    csr_request = CertificateRequest(csr=csr_pem.decode())
    # zone_config = conn.read_zone_conf(zone)
    # request.update_from_zone_config(zone_config)
    conn.request_cert(csr_request, zone)

    # and wait for signing
    while True:
        cert = conn.retrieve_cert(csr_request)
        if cert:
            break
        else:
            time.sleep(5)

    # after that print cert and key
    print(cert.full_chain)
    # and save into file
    f = open("/tmp/signed-cert.pem", "w")
    f.write(cert.full_chain)
    f.close()


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
