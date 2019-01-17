#!/usr/bin/env python2
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
from vcert import CertificateRequest, Connection, CloudConnection, FakeConnection
import string
import random
import logging
import time
from os import environ

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    token = environ.get('TOKEN')
    user = environ.get('TPPUSER')
    password = environ.get('TPPPASSWORD')
    url = environ.get('TPPURL')
    zone = environ.get("ZONE")
    conn = Connection(url=url, token=token, user=user, password=password)

    print("Trying to ping url %s" % conn._base_url)
    status = conn.ping()
    print("Server online: %s" % status)
    if not status:
        print('Server offline - exit')
        exit(1)

    request = CertificateRequest(common_name=randomword(10) + u".venafi.example.com")
    if not isinstance(conn, CloudConnection):
        # Cloud connection doesn`t support dns, email and ip in CSR
        request.san_dns = [u"www.client.venafi.example.com", u"ww1.client.venafi.example.com"]
        request.email_addresses = [u"e1@venafi.example.com", u"e2@venafi.example.com"]
        request.ip_addresses = [u"127.0.0.1", u"192.168.1.1"]
        # Specify ordering certificates in chain. Root can be "first" or "last". By default it last. You also can
        # specify "ignore" to ignore chain (supported only for Platform).

    # make certificate request
    conn.request_cert(request, zone)

    # and wait for signing
    while True:
        cert = conn.retrieve_cert(request)
        if cert:
            break
        else:
            time.sleep(5)

    # after that print cert and key
    print(cert)
    print(request.private_key_pem)
    # and save into file
    f = open("/tmp/cert.pem", "w")
    f.write(cert)
    f = open("/tmp/cert.key", "w")
    f.write(request.private_key_pem)
    f.close()

    if not isinstance(conn, FakeConnection):
        # fake connection doesn`t support certificate renewing
        print("Trying to renew certificate")
        new_request = CertificateRequest(
            id=request.id,
        )
        conn.renew_cert(new_request)
        while True:
            new_cert = conn.retrieve_cert(new_request)
            if new_cert:
                break
            else:
                time.sleep(5)
        print(new_cert)
        fn = open("/tmp/new_cert.pem", "w")
        fn.write(new_cert)


def randomword(length):
    letters = string.ascii_lowercase
    return u''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
