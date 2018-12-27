#!/usr/bin/env python2
from __future__ import absolute_import, division, generators, unicode_literals, print_function, nested_scopes, with_statement

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
    print("Server online:", status)
    if not status:
        print('Server offline - exit')
        exit(1)

    request = CertificateRequest(common_name=randomword(10) + ".venafi.example.com")
    if not isinstance(conn, CloudConnection):
        # cloud connection doesn`t support dns, email and ip in CSR
        request.dns_names = ["www.client.venafi.example.com", "ww1.client.venafi.example.com"]
        request.email_addresses = "e1@venafi.example.com, e2@venafi.example.com"
        request.ip_addresses = ["127.0.0.1", "192.168.1.1"]
        request.chain_option = "last"

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
    print(cert, request.private_key_pem, sep="\n")
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
    return ''.join(random.choice(letters) for i in range(length))


if __name__ == '__main__':
    main()
