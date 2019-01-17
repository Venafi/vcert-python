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

from __future__ import absolute_import, division, generators, unicode_literals, print_function, nested_scopes, \
    with_statement

from vcert import CloudConnection, CertificateRequest, TPPConnection, FakeConnection
import string
import random
import logging
import time
from os import environ
import unittest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)

FAKE = environ.get('FAKE')

TOKEN = environ.get('TOKEN')

USER = environ.get('TPPUSER')
PASSWORD = environ.get('TPPPASSWORD')
TPPURL = environ.get('TPPURL')
CLOUDURL = environ.get('CLOUDURL')


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


class TestStringMethods(unittest.TestCase):

    def test_fake(self):
        print("Using fake connection")
        conn = FakeConnection()
        zone = "Default"
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, zone, cn)
        # renew(conn, cert_id, pkey)

    def test_cloud(self):
        print("Using Cloud connection")
        zone = environ['CLOUDZONE']
        conn = CloudConnection(token=TOKEN, url=CLOUDURL)
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, zone, cn)
        cert = renew(conn, cert_id, pkey, sn, cn)
        renew_by_thumbprint(conn, cert)

    def test_tpp(self):
        zone = environ['TPPZONE']
        print("Using TPP conection")
        conn = TPPConnection(USER, PASSWORD, TPPURL, http_request_kwargs={"verify": "/tmp/chain.pem"})
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, zone, cn)
        cert = renew(conn, cert_id, pkey, sn, cn)
        renew_by_thumbprint(conn, cert)


def enroll(conn, zone, cn):
    print("Trying to ping service")
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)

    if isinstance(conn, (FakeConnection or TPPConnection)):
        request = CertificateRequest(
            common_name=cn,
            san_dns=["www.client.venafi.example.com", "ww1.client.venafi.example.com"],
            email_addresses=["e1@venafi.example.com", "e2@venafi.example.com"],
            ip_addresses=["127.0.0.1", "192.168.1.1"],
        )
    else:
        request = CertificateRequest(
            common_name=cn,
        )

    conn.request_cert(request, zone)
    while True:
        cert = conn.retrieve_cert(request)
        if cert:
            break
        else:
            time.sleep(5)
    # print("Certificate is:\n %s" % cert_pem)
    # print("Private key is:\n %s:" % request.private_key_pem)
    # and save into file
    f = open("./cert.pem", "w")
    f.write(cert.full_chain)
    f = open("./cert.key", "w")
    f.write(request.private_key_pem)
    f.close()

    cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
    assert isinstance(cert, x509.Certificate)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
        x509.NameAttribute(
            NameOID.COMMON_NAME, cn
        )
    ]

    private_key = serialization.load_pem_private_key(request.private_key_pem.encode(), password=None,
                                                     backend=default_backend())
    private_key_public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_pem = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(private_key_public_key_pem.decode())
    print(public_key_pem.decode())
    assert private_key_public_key_pem == public_key_pem

    return request.id, request.private_key_pem, cert.serial_number


def renew(conn, cert_id, pkey, sn, cn):
    print("Trying to renew certificate")
    new_request = CertificateRequest(
        id=cert_id,
    )
    conn.renew_cert(new_request)
    time.sleep(5)
    while True:
        new_cert= conn.retrieve_cert(new_request)
        if new_cert:
            break
        else:
            time.sleep(5)

    f = open("./renewed_cert.pem", "w")
    f.write(new_cert.full_chain)
    f.close()

    cert = x509.load_pem_x509_certificate(new_cert.cert.encode(), default_backend())
    assert isinstance(cert, x509.Certificate)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
        x509.NameAttribute(
            NameOID.COMMON_NAME, cn
        )
    ]
    assert cert.serial_number != sn
    private_key = serialization.load_pem_private_key(pkey.encode(), password=None, backend=default_backend())
    private_key_public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_pem = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert private_key_public_key_pem == public_key_pem
    return cert


def renew_by_thumbprint(conn, prev_cert):
    print("Trying to renew by thumbprint")
    thumbprint = prev_cert.fingerprint(hashes.SHA1()).hex()
    new_request = CertificateRequest(thumbprint=thumbprint)
    conn.renew_cert(new_request)
    while True:
        new_cert = conn.retrieve_cert(new_request)
        if new_cert:
            break
        else:
            time.sleep(5)
    cert = x509.load_pem_x509_certificate(new_cert.cert.encode(), default_backend())
    assert isinstance(cert, x509.Certificate)
    print(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    print(prev_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == prev_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
