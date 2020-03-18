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

from vcert import CloudConnection, CertificateRequest, TPPConnection, FakeConnection, ZoneConfig
from vcert.common import CertField, KeyType
import string
import random
import logging
import time
from os import environ
from six import string_types, text_type
import unittest
import binascii
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)
from assets import *
FAKE = environ.get('FAKE')

TOKEN = environ.get('CLOUD_APIKEY')

USER = environ.get('TPP_USER')
PASSWORD = environ.get('TPP_PASSWORD')
TPPURL = environ.get('TPP_URL')
CLOUDURL = environ.get('CLOUD_URL')
RANDOM_DOMAIN = environ.get("RANDOM_DOMAIN")
if not isinstance(RANDOM_DOMAIN, text_type):
    RANDOM_DOMAIN = RANDOM_DOMAIN.decode()


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


class TestEnrollMethods(unittest.TestCase):

    def test_fake(self):
        print("Using fake connection")
        conn = FakeConnection()
        zone = "Default"
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn, _ = enroll(conn, zone, cn)
        # renew(conn, cert_id, pkey)

    def test_cloud(self):
        print("Using Cloud connection")
        zone = environ['CLOUD_ZONE']
        conn = CloudConnection(token=TOKEN, url=CLOUDURL)
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn, _ = enroll(conn, zone, cn)
        cert = renew(conn, cert_id, pkey, sn, cn)
        renew_by_thumbprint(conn, cert)
        req = CertificateRequest(cert_id=cert_id)
        self.renew_without_key_reuse(conn, zone)

    def test_tpp(self):
        zone = environ['TPP_ZONE']
        ecdsa_zone = environ['TPP_ZONE_ECDSA']
        print("Using TPP conection")
        conn = TPPConnection(USER, PASSWORD, TPPURL, http_request_kwargs={"verify": "/tmp/chain.pem"})
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn, _ = enroll(conn, zone, cn)
        time.sleep(5)
        cert = renew(conn, cert_id, pkey, sn, cn)
        time.sleep(5)
        renew_by_thumbprint(conn, cert)

        cn = randomword(10) + ".venafi.example.com"
        enroll(conn, ecdsa_zone, cn, TEST_KEY_ECDSA[0], TEST_KEY_ECDSA[1])
        cn = randomword(10) + ".venafi.example.com"
        enroll(conn, zone, cn, TEST_KEY_RSA_4096[0], TEST_KEY_RSA_4096[1])
        cn = randomword(10) + ".venafi.example.com"
        enroll(conn, zone, cn, TEST_KEY_RSA_2048_ENCRYPTED[0], TEST_KEY_RSA_2048_ENCRYPTED[1], 'venafi')

        key = open("/tmp/csr-test.key.pem").read()
        csr = open("/tmp/csr-test.csr.csr").read()
        enroll(conn, zone, private_key=key, csr=csr)
        self.renew_without_key_reuse(conn, zone)
        cert = enroll_with_zone_update(conn, ecdsa_zone, randomword(10) + ".venafi.example.com")
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        key = cert.public_key()
        self.assertEqual(key.curve.name, "secp521r1")

    def renew_without_key_reuse(self, conn, zone):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn, public_key = enroll(conn, zone, cn)
        req = CertificateRequest(cert_id=cert_id)
        conn.renew_cert(req, reuse_key=False)
        t = time.time()
        while time.time() - t < 300:
            cert = conn.retrieve_cert(req)
            if cert:
                break
            else:
                time.sleep(5)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        public_key_new = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.assertNotEqual(public_key_new, public_key)

def enroll_with_zone_update(conn, zone, cn=None):
    request = CertificateRequest(common_name=cn)
    zc = conn.read_zone_conf(zone)
    request.update_from_zone_config(zc)
    conn.request_cert(request, zone)
    while True:
        cert = conn.retrieve_cert(request)
        if cert:
            break
        else:
            time.sleep(5)
    return cert


def enroll(conn, zone, cn=None, private_key=None, public_key=None, password=None, csr=None):
    request = CertificateRequest(
        common_name=cn,
        private_key=private_key,
        key_password=password
    )
    if isinstance(conn, (FakeConnection or TPPConnection)):
        request.san_dns = ["www.client.venafi.example.com", "ww1.client.venafi.example.com"]
        request.email_addresses = ["e1@venafi.example.com", "e2@venafi.example.com"]
        request.ip_addresses = ["127.0.0.1", "192.168.1.1"]

    if csr:
        request.csr = csr

    conn.request_cert(request, zone)
    t = time.time()
    while time.time() - t < 300:
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
    t1 = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    t2 = [
        x509.NameAttribute(
            NameOID.COMMON_NAME, cn or RANDOM_DOMAIN
        )
    ]
    assert t1 == t2

    cert_public_key_pem = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    if isinstance(public_key, string_types):
        public_key = public_key.encode()
    if public_key:
        source_public_key_pem = serialization.load_pem_public_key(
            public_key, default_backend()
        ).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    else:
        source_public_key_pem = request.public_key_pem
    print(source_public_key_pem)
    print(cert_public_key_pem)
    assert source_public_key_pem == cert_public_key_pem
    return request.id, request.private_key_pem, cert.serial_number, cert_public_key_pem


def renew(conn, cert_id, pkey, sn, cn):
    print("Trying to renew certificate")
    new_request = CertificateRequest(
        cert_id=cert_id,
    )
    conn.renew_cert(new_request, reuse_key=True)
    time.sleep(5)
    t = time.time()
    while time.time() - t < 300:
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
    thumbprint = binascii.hexlify(prev_cert.fingerprint(hashes.SHA1())).decode()
    new_request = CertificateRequest(thumbprint=thumbprint)
    conn.renew_cert(new_request, reuse_key=True)
    t = time.time()
    while time.time() - t < 300:
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


class TestLocalMethods(unittest.TestCase):

    def test_parse_cloud_zone1(self):
        conn = CloudConnection(token="")
        p = conn._parse_policy_responce_to_object(json.loads(POLICY_CLOUD1))
        self.assertEqual(p.id, "3da4ba30-c370-11e9-9e69-99559a9ae32a")
        self.assertEqual(p.SubjectCNRegexes[-1], ".*.test")
        self.assertTrue(p.SubjectCRegexes == p.SubjectLRegexes == p.SubjectORegexes == p.SubjectOURegexes == p.SubjectSTRegexes == [".*"])
        self.assertEqual(p.key_types[0].key_type, KeyType.RSA)
        self.assertEqual(p.key_types[0].option, 2048)
        self.assertEqual(p.key_types[1].key_type, KeyType.RSA)
        self.assertEqual(p.key_types[1].option,  4096)
        self.assertTrue(len(p.key_types) == 2)

    #  cloud doesnt support ecdsa yet. may be can be enabled in the future
    # def test_parse_cloud_zone2(self):
    #     conn = CloudConnection(token="")
    #     p = conn._parse_policy_responce_to_object(json.loads(POLICY_CLOUD2))
    #     self.assertTrue(len(p.key_types) == 2)
    #     self.assertEqual(p.key_types[1].key_type, KeyType.RSA)
    #     self.assertEqual(p.key_types[0].key_type,   KeyType.ECDSA)
    #     self.assertEqual(p.key_types[0].key_curves,  ["p521"])

    def test_parse_tpp_zone1(self):
        conn = TPPConnection(url="http://example.com/", user="", password="")
        z = conn._parse_zone_data_to_object(json.loads(POLICY_TPP1))
        self.assertEqual(z.country.value, "US")
        self.assertEqual(z.locality.value, "Salt Lake")
        self.assertEqual(z.province.value, "Utah")
        self.assertEqual(z.organization.value, "Venafi Inc.")

    def test_update_request_with_zone_config(self):
        r = CertificateRequest()
        z = ZoneConfig(
            organization=CertField("Venafi"),
            organizational_unit=CertField(""),
            country=CertField(""),
            province=CertField(""),
            locality=CertField(""),
            policy=None,
            key_type=None
        )
        r.update_from_zone_config(z)
        self.assertEqual(r.organization, "Venafi")
        r = CertificateRequest(organization="Test")
        r.update_from_zone_config(z)
        self.assertEqual(r.organization, "Test")
        z = ZoneConfig(
            organization=CertField("Venafi", locked=True),
            organizational_unit=CertField(""),
            country=CertField(""),
            province=CertField(""),
            locality=CertField(""),
            policy=None,
            key_type=None
        )
        r.update_from_zone_config(z)
        self.assertEqual(r.organization, "Venafi")

    def test_request_with_csr(self):
        req = CertificateRequest(common_name="test.example.com", csr=EXAMPLE_CSR)
        self.assertEqual(req.common_name, "test.example.com")
        with self.assertRaises(Exception):
            CertificateRequest(common_name="test2.example.com", csr=EXAMPLE_CSR)
        req = CertificateRequest(csr=EXAMPLE_CSR)
        self.assertEqual(req.common_name, None)

