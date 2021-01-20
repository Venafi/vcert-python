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

from vcert import CloudConnection, CertificateRequest, TPPConnection, FakeConnection, ZoneConfig, RevocationRequest, \
    TPPTokenConnection
from vcert.common import CertField, KeyType, CustomField
from vcert.errors import ClientBadData, ServerUnexptedBehavior
from vcert.pem import parse_pem
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
from assets import TEST_KEY_RSA_4096, TEST_KEY_ECDSA, TEST_KEY_RSA_2048_ENCRYPTED, POLICY_CLOUD1, POLICY_TPP1,\
    EXAMPLE_CSR, EXAMPLE_CHAIN

FAKE = environ.get('FAKE')
TOKEN = environ.get('CLOUD_APIKEY')
USER = environ.get('TPP_USER')
PASSWORD = environ.get('TPP_PASSWORD')
TPPURL = environ.get('TPP_URL')
CLOUDURL = environ.get('CLOUD_URL')
RANDOM_DOMAIN = environ.get("RANDOM_DOMAIN")
TPP_TOKEN_URL = environ.get("TPP_TOKEN_URL")

if not isinstance(RANDOM_DOMAIN, text_type):
    RANDOM_DOMAIN = RANDOM_DOMAIN.decode()


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


class TestFakeMethods(unittest.TestCase):
    def test_fake_enroll(self):
        conn = FakeConnection()
        zone = "Default"
        cn = randomword(10) + ".venafi.example.com"
        enroll(conn, zone, cn)
        # renew(conn, cert_id, pkey)


class TestCloudMethods(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.cloud_zone = environ['CLOUD_ZONE']
        self.cloud_conn = CloudConnection(token=TOKEN, url=CLOUDURL)
        super(TestCloudMethods, self).__init__(*args, **kwargs)

    def test_cloud_enroll(self):
        cn = randomword(10) + ".venafi.example.com"
        enroll(self.cloud_conn, self.cloud_zone, cn)

    def test_cloud_enroll_with_custom_csr(self):
        key = open("/tmp/csr-test.key.pem").read()
        csr = open("/tmp/csr-test.csr.csr").read()
        enroll(self.cloud_conn, self.cloud_zone, private_key=key, csr=csr)

    def test_cloud_renew(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.cloud_conn, self.cloud_zone, cn)
        time.sleep(5)
        renew(self.cloud_conn, cert_id, pkey, cert.serial_number, cn)

    def test_cloud_renew_twice(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.cloud_conn, self.cloud_zone, cn)
        time.sleep(5)
        renew(self.cloud_conn, cert_id, pkey, cert.serial_number, cn)
        time.sleep(5)
        renew(self.cloud_conn, cert_id, pkey, cert.serial_number, cn)

    def test_cloud_renew_by_thumbprint(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.cloud_conn, self.cloud_zone, cn)
        time.sleep(5)
        renew_by_thumbprint(self.cloud_conn, cert)

    def test_cloud_renew_without_key_reuse(self):
        renew_without_key_reuse(self, self.cloud_conn, self.cloud_zone)

    def test_cloud_read_zone_config(self):
        zone = self.cloud_conn.read_zone_conf(self.cloud_zone)
        self.assertEqual(zone.key_type.key_type, KeyType.RSA)
        self.assertEqual(zone.key_type.option, 2048)
        p = zone.policy
        self.assertListEqual(p.SubjectCNRegexes, ['.*.example.com', '.*.example.org', '.*.example.net', '.*.invalid',
                                                  '.*.local', '.*.localhost', '.*.test', '.*.vfidev.com'])
        self.assertListEqual(p.SubjectCRegexes, [".*"])
        self.assertListEqual(p.SubjectLRegexes, [".*"])
        self.assertListEqual(p.SubjectORegexes, [".*"])
        self.assertListEqual(p.SubjectOURegexes, [".*"])
        self.assertEqual(p.key_types[0].option, 2048)
        self.assertEqual(p.key_types[1].option, 4096)

    def test_cloud_read_zone_unknown_zone(self):
        with self.assertRaises(Exception):
            self.cloud_conn.read_zone_conf("4d806fbc-06bb-4a2a-b224-9e58a7e996f5")

    def test_cloud_read_zone_invalid_zone(self):
        with self.assertRaises(Exception):
            self.cloud_conn.read_zone_conf("fdsfsfa")

    def test_cloud_retrieve_non_issued(self):
        req = CertificateRequest(cert_id="4d806fbc-06bb-4a2a-b224-9e58a7e996f5")
        with self.assertRaises(Exception):
            self.cloud_conn.retrieve_cert(req)

    def test_cloud_search_by_thumbpint(self):
        req, cert = simple_enroll(self.cloud_conn, self.cloud_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(),  default_backend())
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        time.sleep(1)
        found = self.cloud_conn.search_by_thumbprint(fingerprint)
        self.assertEqual(found.certificateIds[0], req.cert_guid)


class TestTPPMethods(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_zone_ecdsa = environ['TPP_ZONE_ECDSA']
        self.tpp_conn = TPPConnection(USER, PASSWORD, TPPURL, http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestTPPMethods, self).__init__(*args, **kwargs)

    def test_tpp_enroll(self):
        cn = randomword(10) + ".venafi.example.com"
        _, pkey, cert, _, cert_guid = enroll(self.tpp_conn, self.tpp_zone, cn)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config["Origin"], "Venafi VCert-Python")

    def test_tpp_enroll_with_custom_fields(self):
        cn = randomword(10) + ".venafi.example.com"
        custom_fields = [
            CustomField(name="custom", value="pythonTest"),
            CustomField(name="cfList", value="item2"),
            CustomField(name="cfListMulti", value="tier1"),
            CustomField(name="cfListMulti", value="tier4")
        ]
        cert_id, pkey, cert, _, cert_guid = enroll(conn=self.tpp_conn, zone=self.tpp_zone, cn=cn, custom_fields=custom_fields)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config["Origin"], "Venafi VCert-Python")

    def test_tpp_enroll_origin(self):
        cn = randomword(10) + ".venafi.example.com"
        _, pkey, cert, _, cert_guid = enroll(self.tpp_conn, self.tpp_zone, cn)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config["Origin"], "Venafi VCert-Python")

    def test_tpp_renew(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        cert = renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)

    def test_tpp_renew_twice(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        time.sleep(5)
        renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)
        time.sleep(5)
        renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)

    def test_tpp_renew_by_thumbprint(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        renew_by_thumbprint(self.tpp_conn, cert)

    def test_tpp_renew_without_key_reuse(self):
        renew_without_key_reuse(self, self.tpp_conn, self.tpp_zone)

    def test_tpp_enroll_ecdsa(self):
        cn = randomword(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone_ecdsa, cn, TEST_KEY_ECDSA[0], TEST_KEY_ECDSA[1])

    def test_tpp_enroll_with_custom_key(self):
        cn = randomword(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone, cn, TEST_KEY_RSA_4096[0], TEST_KEY_RSA_4096[1])

    def test_tpp_enroll_with_encrypted_key(self):
        cn = randomword(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone, cn, TEST_KEY_RSA_2048_ENCRYPTED[0], TEST_KEY_RSA_2048_ENCRYPTED[1], 'venafi')

    def test_tpp_enroll_with_custom_csr(self):
        key = open("/tmp/csr-test.key.pem").read()
        csr = open("/tmp/csr-test.csr.csr").read()
        enroll(self.tpp_conn, self.tpp_zone, private_key=key, csr=csr)

    def test_tpp_enroll_with_zone_update_and_custom_origin(self):
        cn = randomword(10) + ".venafi.example.com"
        cert, cert_guid = enroll_with_zone_update(self.tpp_conn, self.tpp_zone_ecdsa, cn)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config["Origin"], "Python-SDK ECDSA")
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        key = cert.public_key()
        self.assertEqual(key.curve.name, "secp521r1")

    def test_tpp_read_zone_config(self):
        zone = self.tpp_conn.read_zone_conf(self.tpp_zone)
        self.assertEqual(zone.country.value, "US")
        self.assertEqual(zone.province.value, "Utah")
        self.assertEqual(zone.locality.value, "Salt Lake")
        self.assertEqual(zone.organization.value, "Venafi Inc.")
        self.assertEqual(zone.organizational_unit.value, ["Integrations"])
        self.assertEqual(zone.key_type.key_type, KeyType.RSA)
        self.assertEqual(zone.key_type.option, 2048)

    def test_tpp_read_zone_unknown_zone(self):
        with self.assertRaises(Exception):
            self.tpp_conn.read_zone_conf("fdsfsd")

    def test_tpp_retrieve_non_issued(self):
        with self.assertRaises(Exception):
            self.tpp_conn.retrieve_cert(self.tpp_zone + "\\devops\\vcert\\test-non-issued.example.com")

    def test_tpp_search_by_thumbpint(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(),  default_backend())
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        found = self.tpp_conn.search_by_thumbprint(fingerprint)
        self.assertEqual(found, req.id)

    def test_revoke_not_issued(self):
        req = RevocationRequest(req_id=self.tpp_zone + '\\not-issued.example.com')
        with self.assertRaises(Exception):
            self.tpp_conn.revoke_cert(req)
        req = RevocationRequest(thumbprint="2b25ff9f8725dfee37c6a7adcba31897b12e921d")
        with self.assertRaises(Exception):
            self.tpp_conn.revoke_cert(req)
        req = RevocationRequest()
        with self.assertRaises(Exception):
            self.tpp_conn.revoke_cert(req)

    def test_revoke_normal(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        rev_req = RevocationRequest(req_id=req.id)
        self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        with self.assertRaises(Exception):
            self.tpp_conn.renew_cert(req)

    def test_revoke_without_disable(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        rev_req = RevocationRequest(req_id=req.id, disable=False)
        self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        self.tpp_conn.renew_cert(req)

    def test_revoke_normal_thumbprint(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(),default_backend())
        thumbprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        rev_req = RevocationRequest(thumbprint=thumbprint)
        self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        with self.assertRaises(Exception):
            self.tpp_conn.renew_cert(req)


class TestTPPTokenMethods(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_zone_ecdsa = environ['TPP_ZONE_ECDSA']
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, user=USER, password=PASSWORD,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestTPPTokenMethods, self).__init__(*args, **kwargs)

    def test_tpp_token_enroll(self):
        cn = randomword(10) + ".venafi.example.com"
        try:
            cert_id, pkey, cert, _, cert_guid = enroll(self.tpp_conn, self.tpp_zone, cn)
            cert_config = self.tpp_conn._get_certificate_details(cert_guid)
            self.assertEqual(cert_config["Origin"], "Venafi VCert-Python")
        except Exception as err:
            self.fail("Error in test: %s" % err.__str__)

    def test_tpp_token_enroll_with_custom_fields(self):
        cn = randomword(10) + ".venafi.example.com"
        custom_fields = [
            CustomField(name="custom", value="pythonTest"),
            CustomField(name="cfList", value="item2"),
            CustomField(name="cfListMulti", value="tier1"),
            CustomField(name="cfListMulti", value="tier4")
        ]
        try:
            cert_id, pkey, cert, _, cert_guid = enroll(conn=self.tpp_conn, zone=self.tpp_zone, cn=cn, custom_fields=custom_fields)
            cert_config = self.tpp_conn._get_certificate_details(cert_guid)
            self.assertEqual(cert_config["Origin"], "Venafi VCert-Python")
        except Exception as err:
            self.fail("Error in test: %s" % err.__str__)

    def test_tpp_token_enroll_origin(self):
        cn = randomword(10) + ".venafi.example.com"
        try:
            cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        except Exception as err:
            self.fail("Error in test: %s" %err.__str__())

    def test_tpp_token_renew(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        cert = renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)

    def test_tpp_token_renew_twice(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        time.sleep(5)
        renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)
        time.sleep(5)
        renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)

    def test_tpp_token_renew_by_thumbprint(self):
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        renew_by_thumbprint(self.tpp_conn, cert)

    def test_tpp_token_renew_without_key_reuse(self):
        renew_without_key_reuse(self, self.tpp_conn, self.tpp_zone)

    def test_tpp_token_enroll_ecdsa(self):
        cn = randomword(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone_ecdsa, cn, TEST_KEY_ECDSA[0], TEST_KEY_ECDSA[1])

    def test_tpp_token_enroll_with_custom_key(self):
        cn = randomword(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone, cn, TEST_KEY_RSA_4096[0], TEST_KEY_RSA_4096[1])

    def test_tpp_token_enroll_with_encrypted_key(self):
        cn = randomword(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone, cn, TEST_KEY_RSA_2048_ENCRYPTED[0], TEST_KEY_RSA_2048_ENCRYPTED[1], 'venafi')

    def test_tpp_token_enroll_with_custom_csr(self):
        key = open("/tmp/csr-test.key.pem").read()
        csr = open("/tmp/csr-test.csr.csr").read()
        enroll(self.tpp_conn, self.tpp_zone, private_key=key, csr=csr)

    def test_tpp_token_enroll_with_zone_update_and_custom_origin(self):
        cn = randomword(10) + ".venafi.example.com"
        cert, cert_guid = enroll_with_zone_update(self.tpp_conn, self.tpp_zone_ecdsa, cn)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config["Origin"], "Python-SDK ECDSA")
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        key = cert.public_key()
        self.assertEqual(key.curve.name, "secp521r1")

    def test_tpp_token_read_zone_config(self):
        zone = self.tpp_conn.read_zone_conf(self.tpp_zone)
        self.assertEqual(zone.country.value, "US")
        self.assertEqual(zone.province.value, "Utah")
        self.assertEqual(zone.locality.value, "Salt Lake")
        self.assertEqual(zone.organization.value, "Venafi Inc.")
        self.assertEqual(zone.organizational_unit.value, ["Integrations"])
        self.assertEqual(zone.key_type.key_type, KeyType.RSA)
        self.assertEqual(zone.key_type.option, 2048)

    def test_tpp_token_read_zone_unknown_zone(self):
        with self.assertRaises(Exception):
            self.tpp_conn.read_zone_conf("fdsfsd")

    def test_tpp_token_retrieve_non_issued(self):
        with self.assertRaises(Exception):
            self.tpp_conn.retrieve_cert(self.tpp_zone + "\\devops\\vcert\\test-non-issued.example.com")

    def test_tpp_token_search_by_thumbprint(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(),  default_backend())
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        found = self.tpp_conn.search_by_thumbprint(fingerprint)
        self.assertEqual(found, req.id)

    def test_token_revoke_not_issued(self):
        req = RevocationRequest(req_id=self.tpp_zone + '\\not-issued.example.com')
        with self.assertRaises(Exception):
            self.tpp_conn.revoke_cert(req)
        req = RevocationRequest(thumbprint="2b25ff9f8725dfee37c6a7adcba31897b12e921d")
        with self.assertRaises(Exception):
            self.tpp_conn.revoke_cert(req)
        req = RevocationRequest()
        with self.assertRaises(Exception):
            self.tpp_conn.revoke_cert(req)

    def test_token_revoke_normal(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        rev_req = RevocationRequest(req_id=req.id)
        self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        with self.assertRaises(Exception):
            self.tpp_conn.renew_cert(req)

    def test_token_revoke_without_disable(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        rev_req = RevocationRequest(req_id=req.id, disable=False)
        self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        self.tpp_conn.renew_cert(req)

    def test_token_revoke_normal_thumbprint(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(),default_backend())
        thumbprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        rev_req = RevocationRequest(thumbprint=thumbprint)
        self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        with self.assertRaises(Exception):
            self.tpp_conn.renew_cert(req)


class TestTPPTokenAccess(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = environ['TPP_ZONE']
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, user=USER, password=PASSWORD,
                                           http_request_kwargs={"verify": "/tmp/chain.pem"})
        super(TestTPPTokenAccess, self).__init__(*args, **kwargs)

    def test_get_access_token(self):
        try:
            token_info = self.tpp_conn.get_access_token()
            self.assertIsNotNone(token_info)
            self.assertIsNotNone(token_info.access_token)
            self.assertIsNotNone(token_info.refresh_token)
            self.assertIsNotNone(token_info.expires)
        except ClientBadData:
            self.fail("Error in Test Data")
        except ServerUnexptedBehavior as sub:
            self.fail("Error from server: %s" % sub.__str__())

    def test_refresh_access_token(self):
        try:
            self.tpp_conn.get_access_token()
            refresh_info = self.tpp_conn.refresh_access_token()
            self.assertIsNotNone(refresh_info)
            self.assertIsNotNone(refresh_info.access_token)
            self.assertIsNotNone(refresh_info.refresh_token)
            self.assertIsNotNone(refresh_info.expires)
        except ClientBadData:
            self.fail("Error in Test Data")
        except ServerUnexptedBehavior as sub:
            self.fail("Error from server: %s" % sub.__str__())

    def test_revoke_access_token(self):
        try:
            self.tpp_conn.get_access_token()
            status, resp = self.tpp_conn.revoke_access_token()
            self.assertEqual(status, 200)
        except Exception as err:
            self.fail("Error happened: %s" % err.__str__())

        cn = randomword(10) + ".venafi.example.com"
        with self.assertRaises(Exception):
            enroll(self.tpp_conn, self.tpp_zone, cn)


def simple_enroll(conn,  zone):
    req = CertificateRequest(common_name=randomword(12) + ".venafi.example.com")
    conn.request_cert(req, zone)
    t = time.time()
    while time.time() - t < 300:
        cert = conn.retrieve_cert(req)
        if cert:
            break
        else:
            time.sleep(5)
    return req, cert


def renew_without_key_reuse(unittest_object, conn, zone):
    cn = randomword(10) + ".venafi.example.com"
    cert_id, pkey, _, public_key, _ = enroll(conn, zone, cn)
    time.sleep(5)
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
    unittest_object.assertNotEqual(public_key_new, public_key)


def enroll_with_zone_update(conn, zone, cn=None):
    request = CertificateRequest(common_name=cn, origin="Python-SDK ECDSA")
    zc = conn.read_zone_conf(zone)
    request.update_from_zone_config(zc)
    conn.request_cert(request, zone)
    while True:
        cert = conn.retrieve_cert(request)
        if cert:
            break
        else:
            time.sleep(5)
    return cert, request.cert_guid


def enroll(conn, zone, cn=None, private_key=None, public_key=None, password=None, csr=None, custom_fields=None):
    request = CertificateRequest(
        common_name=cn,
        private_key=private_key,
        key_password=password,
    )

    if custom_fields:
        request.custom_fields = custom_fields

    request.san_dns = ["www.client.venafi.example.com", "ww1.client.venafi.example.com"]
    if isinstance(conn, (FakeConnection, TPPConnection, TPPTokenConnection)):
        request.email_addresses = ["e1@venafi.example.com", "e2@venafi.example.com"]
        request.ip_addresses = ["127.0.0.1", "192.168.1.1"]
        request.user_principal_names = ["e1@venafi.example.com", "e2@venafi.example.com"]
        request.uniform_resource_identifiers = ["https://www.venafi.com","https://venafi.cloud"]

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
    return request.id, request.private_key_pem, cert, cert_public_key_pem, request.cert_guid


def renew(conn, cert_id, pkey, sn, cn):
    print("Trying to renew certificate")
    new_request = CertificateRequest(
        cert_id=cert_id,
    )
    conn.renew_cert(new_request, reuse_key=False)
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
    # assert private_key_public_key_pem == public_key_pem
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

    def test_parse_tpp_policy1(self):
        conn = TPPConnection(url="http://example.com/", user="", password="")
        raw_data = json.loads(POLICY_TPP1)
        p = conn._parse_zone_config_to_policy(raw_data)
        self.assertEqual(len(p.key_types), 7)
        raw_data['Policy']['KeyPair']['KeySize']['Locked'] = True
        p = conn._parse_zone_config_to_policy(raw_data)
        self.assertEqual(len(p.key_types), 4)
        raw_data['Policy']['KeyPair']['KeyAlgorithm']['Locked'] = True
        p = conn._parse_zone_config_to_policy(raw_data)
        self.assertEqual(len(p.key_types), 1)

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

    def test_generate_rsa_csr(self):
        req = CertificateRequest(common_name="test.example.com", key_type=KeyType("rsa", 2048))
        req.build_csr()
        req = x509.load_pem_x509_csr(req.csr.encode(), default_backend())
        self.assertEqual(req.public_key().key_size, 2048)

    def test_generate_ecdsa_csr(self):
        req = CertificateRequest(common_name="test.exampe.com", key_type=KeyType("ecdsa", "p384"))
        req.build_csr()
        req = x509.load_pem_x509_csr(req.csr.encode(), default_backend())
        self.assertEqual(req.public_key().curve.name, "secp384r1")

    def test_generate_rsa_key(self):
        req = CertificateRequest(common_name="test.example.com", key_type=KeyType("rsa", 2048))
        req._gen_key()
        self.assertEqual(req.public_key.key_size, 2048)

    def test_generate_ecdsa_key(self):
        req = CertificateRequest(common_name="test.exampe.com", key_type=KeyType("ecdsa", "p384"))
        req._gen_key()
        self.assertEqual(req.public_key.curve.name, "secp384r1")

    def test_parse_key_arguments(self):
        k = KeyType("rsa", 2048)
        self.assertEqual(k.key_type, k.RSA)
        self.assertEqual(k.option, 2048)
        k = KeyType("Rsa", 4096)
        self.assertEqual(k.key_type, k.RSA)
        self.assertEqual(k.option, 4096)
        k = KeyType("ecdsa", "secp256r1")
        self.assertEqual(k.key_type, k.ECDSA)
        self.assertEqual(k.option, "p256")
        with self.assertRaises(Exception):
            k = KeyType("ololo", 2048)
        with self.assertRaises(Exception):
            k = KeyType("ecdsa", 2048)
        with self.assertRaises(Exception):
            k = KeyType("ecdsa", "secp256k1")
        with self.assertRaises(Exception):
            k = KeyType("rsa", "")
        with self.assertRaises(Exception):
            k = KeyType("rsa", 1024)
        with self.assertRaises(Exception):
            k = KeyType("rsa", None)

    def test_pass_invalid_key_type_to_request(self):
        with self.assertRaises(Exception):
            req = CertificateRequest(common_name="test.example.com", key_type="rsa")

    def test_return_pem_private_key(self):
        req = CertificateRequest(common_name="test.example.com", key_password="ololo")
        req.build_csr()
        self.assertIn("ENCRYPTED", req.private_key_pem)
        req = CertificateRequest(common_name="test.example.com")
        req.build_csr()
        self.assertNotIn("ENCRYPTED", req.private_key_pem)

    def test_return_pem_csr(self):
        req = CertificateRequest(common_name="test.example.com")
        req.build_csr()
        self.assertIn("CERTIFICATE REQUEST", req.csr)

    def test_return_pem_cert(self):
        conn = FakeConnection()
        req = CertificateRequest(common_name="test.example.com")
        conn.request_cert(req, "")
        cert = conn.retrieve_cert(req)
        self.assertIn("BEGIN CERTIFICATE", cert.cert)

    def test_tpp_url_noramlization(self):
        conn = TPPConnection(url="localhost", user="user", password="password")
        self.assertEqual(conn._base_url, "https://localhost/vedsdk/")
        conn._base_url = "http://localhost:8080"
        self.assertEqual(conn._base_url, "https://localhost:8080/vedsdk/")
        conn._base_url = "http://localhost:8080/"
        self.assertEqual(conn._base_url, "https://localhost:8080/vedsdk/")
        with self.assertRaises(Exception):
            conn._base_url = "ftp://example.com"
        with self.assertRaises(Exception):
            conn._base_url = ""
        with self.assertRaises(Exception):
            conn._base_url = "https://"

    def test_parse_pem_chain(self):
        cert = parse_pem(EXAMPLE_CHAIN, "last")
        self.assertEqual(len(cert.chain), 2)
        self.assertIn("PRIVATE", cert.key)
        c = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        for a in c.subject:
            if a.oid == x509.NameOID.COMMON_NAME:
                subject = a.value
        self.assertEqual(subject, "test2.example.com")
