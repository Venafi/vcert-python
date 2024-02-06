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
import binascii
import logging
import time
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from assets import TEST_KEY_ECDSA, TEST_KEY_RSA_4096, TEST_KEY_RSA_2048_ENCRYPTED
from test_env import TPP_PASSWORD, TPP_USER, TPP_URL, TPP_ZONE, TPP_ZONE_ECDSA
from test_utils import enroll, enroll_with_zone_update, random_word, renew, renew_by_thumbprint, \
    renew_without_key_reuse, simple_enroll
from vcert import TPPConnection, FakeConnection, RevocationRequest, KeyType, CustomField

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)


class TestFakeMethods(unittest.TestCase):
    def test_fake_enroll(self):
        conn = FakeConnection()
        zone = "Default"
        cn = f"{random_word(10)}.venafi.example.com"
        enroll(conn, zone, cn)


class TestTPPMethods(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = TPP_ZONE
        self.tpp_zone_ecdsa = TPP_ZONE_ECDSA
        self.tpp_conn = TPPConnection(TPP_USER, TPP_PASSWORD, TPP_URL, http_request_kwargs={'verify': "/tmp/chain.pem"})
        super(TestTPPMethods, self).__init__(*args, **kwargs)

    def test_tpp_enroll(self):
        cn = f"{random_word(10)}.venafi.example.com"
        _, pkey, cert, _, cert_guid = enroll(self.tpp_conn, self.tpp_zone, cn)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config['Origin'], "Venafi VCert-Python")

    def test_tpp_enroll_with_custom_fields(self):
        cn = random_word(10) + ".venafi.example.com"
        custom_fields = [
            CustomField(name="custom", value="pythonTest"),
            CustomField(name="cfList", value="item2"),
            CustomField(name="cfListMulti", value="tier1"),
            CustomField(name="cfListMulti", value="tier4")
        ]
        cert_id, pkey, cert, _, cert_guid = enroll(conn=self.tpp_conn, zone=self.tpp_zone, cn=cn,
                                                   custom_fields=custom_fields)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config["Origin"], "Venafi VCert-Python")

    def test_tpp_enroll_origin(self):
        cn = random_word(10) + ".venafi.example.com"
        _, pkey, cert, _, cert_guid = enroll(self.tpp_conn, self.tpp_zone, cn)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config["Origin"], "Venafi VCert-Python")

    def test_tpp_renew(self):
        cn = random_word(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        cert = renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)

    def test_tpp_renew_twice(self):
        cn = random_word(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        time.sleep(5)
        renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)
        time.sleep(5)
        renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)

    def test_tpp_renew_by_thumbprint(self):
        cn = random_word(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        renew_by_thumbprint(self.tpp_conn, cert)

    def test_tpp_renew_without_key_reuse(self):
        renew_without_key_reuse(self, self.tpp_conn, self.tpp_zone)

    def test_tpp_enroll_ecdsa(self):
        cn = random_word(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone_ecdsa, cn, TEST_KEY_ECDSA[0], TEST_KEY_ECDSA[1])

    def test_tpp_enroll_with_custom_key(self):
        cn = random_word(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone, cn, TEST_KEY_RSA_4096[0], TEST_KEY_RSA_4096[1])

    def test_tpp_enroll_with_encrypted_key(self):
        cn = random_word(10) + ".venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone, cn, TEST_KEY_RSA_2048_ENCRYPTED[0], TEST_KEY_RSA_2048_ENCRYPTED[1],
               'venafi')

    def test_tpp_enroll_with_custom_csr(self):
        key = open("/tmp/csr-test.key.pem").read()
        csr = open("/tmp/csr-test.csr.csr").read()
        enroll(self.tpp_conn, self.tpp_zone, private_key=key, csr=csr)

    def test_tpp_enroll_with_zone_update_and_custom_origin(self):
        cn = random_word(10) + ".venafi.example.com"
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

    def test_tpp_search_by_thumbprint(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
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
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        thumbprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        rev_req = RevocationRequest(thumbprint=thumbprint)
        self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        with self.assertRaises(Exception):
            self.tpp_conn.renew_cert(req)
