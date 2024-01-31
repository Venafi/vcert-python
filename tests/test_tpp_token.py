#!/usr/bin/env python3
#
# Copyright 2021 Venafi, Inc.
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
import time
import unittest
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from assets import TEST_KEY_ECDSA, TEST_KEY_RSA_4096, TEST_KEY_RSA_2048_ENCRYPTED
from test_env import TPP_ZONE, TPP_ZONE_ECDSA, TPP_USER, TPP_PASSWORD, TPP_TOKEN_URL
from test_utils import (random_word, enroll, renew, renew_by_thumbprint, renew_without_key_reuse,
                        enroll_with_zone_update, simple_enroll, retire_by_id, retire_by_thumbprint)
from vcert import (CustomField, KeyType, RevocationRequest, CertificateRequest, IssuerHint, logger, TPPTokenConnection)
from vcert.errors import ClientBadData, ServerUnexptedBehavior

log = logger.get_child("test-tpp-token")


class TestTPPTokenMethods(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_zone = TPP_ZONE
        self.tpp_zone_ecdsa = TPP_ZONE_ECDSA
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, user=TPP_USER, password=TPP_PASSWORD,
                                           http_request_kwargs={'verify': "/tmp/chain.pem"})
        super(TestTPPTokenMethods, self).__init__(*args, **kwargs)

    def test_tpp_token_enroll(self):
        cn = f"{random_word(10)}.venafi.example.com"
        try:
            cert_id, pkey, cert, _, cert_guid = enroll(self.tpp_conn, self.tpp_zone, cn)
            cert_config = self.tpp_conn._get_certificate_details(cert_guid)
            self.assertEqual(cert_config['Origin'], "Venafi VCert-Python")
        except Exception as err:
            self.fail(f"Error in test: {err.message}")

    def test_tpp_token_enroll_with_service_generated_csr(self):
        cn = f"{random_word(10)}.venafi.example.com"
        try:
            _, _, _, _, cert_guid = enroll(self.tpp_conn, self.tpp_zone, cn=cn, password="FooBarPass123",
                                           service_generated_csr=True)
            cert_config = self.tpp_conn._get_certificate_details(cert_guid)
            self.assertEqual(cert_config['Origin'], "Venafi VCert-Python")
        except Exception as err:
            self.fail(f"Error in test: {err.message}")

    def test_tpp_token_enroll_with_custom_fields(self):
        cn = f"{random_word(10)}.venafi.example.com"
        custom_fields = [
            CustomField(name="custom", value="pythonTest"),
            CustomField(name="cfList", value="item2"),
            CustomField(name="cfListMulti", value="tier1"),
            CustomField(name="cfListMulti", value="tier4")
        ]
        try:
            cert_id, pkey, cert, _, cert_guid = enroll(conn=self.tpp_conn, zone=self.tpp_zone, cn=cn,
                                                       custom_fields=custom_fields)
            cert_config = self.tpp_conn._get_certificate_details(cert_guid)
            self.assertEqual(cert_config['Origin'], "Venafi VCert-Python")
        except Exception as err:
            self.fail(f"Error in test: {err.__str__}")

    def test_tpp_token_enroll_origin(self):
        cn = f"{random_word(10)}.venafi.example.com"
        try:
            cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        except Exception as err:
            self.fail(f"Error in test: {err.__str__()}")

    def test_tpp_token_renew(self):
        cn = f"{random_word(10)}.venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        cert = renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)

    def test_tpp_token_renew_twice(self):
        cn = f"{random_word(10)}.venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        time.sleep(5)
        renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)
        time.sleep(5)
        renew(self.tpp_conn, cert_id, pkey, cert.serial_number, cn)

    def test_tpp_token_renew_by_thumbprint(self):
        cn = f"{random_word(10)}.venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.tpp_conn, self.tpp_zone, cn)
        renew_by_thumbprint(self.tpp_conn, cert)

    def test_tpp_token_renew_without_key_reuse(self):
        renew_without_key_reuse(self, self.tpp_conn, self.tpp_zone)

    def test_tpp_token_enroll_ecdsa(self):
        cn = f"{random_word(10)}.venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone_ecdsa, cn, TEST_KEY_ECDSA[0], TEST_KEY_ECDSA[1])

    def test_tpp_token_enroll_with_custom_key(self):
        cn = f"{random_word(10)}.venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone, cn, TEST_KEY_RSA_4096[0], TEST_KEY_RSA_4096[1])

    def test_tpp_token_enroll_with_encrypted_key(self):
        cn = f"{random_word(10)}.venafi.example.com"
        enroll(self.tpp_conn, self.tpp_zone, cn, TEST_KEY_RSA_2048_ENCRYPTED[0], TEST_KEY_RSA_2048_ENCRYPTED[1],
               'venafi')

    def test_tpp_token_enroll_with_custom_csr(self):
        key = open("/tmp/csr-test.key.pem").read()
        csr = open("/tmp/csr-test.csr.csr").read()
        enroll(self.tpp_conn, self.tpp_zone, private_key=key, csr=csr)

    def test_tpp_token_enroll_with_zone_update_and_custom_origin(self):
        cn = f"{random_word(10)}.venafi.example.com"
        cert, cert_guid = enroll_with_zone_update(self.tpp_conn, self.tpp_zone_ecdsa, cn)
        cert_config = self.tpp_conn._get_certificate_details(cert_guid)
        self.assertEqual(cert_config['Origin'], "Python-SDK ECDSA")
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
            self.tpp_conn.retrieve_cert(f"{self.tpp_zone}\\devops\\vcert\\test-non-issued.example.com")

    def test_tpp_token_search_by_thumbprint(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        found = self.tpp_conn.search_by_thumbprint(fingerprint)
        self.assertEqual(found, req.id)

    def test_token_revoke_not_issued(self):
        req = RevocationRequest(req_id=f"{self.tpp_zone}\\not-issued.example.com")
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
        revoke_data = self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        assert revoke_data['Success'] is True


    def test_token_revoke_without_disable(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        rev_req = RevocationRequest(req_id=req.id, disable=False)
        revoke_data = self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        assert revoke_data['Success'] is True

    def test_token_revoke_normal_thumbprint(self):
        req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        thumbprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        rev_req = RevocationRequest(thumbprint=thumbprint)
        revoke_data = self.tpp_conn.revoke_cert(rev_req)
        time.sleep(1)
        assert revoke_data['Success'] is True

    def test_tpp_token_enroll_valid_hours(self):
        cn = f"{random_word(10)}.venafi.example.com"
        request = CertificateRequest(common_name=cn)

        request.san_dns = ["www.client.venafi.example.com", "ww1.client.venafi.example.com"]
        request.email_addresses = ["e1@venafi.example.com", "e2@venafi.example.com"]
        request.ip_addresses = ["127.0.0.1", u"192.168.1.1"]
        request.user_principal_names = ["e1@venafi.example.com", "e2@venafi.example.com"]
        request.uniform_resource_identifiers = ["https://www.venafi.com", "https://venafi.cloud"]

        custom_fields = [
            CustomField(name="custom", value="pythonTest"),
            CustomField(name="cfList", value="item2"),
            CustomField(name="cfListMulti", value="tier1"),
            CustomField(name="cfListMulti", value="tier4")
        ]

        request.custom_fields = custom_fields
        request.validity_hours = 144
        request.issuer_hint = IssuerHint.MICROSOFT
        expected_date = datetime.utcnow() + timedelta(hours=request.validity_hours)

        self.tpp_conn.request_cert(request, self.tpp_zone)
        cert = self.tpp_conn.retrieve_cert(request)

        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        assert isinstance(cert, x509.Certificate)
        expiration_date = cert.not_valid_after
        # Due to some roundings and delays in operations on the server side, the certificate expiration date
        # is not exactly the same as the one used in the request. A gap is allowed in this scenario to compensate
        # this delays and roundings.
        delta = timedelta(seconds=60)
        date_format = "%Y-%m-%d %H:%M:%S"
        self.assertAlmostEqual(expected_date, expiration_date, delta=delta,
                               msg=f"Delta between expected and expiration date is too big."
                                   f"\nExpected: {expected_date.strftime(date_format)}"
                                   f"\nGot: {expiration_date.strftime(date_format)}"
                                   f"\nExpected_delta: {delta.total_seconds()} seconds.")

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
            self.fail(f"Error from server: {sub.__str__()}")

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
            self.fail(f"Error from server: {sub.__str__()}")

    def test_revoke_access_token(self):
        try:
            self.tpp_conn.get_access_token()
            status, resp = self.tpp_conn.revoke_access_token()
            self.assertEqual(status, 200)
        except Exception as err:
            self.fail(f"Error happened: {err.__str__()}")

        cn = f"{random_word(10)}.venafi.example.com"
        with self.assertRaises(Exception):
            enroll(self.tpp_conn, self.tpp_zone, cn)

    def test_tpp_token_retire_cert_id(self):
        try:
            req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
            ret_data = retire_by_id(self.tpp_conn, req.id)
            assert ret_data['Success'] is True
        except Exception as err:
            self.fail(f"Error in tpp retire by id test: {err}")

    def test_tpp_token_retire_cert_thumbprint(self):
        try:
            req, cert = simple_enroll(self.tpp_conn, self.tpp_zone)
            cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
            ret_data = retire_by_thumbprint(self.tpp_conn, cert)
            assert ret_data['Success'] is True
        except Exception as err:
            self.fail(f"Error in tpp retire by thumbprint test: {err}")