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

from test_env import CLOUD_ZONE, CLOUD_APIKEY, CLOUD_URL
from test_utils import random_word, enroll, renew, renew_by_thumbprint, renew_without_key_reuse, simple_enroll
from vcert import CloudConnection, KeyType, CertificateRequest, CustomField, logger

log = logger.get_child("test-vaas")


class TestCloudMethods(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.cloud_zone = CLOUD_ZONE
        self.cloud_conn = CloudConnection(token=CLOUD_APIKEY, url=CLOUD_URL)
        super(TestCloudMethods, self).__init__(*args, **kwargs)

    def test_cloud_enroll(self):
        cn = random_word(10) + ".venafi.example.com"
        enroll(self.cloud_conn, self.cloud_zone, cn)

    def test_cloud_enroll_with_custom_csr(self):
        key = open("/tmp/csr-test.key.pem").read()
        csr = open("/tmp/csr-test.csr.csr").read()
        enroll(self.cloud_conn, self.cloud_zone, private_key=key, csr=csr)

    def test_cloud_renew(self):
        cn = random_word(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.cloud_conn, self.cloud_zone, cn)
        time.sleep(5)
        renew(self.cloud_conn, cert_id, pkey, cert.serial_number, cn)

    def test_cloud_renew_twice(self):
        cn = random_word(10) + ".venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.cloud_conn, self.cloud_zone, cn)

        new_cert = renew(self.cloud_conn, cert_id, pkey, cert.serial_number, cn)
        fingerprint = binascii.hexlify(new_cert.fingerprint(hashes.SHA1())).decode()
        found_cert = self.cloud_conn.search_by_thumbprint(thumbprint=fingerprint)

        renew(self.cloud_conn, found_cert.csrId, pkey, new_cert.serial_number, cn)

    def test_cloud_renew_by_thumbprint(self):
        cn = random_word(10) + ".venafi.example.com"
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
        self.assertListEqual(p.SubjectCNRegexes, ['.*'])
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

    def test_cloud_search_by_thumbprint(self):
        req, cert = simple_enroll(self.cloud_conn, self.cloud_zone)
        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        time.sleep(1)
        found = self.cloud_conn.search_by_thumbprint(fingerprint)
        self.assertEqual(found.certificateIds[0], req.cert_guid)

    def test_cloud_enroll_valid_hours(self):
        cn = random_word(10) + ".venafi.example.com"
        request = CertificateRequest(common_name=cn)
        request.san_dns = [u"www.client.venafi.example.com", u"ww1.client.venafi.example.com"]
        custom_fields = [
            CustomField(name="custom", value="pythonTest"),
            CustomField(name="cfList", value="item2"),
            CustomField(name="cfListMulti", value="tier1"),
            CustomField(name="cfListMulti", value="tier4")
        ]
        request.custom_fields = custom_fields
        request.validity_hours = 144
        expected_date = datetime.utcnow() + timedelta(hours=request.validity_hours)

        self.cloud_conn.request_cert(request, self.cloud_zone)
        cert = self.cloud_conn.retrieve_cert(request)

        cert = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        assert isinstance(cert, x509.Certificate)
        expiration_date = cert.not_valid_after
        # Due to some roundings and delays in operations on the server side, the certificate expiration date
        # is not exactly the same as the one used in the request. A gap is allowed in this scenario to compensate
        # this delays and roundings.
        delta = timedelta(seconds=60)
        date_format = "%Y-%m-%d %H:%M:%S"
        self.assertAlmostEqual(expected_date, expiration_date, delta=delta,
                               msg="Delta between expected and expiration date is too big.\nExpected: %s\nGot: %s\n"
                                   "Expected_delta: %s seconds."
                                   % (expected_date.strftime(date_format), expiration_date.strftime(date_format),
                                      delta.total_seconds()))
