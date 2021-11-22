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
from cryptography.x509.oid import NameOID

from test_env import CLOUD_ZONE, CLOUD_APIKEY, CLOUD_URL, RANDOM_DOMAIN
from test_utils import random_word, enroll, renew, renew_by_thumbprint, renew_without_key_reuse, simple_enroll
from vcert import CloudConnection, KeyType, CertificateRequest, CustomField, logger, CSR_ORIGIN_SERVICE
from vcert.pem import pkcs8_to_pem_private_key

log = logger.get_child("test-vaas")

p8_key = """
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIPLsOsD8egf4CAicQ
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCGU0yCgxPiFpL/l+F5/wmzBIIE
0B2QHY6GoIj204ovABzvhgu6DPt3qvMtxWUhparQoOirf6IWpgPs5yIEVYzm33vb
I0yWb4DTTLQc0k+s1e1whDkhEDyeZ0GGHzHu2LHnsLLUKbUW9wsod9GlQ61IACnr
i8ehxgAAyYAB/PIcwpuF+nzyRHx9bud/916DYQ7Y/DWmCpSHB1/O9vkY1RZJjOqc
XrmzVqL+FBWjPzXk5FfWkRoVIUWsB/yWaP4ZYb5o8xgcAvvyXeofhum9vmiRlRB+
ii6SH7lgFE7BL1qZPnNCjFeBbDv9OryR1h3FbGnNaKJGOrlA1sirg0lMyi2zsaBe
M0B8y8AVnU8q5JnToIFFo4BnimK7jXPspQ/opu9IaZDWKf3wbwUiC+IfytlelVpT
lMTLvYPPypsjqhInDRrPbdlmx1WN9bfHdkwzRm3x4UuAKTcQKX/5s8AdNDTRx4Kv
UZ2wLylEQcCWYWm3m+YL0PcsnUX301dmKHGG0ub/CwIFO1GYI9+Eb1azsS3h+fx7
Ec4rOzZ4Q5h1HWnV3P7CVqyq4hSqJ3f7DMThCgW0up2woCMZnZqQcg4+VUYH1oFg
YvrCV0N4W9woHWS6v0HDhMAR9HadUAvDetljrp1ygiPGAe+giNF9AZ+7+MTVwT/M
YEcDzxCrKWQ57KdxnZL2cVELx0pihmqEs0jvh++YShszE39S/Pk58BqFLaS+/eAy
42fXlih2FE+Pj5dTrxY3wY759SOZy+AlHytd3PkYHvCd7qgYTCUo+y8Gd2tIVW2g
pwx59953QhCoyPFMvm97pkHi9IMLLoBobdngV2FKzj3lch1V8iujqNdA8W0Zny0S
6KQgSn6GvW/EVVVIckS41uoKxTJVnCNsI8jpBa4/bUvZzx8s6gDHSZqTFgh+jssu
8rI8nGRsFa3+ynoR3rFcaRFi733BjPHdCYlEYLxfPwhpQ5wYAU2NCMJbCkiakPSR
ywNbIhxJhdmhD8zbNifLaXUB/iFhbW4e+QcZZNo8im/ty0J3OSj9OqNIAAP8k7CV
MdQbI4yu09hDPKIw7YBS+R5pmOjiuQOL4mzeOb8MN4i4AHCUiH/K63pVDqkT1yNM
rIIFjljg1loosubHTU59vWKE/OPuY+BFviK49rw0xGyPdHECgkpS6/CPfzIEkr8U
RsNxRVW/fjTdSw3YaqlrTNEN6tLuddq2R/rMvyXlzhcGB2H81V8ZgJ4bqTgfUdH4
iAv49PCCIClPQYD4W1HzuSFlNwT4Cy29QgSjw0bHFmvmNvfInidBH5DoJeMovMsy
OROtIuCG0QZjfIcsreU7gcbUvwPNB+nQaDA3IA7fkYmE1xvj38YMIimDRWFKN5Q6
f67kAGgkFcBlKGh6J+iGNIMscGkRbPRlNHtefE/vaAMHNUBfNxuVk6ylf2Hj2YC9
gXSp4S0pq5RUvt8KPzeba0mtNlmuFSK9ZfOOu/eBIGvHwA7+HWG4ogTpER1IXbnE
ZzcdVwYponiGL/dtKZIyibxxEUOHjoM9XyoopE9wFq/kQXEgVDCFLdyPAxFS7WA+
NRqtgX8X41i/zQ72ZvM+bHrq2gk2OnDJ4jyDTBLBQezdOX4rLrWvzIcqh7hmWC1L
KrcsYl3EZcK4zmMgSTTCgEJGKJsgClqUh6TS7atxgIjr
-----END ENCRYPTED PRIVATE KEY-----
"""


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

    def test_cloud_enroll_service_generated_csr(self):
        cn = random_word(10) + ".venafi.example.com"
        password = 'FooBarPass123'

        request = CertificateRequest(
            common_name=cn,
            key_password=password,
            country='US'
        )

        request.san_dns = ["www.client.venafi.example.com", "ww1.client.venafi.example.com"]
        request.csr_origin = CSR_ORIGIN_SERVICE

        self.cloud_conn.request_cert(request, self.cloud_zone)
        cert_object = self.cloud_conn.retrieve_cert(request)

        cert = x509.load_pem_x509_certificate(cert_object.cert.encode(), default_backend())
        assert isinstance(cert, x509.Certificate)
        t1 = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        t2 = [
            x509.NameAttribute(
                NameOID.COMMON_NAME, cn or RANDOM_DOMAIN
            )
        ]
        assert t1 == t2

        output = cert_object.as_pkcs12('FooBarPass123')
        log.info("PKCS12 created successfully:\n%s" % output)

    def test_cloud_parse_key_p8_to_p12(self):
        passphrase = 'FooBarPass123'
        pem_pk = pkcs8_to_pem_private_key(self.p8_key, passphrase)
        log.info("PEM Private Key is: %s" % pem_pk)
