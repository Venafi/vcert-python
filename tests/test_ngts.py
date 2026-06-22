#!/usr/bin/env python3
#
# Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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
# Live tests for the NGTS (Palo Alto Networks Next-Gen Trust Security) connector.
# These hit a live backend and are skipped unless the NGTS_* credentials are present in the
# environment (see tests/test_env.py).
#
import binascii
import time
import unittest

from cryptography.hazmat.primitives import hashes

from test_env import (NGTS_URL, NGTS_TOKEN_URL, NGTS_CLIENT_ID, NGTS_CLIENT_SECRET, NGTS_TSG_ID, NGTS_SCOPE,
                      NGTS_ZONE)
from test_utils import random_word, enroll, renew, renew_by_thumbprint
from vcert import NGTSConnection, KeyType, logger
from vcert.common import RetireRequest

log = logger.get_child("test-ngts")

_HAS_CREDS = all([NGTS_URL, NGTS_TOKEN_URL, NGTS_CLIENT_ID, NGTS_CLIENT_SECRET, NGTS_ZONE]) \
    and (NGTS_TSG_ID or NGTS_SCOPE)


@unittest.skipUnless(_HAS_CREDS, "NGTS_* credentials are not set; skipping live NGTS tests")
class TestNGTSMethods(unittest.TestCase):
    def setUp(self):
        # Built in setUp (not __init__) so collecting this module without NGTS_* creds does not
        # try to construct a connection - the class is skipped before setUp runs.
        self.ngts_zone = NGTS_ZONE
        self.ngts_conn = NGTSConnection(client_id=NGTS_CLIENT_ID, client_secret=NGTS_CLIENT_SECRET,
                                        token_url=NGTS_TOKEN_URL, scope=NGTS_SCOPE, tsg_id=NGTS_TSG_ID, url=NGTS_URL)

    def test_ngts_auth(self):
        token = self.ngts_conn.auth()
        self.assertTrue(token)
        self.assertIsNotNone(self.ngts_conn._token_expires)

    def test_ngts_enroll(self):
        cn = f"{random_word(10)}.venafi.example.com"
        enroll(self.ngts_conn, self.ngts_zone, cn)

    def test_ngts_renew(self):
        cn = f"{random_word(10)}.venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.ngts_conn, self.ngts_zone, cn)
        time.sleep(5)
        renew(self.ngts_conn, cert_id, pkey, cert.serial_number, cn)

    def test_ngts_renew_by_thumbprint(self):
        cn = f"{random_word(10)}.venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.ngts_conn, self.ngts_zone, cn)
        time.sleep(5)
        renew_by_thumbprint(self.ngts_conn, cert)

    def test_ngts_retire_by_thumbprint(self):
        cn = f"{random_word(10)}.venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.ngts_conn, self.ngts_zone, cn)
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        ret_request = RetireRequest(thumbprint=fingerprint)
        self.assertTrue(self.ngts_conn.retire_cert(ret_request))

    def test_ngts_read_zone_config(self):
        zone = self.ngts_conn.read_zone_conf(self.ngts_zone)
        self.assertIsNotNone(zone.policy)
        self.assertTrue(len(zone.policy.key_types) > 0)

    def test_ngts_read_zone_invalid_zone(self):
        with self.assertRaises(Exception):
            self.ngts_conn.read_zone_conf(f"non-existent-cit-{random_word(8)}")


if __name__ == '__main__':
    unittest.main()
