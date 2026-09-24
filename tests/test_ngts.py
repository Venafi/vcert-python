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
                      NGTS_ZONE, NGTS_WORKSPACE)
from test_utils import random_word, enroll, renew, renew_by_thumbprint
from vcert import NGTSConnection, KeyType, logger, CertificateRevokeError
from vcert.common import RetireRequest, RevocationRequest
from vcert.policy.policy_spec import KeyPair, Policy, PolicySpecification

log = logger.get_child("test-ngts")

_HAS_CREDS = all([NGTS_URL, NGTS_TOKEN_URL, NGTS_CLIENT_ID, NGTS_CLIENT_SECRET, NGTS_ZONE]) \
    and (NGTS_TSG_ID or NGTS_SCOPE)


@unittest.skipUnless(_HAS_CREDS, "NGTS_* credentials are not set; skipping live NGTS tests")
class TestNGTSMethods(unittest.TestCase):
    def setUp(self):
        # Built in setUp (not __init__) so collecting this module without NGTS_* creds does not
        # try to construct a connection - the class is skipped before setUp runs.
        self.ngts_zone = NGTS_ZONE
        # NGTS_WORKSPACE is optional: unset, every call goes to the tenant's default workspace, so
        # the suite exercises both paths depending on the environment it runs in.
        self.ngts_conn = NGTSConnection(client_id=NGTS_CLIENT_ID, client_secret=NGTS_CLIENT_SECRET,
                                        token_url=NGTS_TOKEN_URL, scope=NGTS_SCOPE, tsg_id=NGTS_TSG_ID, url=NGTS_URL,
                                        workspace=NGTS_WORKSPACE)

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

    def test_ngts_revoke_by_thumbprint(self):
        # Cryptographic revocation via the GraphQL CA-operations mutation (thumbprint-keyed).
        # revoke_cert uppercases the thumbprint internally, so a lowercase hexlify is fine here.
        cn = f"{random_word(10)}.venafi.example.com"
        cert_id, pkey, cert, _, _ = enroll(self.ngts_conn, self.ngts_zone, cn)
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        rev_request = RevocationRequest(thumbprint=fingerprint)
        try:
            result = self.ngts_conn.revoke_cert(rev_request)
        except CertificateRevokeError as e:
            # The whole request path (GraphQL revokeCertificate via the CA-operations service) is
            # exercised end-to-end here. A tenant whose zone uses only the built-in CA gets back
            # "revocation is not supported for CA type BUILTIN_CA" from the backend - skip the
            # success assertion in that case (it needs a zone backed by a revocation-capable CA).
            if "not supported for CA type" in str(e) or "BUILTIN" in str(e).upper():
                self.skipTest(f"zone CA does not support revocation: {e}")
            raise
        self.assertIsNotNone(result)
        self.assertIn("status", result)

    def test_ngts_read_zone_config(self):
        zone = self.ngts_conn.read_zone_conf(self.ngts_zone)
        self.assertIsNotNone(zone.policy)
        self.assertTrue(len(zone.policy.key_types) > 0)

    def test_ngts_read_zone_invalid_zone(self):
        with self.assertRaises(Exception):
            self.ngts_conn.read_zone_conf(f"non-existent-cit-{random_word(8)}")

    def test_ngts_get_policy(self):
        # Read-only: get_policy on the configured zone. NGTS has no Application layer, so users
        # are always empty (parity with Go NGTS).
        ps = self.ngts_conn.get_policy(self.ngts_zone)
        self.assertIsNotNone(ps.policy)
        self.assertTrue(ps.policy.certificate_authority)
        self.assertEqual(ps.users, [])

    def test_ngts_set_get_policy_roundtrip(self):
        # Issuing templates (Request Policies) belong to the tenant and are read-only inside a
        # workspace: creating or editing one requires tenant-level Superuser, so NGTS rejects
        # set_policy with 403/1002 whenever a workspace is set.
        if NGTS_WORKSPACE:
            self.skipTest("set_policy requires tenant level; issuing templates are read-only in a workspace")
        # set_policy mutates a CIT by alias, so use a THROWAWAY alias - never self.ngts_zone,
        # which the other tests depend on. The CA is read from the existing zone so it is
        # guaranteed valid for this tenant.
        existing = self.ngts_conn.get_policy(self.ngts_zone)
        ca = existing.policy.certificate_authority

        ps = PolicySpecification()
        ps.policy = Policy(
            domains=["venafi.example"],
            max_valid_days=90,
            cert_auth=ca,
            # serviceGenerated must be explicit. Omitting key_pair makes build_cit_request send
            # csrUploadAllowed AND keyGeneratedByVenafiAllowed both true (pm_cloud.py:636), which
            # NGTS rejects with a malformed 405 that its gateway then surfaces as a 502.
            key_pair=KeyPair(service_generated=False),
        )
        throwaway_zone = f"vcert-python-pmtest-{random_word(8)}"
        self.ngts_conn.set_policy(throwaway_zone, ps)

        result = self.ngts_conn.get_policy(throwaway_zone)
        self.assertEqual(result.policy.certificate_authority, ca)
        # max_valid_days is deliberately not asserted: set_policy writes validityPeriod nested
        # inside the product object (pm_cloud.py:491) while the CIT parser only looks for it at the
        # top level (connection_cloud.py:316), so it always reads back None for Cloud and NGTS
        # alike. Pre-existing, unrelated to workspaces, tracked separately.
        self.assertIn("venafi.example", result.policy.domains)
        self.assertEqual(result.users, [])


if __name__ == '__main__':
    unittest.main()
