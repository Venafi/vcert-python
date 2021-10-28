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
import logging
import platform
import re
import unittest

from assets import SSH_CERT_DATA, SSH_PRIVATE_KEY, SSH_PUBLIC_KEY
from test_env import TPP_TOKEN_URL, TPP_USER, TPP_PASSWORD, TPP_SSH_CADN
from test_utils import timestamp
from vcert import CommonConnection, SSHCertRequest, TPPTokenConnection, Authentication, \
    SCOPE_SSH, write_ssh_files, logger, venafi_connection, VenafiPlatform
from vcert.ssh_utils import SSHRetrieveResponse, SSHKeyPair, SSHCATemplateRequest

log = logger.get_child("test-ssh")

SERVICE_GENERATED_NO_KEY_ERROR = "%s key data is %s empty for Certificate %s"  # type: str
SSH_CERT_DATA_ERROR = "Certificate data is empty for Certificate %s"  # type: str


class TestTPPSSHCertificate(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.tpp_conn = TPPTokenConnection(url=TPP_TOKEN_URL, http_request_kwargs={"verify": "/tmp/chain.pem"})
        auth = Authentication(user=TPP_USER, password=TPP_PASSWORD, scope=SCOPE_SSH)
        self.tpp_conn.get_access_token(auth)
        super(TestTPPSSHCertificate, self).__init__(*args, **kwargs)

    def test_enroll_local_generated_keypair(self):
        keypair = SSHKeyPair()
        keypair.generate(key_size=4096, passphrase="foobar")

        request = SSHCertRequest(cadn=TPP_SSH_CADN, key_id=_random_key_id())
        request.validity_period = "4h"
        request.source_addresses = ["test.com"]
        request.set_public_key_data(keypair.public_key())
        response = _enroll_ssh_cert(self.tpp_conn, request)
        self.assertTrue(response.private_key_data is None,
                        SERVICE_GENERATED_NO_KEY_ERROR % ("Private", "not", request.key_id))
        self.assertTrue(response.public_key_data, SERVICE_GENERATED_NO_KEY_ERROR % ("Public", "", request.key_id))
        self.assertTrue(response.public_key_data == request.get_public_key_data(),
                        "Public key on response does not match request.\nExpected: %s\nGot: %s"
                        % (request.get_public_key_data(), response.public_key_data))
        self.assertTrue(response.certificate_data, SSH_CERT_DATA_ERROR % request.key_id)

    def test_enroll_service_generated_keypair(self):
        request = SSHCertRequest(cadn=TPP_SSH_CADN, key_id=_random_key_id())
        request.validity_period = "4h"
        request.source_addresses = ["test.com"]
        response = _enroll_ssh_cert(self.tpp_conn, request)
        self.assertTrue(response.private_key_data, SERVICE_GENERATED_NO_KEY_ERROR % ("Private", "", request.key_id))
        self.assertTrue(response.public_key_data, SERVICE_GENERATED_NO_KEY_ERROR % ("Public", "", request.key_id))
        self.assertTrue(response.certificate_data, SSH_CERT_DATA_ERROR % request.key_id)

    def test_retrieve_ca_public_key(self):
        tpp_connector = venafi_connection(platform=VenafiPlatform.TPP, url=TPP_TOKEN_URL,
                                          http_request_kwargs={"verify": "/tmp/chain.pem"})
        request = SSHCATemplateRequest(ca_template=TPP_SSH_CADN)
        ssh_config = tpp_connector.retrieve_ssh_config(ca_request=request)
        self.assertIsNotNone(ssh_config.ca_public_key, "%s Public Key data is empty" % TPP_SSH_CADN)
        self.assertIsNone(ssh_config.ca_principals, "%s default principals is not empty" % TPP_SSH_CADN)
        log.debug("%s Public Key data:\n%s" % (TPP_SSH_CADN, ssh_config.ca_public_key))

    def test_retrieve_ca_public_key_and_principals(self):
        request = SSHCATemplateRequest(ca_template=TPP_SSH_CADN)
        ssh_config = self.tpp_conn.retrieve_ssh_config(ca_request=request)
        self.assertIsNotNone(ssh_config.ca_public_key, "%s Public Key data is empty" % TPP_SSH_CADN)
        self.assertIsNotNone(ssh_config.ca_principals, "%s default principals is empty" % TPP_SSH_CADN)
        log.debug("%s Public Key data: %s" % (TPP_SSH_CADN, ssh_config.ca_public_key))
        log.debug("%s default principals: %s" % (TPP_SSH_CADN, ssh_config.ca_principals))


class TestSSHUtils(unittest.TestCase):
    def test_write_ssh_files(self):
        key_id = _random_key_id()
        normalized_name = re.sub(r"[^A-Za-z0-9]+", "_", key_id)
        full_path = "./" + normalized_name
        write_ssh_files("./", key_id, SSH_CERT_DATA, SSH_PRIVATE_KEY, SSH_PUBLIC_KEY)

        err_msg = "%s serialization does not match expected value"

        with open(full_path + "-cert.pub", "r") as cert_file:
            s_cert = cert_file.read()
            self.assertTrue(SSH_CERT_DATA == s_cert, err_msg % "SSH Certificate")

        with open(full_path, "r") as priv_key_file:
            s_priv_key = priv_key_file.read()
            expected_priv_key = SSH_PRIVATE_KEY
            if platform.system() != "Windows":
                expected_priv_key = expected_priv_key.replace("\r\n", "\n")

            self.assertTrue(expected_priv_key == s_priv_key, err_msg % "SSH Private Key")

        with open(full_path + ".pub", "r") as pub_key_file:
            s_pub_key = pub_key_file.read()
            self.assertTrue(SSH_PUBLIC_KEY == s_pub_key, err_msg % "SSH Public Key")


def _enroll_ssh_cert(connector, request):
    """
    :param CommonConnection connector:
    :param SSHCertRequest request:
    :rtype: SSHRetrieveResponse
    """
    success = connector.request_ssh_cert(request)
    assert success
    response = connector.retrieve_ssh_cert(request)
    assert isinstance(response, SSHRetrieveResponse)
    return response


def _random_key_id():
    return "vcert-python-ssh-%s" % timestamp()
