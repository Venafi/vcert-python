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
from __future__ import absolute_import, division, generators, unicode_literals, print_function, nested_scopes, \
    with_statement

import binascii
import random
import string
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from future.backports.datetime import datetime
from six import string_types

from test_env import RANDOM_DOMAIN
from vcert import CertificateRequest, FakeConnection, TPPConnection, TPPTokenConnection, CSR_ORIGIN_SERVICE


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


def timestamp():
    return datetime.today().strftime('%Y.%m.%d-%Hh%Mm%Ss')


def simple_enroll(conn, zone):
    req = CertificateRequest(common_name=random_word(12) + ".venafi.example.com")
    conn.request_cert(req, zone)
    cert = conn.retrieve_cert(req)
    return req, cert


def renew_without_key_reuse(unittest_object, conn, zone):
    cn = random_word(10) + ".venafi.example.com"
    cert_id, pkey, _, public_key, _ = enroll(conn, zone, cn)
    time.sleep(5)
    req = CertificateRequest(cert_id=cert_id)
    conn.renew_cert(req, reuse_key=False)
    cert = conn.retrieve_cert(req)
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
    cert = conn.retrieve_cert(request)
    return cert, request.cert_guid


def enroll(conn, zone, cn=None, private_key=None, public_key=None, password=None, csr=None, custom_fields=None,
           service_generated_csr=False):
    request = CertificateRequest(
        common_name=cn,
        private_key=private_key,
        key_password=password
    )

    if custom_fields:
        request.custom_fields = custom_fields

    request.san_dns = ["www.client.venafi.example.com", "ww1.client.venafi.example.com"]
    if isinstance(conn, (FakeConnection, TPPConnection, TPPTokenConnection)):
        request.email_addresses = ["e1@venafi.example.com", "e2@venafi.example.com"]
        request.ip_addresses = ["127.0.0.1", "192.168.1.1"]
        request.user_principal_names = ["e1@venafi.example.com", "e2@venafi.example.com"]
        request.uniform_resource_identifiers = ["https://www.venafi.com", "https://venafi.cloud"]

    if csr:
        request.csr = csr
    elif service_generated_csr:
        request.csr_origin = CSR_ORIGIN_SERVICE
        request.include_private_key = True

    conn.request_cert(request, zone)
    cert = conn.retrieve_cert(request)
    # print("Certificate is:\n %s" % cert_pem)
    # print("Private key is:\n %s:" % request.private_key_pem)
    # and save into file
    with open("./cert.pem", "w") as f:
        f.write(cert.full_chain)
    with open("./cert.key", "w") as f2:
        if request.include_private_key:
            assert cert.key is not None
            f2.write(cert.key)
        else:
            f2.write(request.private_key_pem)

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
        source_public_key_pem = request.public_key_pem if not service_generated_csr else None
    print(source_public_key_pem)
    print(cert_public_key_pem)

    if not service_generated_csr:
        assert source_public_key_pem == cert_public_key_pem
    private_key_pem = request.private_key_pem if not service_generated_csr else None

    return request.id, private_key_pem, cert, cert_public_key_pem, request.cert_guid


def renew(conn, cert_id, pkey, sn, cn):
    print("Trying to renew certificate")
    new_request = CertificateRequest(
        cert_id=cert_id
    )
    # TODO change back to True when support for renew with csr use is deployed.
    conn.renew_cert(new_request, reuse_key=False)
    new_cert = conn.retrieve_cert(new_request)

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
    # TODO this assertion only works when the reuse key is set to true in the renew method
    # assert private_key_public_key_pem == public_key_pem
    return cert


def renew_by_thumbprint(conn, prev_cert):
    print("Trying to renew by thumbprint")
    thumbprint = binascii.hexlify(prev_cert.fingerprint(hashes.SHA1())).decode()
    new_request = CertificateRequest(thumbprint=thumbprint)
    # TODO change back to True when support for renew with csr use is deployed.
    conn.renew_cert(new_request, reuse_key=False)
    new_cert = conn.retrieve_cert(new_request)
    cert = x509.load_pem_x509_certificate(new_cert.cert.encode(), default_backend())
    assert isinstance(cert, x509.Certificate)
    print(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    print(prev_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == prev_cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)
