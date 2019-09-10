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

from vcert import CloudConnection, CertificateRequest, TPPConnection, FakeConnection
import string
import random
import logging
import time
from os import environ
from six import string_types, text_type
import unittest
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)

FAKE = environ.get('FAKE')

TOKEN = environ.get('TOKEN')

USER = environ.get('TPPUSER')
PASSWORD = environ.get('TPPPASSWORD')
TPPURL = environ.get('TPPURL')
CLOUDURL = environ.get('CLOUDURL')
RANDOM_DOMAIN = environ.get("RANDOM_DOMAIN")
if not isinstance(RANDOM_DOMAIN, text_type):
    RANDOM_DOMAIN = RANDOM_DOMAIN.decode()


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


class TestStringMethods(unittest.TestCase):

    def test_fake(self):
        print("Using fake connection")
        conn = FakeConnection()
        zone = "Default"
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, zone, cn)
        # renew(conn, cert_id, pkey)

    def test_cloud(self):
        print("Using Cloud connection")
        zone = environ['CLOUDZONE']
        conn = CloudConnection(token=TOKEN, url=CLOUDURL)
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, zone, cn)
        cert = renew(conn, cert_id, pkey, sn, cn)
        renew_by_thumbprint(conn, cert)

    def test_tpp(self):
        zone = environ['TPPZONE']
        ecdsa_zone = environ['TPPZONE_ECDSA']
        print("Using TPP conection")
        conn = TPPConnection(USER, PASSWORD, TPPURL, http_request_kwargs={"verify": "/tmp/chain.pem"})

        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, zone, cn)
        cert = renew(conn, cert_id, pkey, sn, cn)
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


def enroll(conn, zone, cn=None, private_key=None, public_key=None, password=None, csr=None):
    print("Trying to ping service")
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)

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
    while True:
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
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
        x509.NameAttribute(
            NameOID.COMMON_NAME, cn or RANDOM_DOMAIN
        )
    ]

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
    return request.id, request.private_key_pem, cert.serial_number


def renew(conn, cert_id, pkey, sn, cn):
    print("Trying to renew certificate")
    new_request = CertificateRequest(
        cert_id=cert_id,
    )
    conn.renew_cert(new_request)
    time.sleep(5)
    while True:
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
    conn.renew_cert(new_request)
    while True:
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


# TODO: add test sign CSR

TEST_KEY_RSA_2048_ENCRYPTED = ("""
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,4C68B019B2BFC3E7E2C390A3A6751E00

mLrpIxg4S287bNYhpcO18R05ODFy0qlBY3prko0OI9nXRlxaCVa2knEBmU9S6VNR
7dtxIghXn4T6hwHP12hgNLQFoIFe9JWCPjH2rmxYUuYrYkVK4FvpYYBtubiJbCmn
hkXhHTXhieZ3AMgaXfFsTwX2DZAcjz3kAnMh/G7Yygr1IS3FANOT1lFU3jUFoOyz
EUBw5+ez1NP0K9i7115B4c/axZScTP/9hbXESA6n1Ky942OkahfKOwcT5nrgou9M
djaOqLcBNpZH6XVZsf87IhrJltThso6+lFSL2EwFnP4V/Gaq2dNbEjXQorsRKmX9
/RQG5TIp/3HG311jOKJLw+6/mUGU0Wkkr0f+pL/FyvrxS61pQzo/KZ6kcidtNouY
okMaWwP4IYXkr3YboQ4R6NrsnjQiQGfaDOazbIzlX8oPSbeRv1jaKIxCQK9WGEMj
tY/swWy3kSMZIqcglqJzpeKysxZO6WHP230Zohhp2Q8lBLggQjJCMmYiSnq8WQ6r
02YvHNRMyYBoVvUaA5ruCNJkBEIJrJcPA66e7yUqFfR4En2FlwVQPIWugo3fOnU1
3CIknfsDzy28gjb9fk3WNEIUZMEdjbf0djqYw5z6v9ksOYwWwUvvwBMnyFLlEuet
2zH5DTDxUhP0zD2qxY/3/+wZ3c1X1WRg6zZB0CfZRWcCtUs/VSP4+ltDdin08CX8
13UOF2GKks8iAhQSyIyrRHfFSROAJ7eDYHs/tCVeIjv0qS4SYTiEhR13A1GFzJzd
GfjIBh7496uLCEgoYC4KkeKWoXG6o8WTwLld/dcBxgn5vBwheMVdZG/5gKypHDNe
RHcSbmNsE18dIhpGDIuutEiNGypWQnQajM97cdGr3R8O1WmbIo1P1F7fAjH8kre+
iUU896nbvqEZ6xvhoWxwPp4dyEktajE5+purlS27XIXXprTFFSpmHS709EzFmrHS
iZZjWuqCuvFneCc8nkk1+F1RBrqoHW6ZEFyI9B4y4czs0t0NJeIK5+RX9vDuvA3Y
j9QVTg5xVx2WYkll0YWRlZmSzfxpucDYN6TStSNk2LeoEnirsmxppRb9doqk8juA
NNDUJSZTUtCRYOcuKvg7mks3Jh46xIDwhbNM1MvacB3IB0ZUCKIrQ7UWj6JmRWnF
/S3wvqEUsavIuGAqEVJAq8qz/eoGYlffTluQXTuwl2tx9n36hMbwRPtsq/iLkQHz
IXKU/bzfjJN5QiOEoL8tu9o1T8kvT8bRsLaIFiAR9o3azKonZEY11HE46W9B6qIx
Qh6NSvyRIpMUt9BShkGlo9kA/hWLDA9nRJ+b4wbmvvFxfJg75cCrewvRGijBDJ35
vMQck6r5K7WA8gZgzJv4juP9ik6BssqnCb7tdUWyei725Uh3CRzwjiYzGCrArzp/
48GSM9QntGrPF4lFymjm030zsYDPzEtAsR3pmjJXP9oT/dPR5SCWzM9E2AwSgap1
FfEaT87Jbir/OjG7kuwPKPC0JMwZ1a5dNQic36RYY1Uu6Riv2nJLYHuIVDcmyiRU
JpNJPumQuxhY9KPxRPq89hsh8+UjAaoF6gGET+YsVWFQDAfR8uKAjyoFe2U0aOu6
-----END RSA PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAul48ENeuw+Zv7lynNpcU
s+vNyRAIZXj2cxepO+uefZewyadDjZRDvw43PAHizaN7IX2D4N81SnlLShMqc/gc
jGAze2pxU+GkiMcW2hph6AX60b6Na3GmozeZlVWpz+kfv8hYcRdSL4HoknVOVYU5
vEDK1GH2Jrv59ZlzL1z6Qyyc7OCDCXaHFp0Ft4/lQtB5vFQBva/+RM5QJEaeM2mY
CLmbDPc1IZcRJNDLqstTyVD13rO+v48pnkxxGV4RCvsTvA4QbSo4X63doYxPrrvZ
wWueQ2fTDs+gUGRj4VGC9PQuAdTIvpkUIQr28vyb+O6q/fO8oeXNYuzXbKjXRxpZ
2wIDAQAB
-----END PUBLIC KEY-----
""")

TEST_KEY_RSA_4096 = ("""
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApoRGAyYvB8v3uD+oHCfE
Dv7MQlKeOl3mUJKLC4BOuAbYLf35xsy0+pIQSQkuU+HSSBPkw/8nH8nFn+YjcYPY
ZS2mhxVYyGwaHqz7l5xA/u3SF7Y7tv0YdtfDFNHR8PH4e6oLP3cx2xVsXPQib8az
yOHuei5320Hsv5xRBlOrK7gtlv4c+9OvGbJZa6VnZ83s4SvtrXlgqpiwYCiFMKrJ
y0zy1CuqXpCRqHRmOwcX9o63+QxgvZGCo+E3Jz/E1HrQQkmdC7rsLDcrTde5bV1K
dk/+zXHTuCb8mi7ticShXSv93qSMUIhAp81zFa5Ys+ueMctCl0YnFLQsCAPsQprE
SPKqhweq8W8RkFEvfSioeIo/qlU5clCSWwaFdX0ZPJV3yS90cEYIh5dc/Yt+bJka
oFwO+fswiDaMkQ9wd18Mk4QyWaqp1p6EphXx6wvUm11EgkNFjgIJo/FY6v9Tyz2i
zH35Z02EDjyVoEuz8M7iZvDVBmz5N2Hqre72KgZobRrpH+vXO0zP3SqbfYUaG5L6
IKu9AVJcWGnaQn2RRc4ruXYDnzpJgt4y9RScBTaLHPNLeG0edPv49N2Kfhfm5ziK
PSwN1jd7DmUmtcOaQhgtl+1Tp7bFpDmUBTyFQ3wxDJFnVFjTsofJsdSW33g0+DtX
b/G8hnsWUukvxRXg8TJJIFsCAwEAAQ==
-----END PUBLIC KEY-----
""")

TEST_KEY_ECDSA = ("""
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAhS7UG/d7YwTg/pOnmyGGzmt/YFVCAOIiu18Mo+/3ZFc/Kb50ky2q
UzHfCWy+tcpWkzIT7FO/eAeUqy7Xzu/lqB+gBwYFK4EEACOhgYkDgYYABADLRK7k
tpl+AyP2f8MDiVgawDp84WV7qyqHa+aidct/1CMu7KHGKg+LXSCY2VXbxkY6mrV/
c22Vv6i3GH9pzxFzQwBw6whrrMos5MMDVvQSE1pAjT6fajVzD3sNz6BBlTzUxeLe
kbm18LiyjLSlxy+taObmfdoraG7/3AdhMcWGP2pp2A==
-----END EC PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAy0Su5LaZfgMj9n/DA4lYGsA6fOFl
e6sqh2vmonXLf9QjLuyhxioPi10gmNlV28ZGOpq1f3Ntlb+otxh/ac8Rc0MAcOsI
a6zKLOTDA1b0EhNaQI0+n2o1cw97Dc+gQZU81MXi3pG5tfC4soy0pccvrWjm5n3a
K2hu/9wHYTHFhj9qadg=
-----END PUBLIC KEY-----
""")