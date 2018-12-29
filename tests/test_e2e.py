#!/usr/bin/env python3
from vcert import CloudConnection, CertificateRequest, TPPConnection, FakeConnection
import string
import random
import logging
import time
from os import environ
import unittest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)

FAKE = environ.get('FAKE')

TOKEN = environ.get('TOKEN')

USER = environ.get('TPPUSER')
PASSWORD = environ.get('TPPPASSWORD')
TPPURL = environ.get('TPPURL')
CLOUDURL = environ.get('CLOUDURL')


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
        print("Using cloud connection")
        zone = environ['CLOUDZONE']
        conn = CloudConnection(token=TOKEN, url=CLOUDURL)
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, zone, cn)
        renew(conn, cert_id, pkey, sn, cn)

    def test_tpp(self):
        zone = environ['TPPZONE']
        print("Using TPP conection")
        conn = TPPConnection(USER, PASSWORD, TPPURL)
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, zone, cn)
        renew(conn, cert_id, pkey, sn, cn)


def enroll(conn, zone, cn):
    print("Trying to ping service")
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)

    if isinstance(conn, (FakeConnection or TPPConnection)):
        request = CertificateRequest(
            common_name=cn,
            san_dns=["www.client.venafi.example.com", "ww1.client.venafi.example.com"],
            email_addresses="e1@venafi.example.com, e2@venafi.example.com",
            ip_addresses=["127.0.0.1", "192.168.1.1"],
            chain_option="last"
        )
    else:
        request = CertificateRequest(
            common_name=cn,
            chain_option="last"
        )

    conn.request_cert(request, zone)
    while True:
        cert_pem = conn.retrieve_cert(request)
        if cert_pem:
            break
        else:
            time.sleep(5)
    # print("Certificate is:\n %s" % cert_pem)
    # print("Private key is:\n %s:" % request.private_key_pem)
    # and save into file
    f = open("./cert.pem", "w")
    f.write(cert_pem)
    f = open("./cert.key", "w")
    f.write(request.private_key_pem)
    f.close()

    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    assert isinstance(cert, x509.Certificate)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
        x509.NameAttribute(
            NameOID.COMMON_NAME, cn
        )
    ]

    private_key = serialization.load_pem_private_key(request.private_key_pem.encode(), password=None,
                                                     backend=default_backend())
    private_key_public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_pem = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(private_key_public_key_pem.decode())
    print(public_key_pem.decode())
    assert private_key_public_key_pem == public_key_pem

    return request.id, request.private_key_pem, cert.serial_number


def renew(conn, cert_id, pkey, sn, cn):
    print("Trying to renew certificate")
    new_request = CertificateRequest(
        id=cert_id,
        chain_option="last"
    )
    conn.renew_cert(new_request)
    time.sleep(5)
    while True:
        new_cert_pem = conn.retrieve_cert(new_request)
        if new_cert_pem:
            break
        else:
            time.sleep(5)

    f = open("./renewed_cert.pem", "w")
    f.write(new_cert_pem)
    f.close()

    cert = x509.load_pem_x509_certificate(new_cert_pem.encode(), default_backend())
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
