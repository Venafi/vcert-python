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

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.ERROR)

FAKE = environ.get('FAKE')

TOKEN = environ.get('TOKEN')

USER = environ.get('TPPUSER')
PASSWORD = environ.get('TPPPASSWORD')
URL = environ.get('TPPURL')


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))



class TestStringMethods(unittest.TestCase):


    def test_fake(self):
        print("Using fake connection")
        conn = FakeConnection()
        ZONE = "Default"
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, ZONE, cn)
        # renew(conn, cert_id, pkey)

    def test_cloud(self):
        print("Using cloud connection")
        ZONE = environ['CLOUDZONE']
        conn = CloudConnection(token=TOKEN,url=environ.get('CLOUDURL'))
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, ZONE, cn)
        renew(conn, cert_id, pkey, sn, cn)

    def test_tpp(self):
        ZONE = environ['TPPZONE']
        print("Using TPP conection")
        conn = TPPConnection(USER, PASSWORD, URL)
        cn = randomword(10) + ".venafi.example.com"
        cert_id, pkey, sn = enroll(conn, ZONE, cn)
        renew(conn, cert_id, pkey, sn, cn)


def enroll(conn, ZONE, cn):
    print("Tring to ping url", URL)
    status = conn.ping()
    print("Server online:", status)
    if not status:
        print('Server offline')
        exit(1)

    if isinstance(conn, (FakeConnection or TPPConnection)):
        request = CertificateRequest(
            common_name=cn,
            dns_names=["www.client.venafi.example.com", "ww1.client.venafi.example.com"],
            email_addresses="e1@venafi.example.com, e2@venafi.example.com",
            ip_addresses=["127.0.0.1", "192.168.1.1"],
            chain_option="last"
        )
    else:
        request = CertificateRequest(
            common_name=cn,
            chain_option="last"
        )

    conn.request_cert(request, ZONE)
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
    return request.id, request.private_key_pem, cert.serial_number

def renew(conn, cert_id, pkey, sn, cn):
    print("Trying to renew certificate")
    new_request = CertificateRequest(
        id=cert_id,
        chain_option="last"
    )
    conn.renew_cert(new_request)
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

if __name__ == '__main__':
    main()

