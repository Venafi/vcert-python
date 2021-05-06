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

import datetime
import logging as log
import time
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from .common import (ZoneConfig, CommonConnection, Policy, CertField, KeyType)
from .pem import parse_pem

ROOT_CA = b"""-----BEGIN CERTIFICATE-----
MIID1TCCAr2gAwIBAgIJAIOVTvMIMD7OMA0GCSqGSIb3DQEBCwUAMIGAMQswCQYD
VQQGEwJVUzENMAsGA1UECAwEVXRhaDEXMBUGA1UEBwwOU2FsdCBMYWtlIENpdHkx
DzANBgNVBAoMBlZlbmFmaTEbMBkGA1UECwwSTk9UIEZPUiBQUk9EVUNUSU9OMRsw
GQYDVQQDDBJWQ2VydCBUZXN0IE1vZGUgQ0EwHhcNMTgwMzI3MTAyNTI5WhcNMzgw
MzIyMTAyNTI5WjCBgDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxFzAVBgNV
BAcMDlNhbHQgTGFrZSBDaXR5MQ8wDQYDVQQKDAZWZW5hZmkxGzAZBgNVBAsMEk5P
VCBGT1IgUFJPRFVDVElPTjEbMBkGA1UEAwwSVkNlcnQgVGVzdCBNb2RlIENBMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0BobDKthxG5SuMfAp2heyDQN
/IL9NTEnFJUUl/CkLEQTSQT68M9US7TCxi+FOizIoev2k4Nkovgk7uM0q94aygbh
cHyTTL64uphHwcClu99ZQ6DIwzDH2gREsLWfj+KXw4bPsne+5tGxv2+0jG2at5or
p/nOQWYD1C1HB6ZQqvP3PypDjou7Uh+Y00bOfXkbYWr8GkX4XAL6UtC0jUnsBEZX
CuwO1BlIIoKNokhOV7Jcb3l/jurjzVWfem+tqwYb/Tkj6MI1YBqt6Yy2EsGsoAv1
E5/IGcjSQnLEqDWhpY0s2fA4o+bAMzyakDFKJoQbF982QhS2fT+d87vQlnMi1QID
AQABo1AwTjAdBgNVHQ4EFgQUzqRFDvLX0mz4AjPb45tLGavm8AcwHwYDVR0jBBgw
FoAUzqRFDvLX0mz4AjPb45tLGavm8AcwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAWbRgS1qUyGMh3ToJ060s5cdoKzyx/ji5pRPXRxrmzzSxP+dlKX7h
AKUgYOV9FU/k2f4C7TeCZSsir20x8fKRg4qs6r8vHTcWnkC6A08SNlT5kjyJl8vt
qQTEsemnyBFis8ZFUfYdmNYqZXuWSb7ZBfNkR7qMVna8A87NyEmTtlTBkZYSTOaB
NRuOli+/6akXg/OW/GfVUD11D413CtZsWNzKaxj1WH88mjBYwQx2pGRzMWHfWBka
f6ZUnA9hhqxO4CHqQWmKPHftbGscwx5yg/J6J7TfG+rYd5ZVVhrr2un2xpOTctjO
lriDCQa4FOwP9/x1OJRXEsSl5YFqBppX5A==
-----END CERTIFICATE-----
"""

ROOT_CA_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0BobDKthxG5SuMfAp2heyDQN/IL9NTEnFJUUl/CkLEQTSQT6
8M9US7TCxi+FOizIoev2k4Nkovgk7uM0q94aygbhcHyTTL64uphHwcClu99ZQ6DI
wzDH2gREsLWfj+KXw4bPsne+5tGxv2+0jG2at5orp/nOQWYD1C1HB6ZQqvP3PypD
jou7Uh+Y00bOfXkbYWr8GkX4XAL6UtC0jUnsBEZXCuwO1BlIIoKNokhOV7Jcb3l/
jurjzVWfem+tqwYb/Tkj6MI1YBqt6Yy2EsGsoAv1E5/IGcjSQnLEqDWhpY0s2fA4
o+bAMzyakDFKJoQbF982QhS2fT+d87vQlnMi1QIDAQABAoIBACDBuzhHUeBlrUfA
yaaQWzsQVpNE2y6gShKHVPKFwpHlNVPtIML/H7m6/l3L5SC/I+W5Cts1d4XfoZCo
2wWitHzQkHPwaA9Qhit5BPKOrIfiJF7s1C1FZHAA8/8M180CUflJIzBogPg8Ucpc
fwMLzarQ7cZHIBxTPo8LgX7GwzPlYn/kSlys8w5+gfXCbPIqWHdHgJPIm52ePLZt
0XfTF3Q+HSKzKHpdP/9kJJ3eknM/uEgyOKVPHdkq6U4HeJQq9lmp85X58cyHZOYT
qeLIqgq63x+K3Rgc2EUEOHEbdoEU9aP2fsk9M4AOHf7CpPg7htwN/5m0l4dYpIb+
tcxH+BECgYEA5u9Mtt67y37IIzwQxh80vVZ47LnZMmxKA3AOJOj3Q/fkt36TM+rM
vRFKf6dR6Yolt7JtB6bGrLyGFFbmVDtfDjt9uvseKtG4PUrwjr+ayxICsPPidPlU
hUYh2uu4+m/DK8BGV+PR6/5kwQ2cDF5pdFHECX4VY0uvBnsif1IcBDsCgYEA5rBh
HeKNiUzmfIhP345tZaVM/SFDmAWDs5GZXpCnpMoI2QBg6nU3o6ssPflLjcDjnBrK
VpDlGsTBldX+HhXuEFJzUFASbXXWPqdUyMPzcTQuJWRH+s7Pz94gu/FliNJwmYu2
tsS/PuId4O7dA/Bkhp94sH7OW4iD451xyn4RVC8CgYBtlLu4QrSl+UEKxyPGf2RN
O80ht4aC0LPGMdPkW8+JJwYWtC8xgYcpaB0Lud+6i90d78Kg0NiRetu8pwegjJOs
czpUEXjdJKriGr9PXUgceC1ivjeE/hLHMuI5uYULASGBjzlR1z7zVsGEgeq8S8iK
c4osXvHTLkSdNKzH8bRtpQKBgQDkOZlLHKjULi1VBPKohFr8lcYOJAugacw7Kg+m
u8vvPyXzsekv69mo5Z72jR1PV4aXGPYXIHBYxFGU8Eng7+c/ZKLK0Pz6J/tWrus1
WI8O7wW8XnLL0jFMQED4T0EZVMCrV8rjFNDz4HaY4xfrXrfFbB3V1w5HBk8dL9W0
9HYmZwKBgQCN6xAb82gwFM0H1w4iu6MnA2LyLc/19xn8khgNynW3cUznvyKGQuQo
ZEU0fw9VRRyQVwUwjAaLbIuME4cKhGjcJUvGPLftNamTlFS/TvtE1fwauGBXYc5o
wWh1aVElz5xMF+SnGUCW7t02dvhK0i29mOfx/eG5jkSm33NvVBq/IA==
-----END RSA PRIVATE KEY-----
"""


def fake_user(email=None):
    fake_user_email = email or "test@example.com"
    fake_user_uuid = str(uuid.uuid4())
    fake_company_uuid = str(uuid.uuid4())
    company_domains = ['auth-demo.com', 'example.com']
    fake_company = 'Example Inc.'
    f = {'user': {'username': fake_user_email, 'id': fake_user_uuid, 'companyId': fake_company_uuid,
                  'firstname': 'John', 'lastname': 'Doe', 'emailAddress': fake_user_email, 'userType': 'EXTERNAL',
                  'userAccountType': 'WEB_UI', 'userStatus': 'ACTIVE', 'roles': ['ADMIN'],
                  'firstLoginDate': '2018-11-27T14:24:37.136+0000', 'creationDate': '2018-11-27T14:24:05.455+0000'},
         'company': {'id': fake_company_uuid, 'name': fake_company, 'companyType': 'TPP_CUSTOMER', 'active': True,
                     'creationDate': '2017-04-16T16:49:51.000+0000', 'domains': company_domains},
         'apiKey': {'userId': fake_user_uuid, 'username': fake_user_email, 'companyId': fake_company_uuid,
                    'apiVersion': 'ALL', 'apiKeyStatus': 'ACTIVE', 'creationDate': '2018-11-27T14:24:05.455+0000',
                    'validityStartDate': '2018-11-27T14:24:05.455+0000',
                    'validityEndDate': '2119-05-26T14:24:05.455+0000'}}
    return f


class FakeConnection(CommonConnection):
    def __init__(self, *args, **kwargs):
        self.status = "200"
        self._base_url = "fake"

    def __str__(self):
        return "[Fake]"

    def auth(self):
        return fake_user()

    def register(self, email):
        return fake_user(email)

    def request_cert(self, request, zone):
        if not request.csr:
            request.build_csr()
        data = {"PolicyDN": zone,
                "PKCS10": request.csr,
                "ObjectName": request.friendly_name,
                "CertificateDN": request.friendly_name,
                "DisableAutomaticRenewal": "true"}
        request.id = data['CertificateDN']
        log.debug("Certificate sucessfully requested with request id %s." % request.id)
        return request

    def read_zone_conf(self, tag):
        policy = Policy()
        policy.key_types = list([KeyType(KeyType.RSA, x) for x in KeyType.ALLOWED_SIZES])
        z = ZoneConfig(
            organization=CertField(""),
            organizational_unit=CertField(""),
            country=CertField(""),
            province=CertField(""),
            locality=CertField(""),
            policy=policy,
            key_type=policy.key_types[0],
        )
        return z

    def retrieve_cert(self, certificate_request):
        log.debug("Getting certificate status for id %s" % certificate_request.id)

        time.sleep(0.1)
        certificate_request._public_key_from_private()
        csr = x509.load_pem_x509_csr(certificate_request.csr.encode(), default_backend())

        root_ca_certificate = x509.load_pem_x509_certificate(ROOT_CA, default_backend())
        root_ca_private_key = serialization.load_pem_private_key(ROOT_CA_KEY, password=None,
                                                                 backend=default_backend())


        # cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, certificate_request.common_name)])
        issuer = root_ca_certificate.issuer
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            issuer
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            # csr_builder.extensions,
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(root_ca_private_key, hashes.SHA256(), default_backend())

        log.info("This certificate is for test purposes only. Don't use it in production!")
        return parse_pem(cert.public_bytes(serialization.Encoding.PEM).decode(), certificate_request.chain_option)

    def revoke_cert(self, request):
        raise NotImplementedError

    def renew_cert(self, request, reuse_key=False):
        log.debug("Renew is not supported in test mode.")
        raise NotImplementedError
