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
import json
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from assets import POLICY_CLOUD1, POLICY_TPP1, EXAMPLE_CSR, EXAMPLE_CHAIN
from pem import parse_pem, Certificate
from vcert import CloudConnection, KeyType, TPPConnection, CertificateRequest, ZoneConfig, CertField, FakeConnection, \
    logger

pkcs12_enc_cert = """-----BEGIN CERTIFICATE-----
MIICljCCAX6gAwIBAgIRAO8Qp6LUsgVDQrxHXX1LUV4wDQYJKoZIhvcNAQENBQAw
gYAxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRcwFQYDVQQHDA5TYWx0IExh
a2UgQ2l0eTEPMA0GA1UECgwGVmVuYWZpMRswGQYDVQQLDBJOT1QgRk9SIFBST0RV
Q1RJT04xGzAZBgNVBAMMElZDZXJ0IFRlc3QgTW9kZSBDQTAeFw0xODA4MDUwMTE4
MjVaFw0xODExMDMwMTE4MjVaMAwxCjAIBgNVBAMTAXEwXDANBgkqhkiG9w0BAQEF
AANLADBIAkEAz5jYYiZbUvxbsaboaoJBUnPdFf6bNwux1Ip3tXRcNQ4j4LIZVn+l
EcnISnOzAGxjGTnixwlZ7TDX2GupqkuxZQIDAQABo0YwRDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFM6kRQ7y19Js+AIz2+Ob
Sxmr5vAHMA0GCSqGSIb3DQEBDQUAA4IBAQBjQB1LiSx0eh0NK3uA9/lbFHfM26D/
FE/CAupvCaSJNi7sc5P35mYAcbVjjPhKG9k+Gn9LXxtbF5O1ipYCLcuYRFGLh7kM
Nd4DqHPZRaIcxXQMYGHZ26omPgx9m7GvPuFFNhtxBSNLPBDoGW2XuUearObxgIWV
IGfez+BB1qWlRNT/aF0qqPCSvYsN5oX79Int8f8wTT4PSmYd9gxOgDq5JlAgvYw5
BfM/og0jia3XsLC25gILLbj3ozkvTndKOF0KDqYIW0kCEE9DiBlC84hIybpgILL7
T9Aufk2CABqo6tnwIW1GC4qf/6xsO6qnU2yGpmds8s1JZqeZ+jC3Dov3
-----END CERTIFICATE-----"""

pkcs12_enc_pk = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1fe24235e016f1c40adbdca0a19cf9d6

B2Fu5Hs31UgSIL689SPisaEpabz+QdmXVnTO1/Ax6so9AN00+HgpMTBDF7t6XqZ6
nCJ24Rlkrb3LJL1yvTX3isRS0ab7uLGh9h6VYX7SpjAvFNsEeY79JyZfHMFBjkyg
IEBwwR1Gyp9MOyUHgaku0cUfcGkRPjWQ/8c/VHUZe5KZ3yBh4lHCGYZoBnDLZfte
Li8WWx+StyDKuCVtt9c/wQkaTgAdWjxe6Sowt2nuE7uJyu5PXSsvqi/eohqh9mE7
Al3nqH2F3QSbPUMTIV6ar6uEFiOIjp6BSPRTOUNgigqlPY51KJVZboKapFHy23Sy
JdT1+vbzuKt50CcU6uqaYxBbU7lpwT61Gvw8bnrLhXVrOcs4Oi2Cc8nt+5qt+++y
ozO8ZQRvOf56AHRMUBmVR4ouRrP0ABOfxSGWjhTBqCgtqeI/+FNDwxpQP/4kiXoT
-----END RSA PRIVATE KEY-----"""

pkcs12_enc_pk_pass = "asdf"

pkcs12_plain_cert = """-----BEGIN CERTIFICATE-----
MIIIWjCCBkKgAwIBAgITbQCc17MIowF0HpTqwAAAAJzXszANBgkqhkiG9w0BAQsF
ADBbMRMwEQYKCZImiZPyLGQBGRYDY29tMRYwFAYKCZImiZPyLGQBGRYGdmVuYWZp
MRUwEwYKCZImiZPyLGQBGRYFdmVucWExFTATBgNVBAMTDFFBIFZlbmFmaSBDQTAe
Fw0yMTEwMDcyMTAyNTVaFw0yOTEwMDUyMTAyNTVaMCgxJjAkBgNVBAMTHWRnZXB3
cnZidmwudmVuYWZpLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAtFtt1HHu1YYkJHfLhJrBdtRxpy7MccsV2GI24dq2GWiqoQ6veOfe
X8iKV152H8Zq9YHbBvs7acil+lOMHjATO0flYl1QKoXjdiLWTFv/By5088pL63OR
rUjeKTY6opVeaWQBAlhy+YQMI5c48SRUlybNwW6DtBuKKwhQL5QUygvqNtTnIdMZ
VkVmxpdeaO4LrjaXf8Jd0x4ONLJ1aYBAjWgidfg3bINkNWL7SBdFN4Lfk3pRL7Rf
RAFUWQmXzTvTlvF155lQiybcole7/Tg/9DlAPKleU6L1piMrz5u3l/zfMY/k6+SY
/cRCesqZXr5UVigJSfR4G58XvZT/tEDUOwIDAQABo4IESDCCBEQwggEiBgNVHREE
ggEZMIIBFaAmBgorBgEEAYI3FAIDoBgMFmUxQHZlbmFmaS5leGFtcGxlLmNvbQCg
JgYKKwYBBAGCNxQCA6AYDBZlMkB2ZW5hZmkuZXhhbXBsZS5jb20AgRVlMUB2ZW5h
ZmkuZXhhbXBsZS5jb22BFWUyQHZlbmFmaS5leGFtcGxlLmNvbYIdd3d3LmNsaWVu
dC52ZW5hZmkuZXhhbXBsZS5jb22CHXd3MS5jbGllbnQudmVuYWZpLmV4YW1wbGUu
Y29tgh1kZ2Vwd3J2YnZsLnZlbmFmaS5leGFtcGxlLmNvbYYWaHR0cHM6Ly93d3cu
dmVuYWZpLmNvbYYUaHR0cHM6Ly92ZW5hZmkuY2xvdWSHBH8AAAGHBMCoAQEwHQYD
VR0OBBYEFN+D5ApcSSlu0bdEIAqiLOL8yK0UMB8GA1UdIwQYMBaAFDysnKYNoTDU
Vqc9eLwjG+y0e011MIIBIgYDVR0fBIIBGTCCARUwggERoIIBDaCCAQmGQmh0dHA6
Ly9xYXZlbmFmaWNhLnZlbnFhLnZlbmFmaS5jb20vQ2VydEVucm9sbC9RQSUyMFZl
bmFmaSUyMENBLmNybIaBwmxkYXA6Ly8vQ049UUElMjBWZW5hZmklMjBDQSxDTj1x
YXZlbmFmaWNhLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXZlbnFhLERDPXZlbmFmaSxEQz1j
b20/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
TERpc3RyaWJ1dGlvblBvaW50MIIBOAYIKwYBBQUHAQEEggEqMIIBJjBqBggrBgEF
BQcwAoZeaHR0cDovL3FhdmVuYWZpY2EudmVucWEudmVuYWZpLmNvbS9DZXJ0RW5y
b2xsL3FhdmVuYWZpY2EudmVucWEudmVuYWZpLmNvbV9RQSUyMFZlbmFmaSUyMENB
LmNydDCBtwYIKwYBBQUHMAKGgapsZGFwOi8vL0NOPVFBJTIwVmVuYWZpJTIwQ0Es
Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
PUNvbmZpZ3VyYXRpb24sREM9dmVucWEsREM9dmVuYWZpLERDPWNvbT9jQUNlcnRp
ZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAL
BgNVHQ8EBAMCBaAwOwYJKwYBBAGCNxUHBC4wLAYkKwYBBAGCNxUIgY+JcoSEsGr1
nRCHlv98xIkVYITPmmOF+65DAgFkAgEEMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBsG
CSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggIBALNX
Fmv1VlebYKENpp8CHu6deggKo9Atsxrein/jYE8OQu3hw1c1dKj0wYszjGpkuX5L
6H3latuWlOYggSqUFI10IYkn93GUQloQz6ZjhQ6gmyGLB/LNNHiK5fQmE+meI+DB
o0OdpB/Aj670CHIx3ycmPWWQrB/KqaNUI1cPn4EtZvJPmZlMY1NqjSkaQD2bCAXU
ywoKHmVNFyNcGicV51Od8fTjohgy5N3jWgSnTqdeuesYQo0NC2x+jc/ALblT0IgO
QrodxC8PEhEkTFpZn1VbrTZN+PcBMRMqEWiIkCxSzh+984txykdjh3b+NKVEx6y6
AEQe3u/sPWIg4UrjjnUu8QAIaazUeKYpM7ppnjn0bWdh+eoFoHBUB2R8S/+Q4Jd6
SeLBz3LOpzv4qXM/9MNCCmmEtrdaoSIY+85CcdLShlpO3lOcScsAdMkofbcrcpLN
+lIT4q7hnJaOiSnN5MzQVsICLKMbKFrBhe9oBW0bLWvoornASq2vNLmShegHFtCA
B2lQPyUyYcJyu48wE7fylfOs4sE0lvsknCs9PYtEDmmVWYNQl3XzMIlPnaGcYM3J
KrGQ3499d3hzo4RAvx+Q9Zu//BRElHQr41NRqdE0Lmnmvtuhs1do3t8cazQMeYp+
dkuKzLf+umxyd1lMSMYu+BJsR3iaPEgY+GdwunnJ
-----END CERTIFICATE-----
"""

pkcs12_plain_pk = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtFtt1HHu1YYkJHfLhJrBdtRxpy7MccsV2GI24dq2GWiqoQ6v
eOfeX8iKV152H8Zq9YHbBvs7acil+lOMHjATO0flYl1QKoXjdiLWTFv/By5088pL
63ORrUjeKTY6opVeaWQBAlhy+YQMI5c48SRUlybNwW6DtBuKKwhQL5QUygvqNtTn
IdMZVkVmxpdeaO4LrjaXf8Jd0x4ONLJ1aYBAjWgidfg3bINkNWL7SBdFN4Lfk3pR
L7RfRAFUWQmXzTvTlvF155lQiybcole7/Tg/9DlAPKleU6L1piMrz5u3l/zfMY/k
6+SY/cRCesqZXr5UVigJSfR4G58XvZT/tEDUOwIDAQABAoIBAFJJiLGuDcbz/dd5
pKxqoywhP32El5ivjNb98IZZcE3leDwlZB/owoe3Co9UNNbIg5Jh3dmwlGnuNvQg
XESFsLCSW/DmHCZake4bdOS/8HqJUqjMOplBUEzceygYauY0+i9hhihYzJRVD+jJ
HRzAc6vG84d2cbah/gcmMteSW23W/oRdxk90xgWjaGT7Y2CgN27Mj/l3+eqDTPcG
2/pAT/q9W0Yi6c+p3JITDVhTe2qJRChQ8Zpmwfzf+TKy2Grl1PU1SRhx+BXNmJpz
etwoPlMwdaJULmOQLocC4qEZqWyGdTi2TubdJ9wVs89mKpPrtoFWjECRgyVMmTMG
H72ERGECgYEA8GlipUYZYKSBI95yw2H5uSIpJhd7rsObZIt/2tFdT7f9hCxC+ijg
scZ2RK4+2MGM70/eqFu16CPbvkXlqwk3V5PFRxjIZ5nn4eDRQjfqMEb8P0dtqPRD
EhMhLLNDHBtQKMMvqg1tI6DEWLy0O9pp5ihLwvLdYIZg/xAiJVAQ4zECgYEAwA0x
gj1NGLWFgTBjNG79XOxwW2DLMC6n1UMlIu/FOUFzx3Kjqa7l3FNgb8jrIgjlubr5
Cpk1AgPIWZTW5TDeDX2TVIqFDLtT708HzeiWGlUJ5rFbyon7DvISdqozV8WWDWGU
kftPZIDikJkyGLK4+VjoW9H6BynZJHhWnnacmysCgYEAqB+au6fNAXepU/MxYI94
us435oqPlQT3+5VOoTC+x4wMv0zQve6uS8RVWuxbyOt56rV5KVWRXbkN5/8rgLOe
PyF42aJsK39G2QCGdn9xx7csmfgSqQ/Ag7ha/86RBOvY39i30X04MK0yAjhc9mpk
mm7dpISA6gqvdE/NATj/xlECgYAMpRG8bILV/KWkouX1PtWJt7uSGKZoLro4LWqV
iUnoAio4WJD0DCLwRcEUuxrYK9PMTcY1725xCoS3eThI8NW996WqrFAkTXUyTXbL
FORFKZI0UTsk877G9iNHEt+8iLLfgKxCjFRm3qGMObn1rFbHfBYYbZPTwuqcHxw8
5Lxc7wKBgQDnbL3FLmiDAXV70q+5paqqFI1T1blrJHsiU7Kjk2JT5UmB+J9Xxl5O
qQJ/SQ/LzcMypueNGRvQi1nU3xAUYWfrVaS/gYsS6OHTsjqTsioArAPJheYjtl9z
R2/ybVHUEAeIf2nuRaUxDbgY9qj7ODcKsTSGODyeQxnrRW/R/0c20A==
-----END RSA PRIVATE KEY-----
"""

ca_cert = """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"""

chain = [ca_cert, ca_cert]

log = logger.get_child("test-local-methods")


class TestLocalMethods(unittest.TestCase):

    def test_parse_cloud_zone1(self):
        conn = CloudConnection(token="")
        p = conn._parse_policy_response_to_object(json.loads(POLICY_CLOUD1))
        self.assertEqual(p.id, "3da4ba30-c370-11e9-9e69-99559a9ae32a")
        self.assertEqual(p.SubjectCNRegexes[-1], ".*.test")
        self.assertTrue(
            p.SubjectCRegexes == p.SubjectLRegexes == p.SubjectORegexes == p.SubjectOURegexes == p.SubjectSTRegexes == [
                ".*"])
        self.assertEqual(p.key_types[0].key_type, KeyType.RSA)
        self.assertEqual(p.key_types[0].option, 2048)
        self.assertEqual(p.key_types[1].key_type, KeyType.RSA)
        self.assertEqual(p.key_types[1].option, 4096)
        self.assertTrue(len(p.key_types) == 2)

    #  cloud doesnt support ecdsa yet. may be can be enabled in the future
    # def test_parse_cloud_zone2(self):
    #     conn = CloudConnection(token="")
    #     p = conn._parse_policy_responce_to_object(json.loads(POLICY_CLOUD2))
    #     self.assertTrue(len(p.key_types) == 2)
    #     self.assertEqual(p.key_types[1].key_type, KeyType.RSA)
    #     self.assertEqual(p.key_types[0].key_type,   KeyType.ECDSA)
    #     self.assertEqual(p.key_types[0].key_curves,  ["p521"])

    def test_parse_tpp_zone1(self):
        conn = TPPConnection(url="http://example.com/", user="", password="")
        z = conn._parse_zone_data_to_object(json.loads(POLICY_TPP1))
        self.assertEqual(z.country.value, "US")
        self.assertEqual(z.locality.value, "Salt Lake")
        self.assertEqual(z.province.value, "Utah")
        self.assertEqual(z.organization.value, "Venafi Inc.")

    def test_parse_tpp_policy1(self):
        conn = TPPConnection(url="http://example.com/", user="", password="")
        raw_data = json.loads(POLICY_TPP1)
        p = conn._parse_zone_config_to_policy(raw_data)
        self.assertEqual(len(p.key_types), 7)
        raw_data['Policy']['KeyPair']['KeySize']['Locked'] = True
        p = conn._parse_zone_config_to_policy(raw_data)
        self.assertEqual(len(p.key_types), 4)
        raw_data['Policy']['KeyPair']['KeyAlgorithm']['Locked'] = True
        p = conn._parse_zone_config_to_policy(raw_data)
        self.assertEqual(len(p.key_types), 1)

    def test_update_request_with_zone_config(self):
        r = CertificateRequest()
        z = ZoneConfig(
            organization=CertField("Venafi"),
            organizational_unit=CertField(""),
            country=CertField(""),
            province=CertField(""),
            locality=CertField(""),
            policy=None,
            key_type=None
        )
        r.update_from_zone_config(z)
        self.assertEqual(r.organization, "Venafi")
        r = CertificateRequest(organization="Test")
        r.update_from_zone_config(z)
        self.assertEqual(r.organization, "Test")
        z = ZoneConfig(
            organization=CertField("Venafi", locked=True),
            organizational_unit=CertField(""),
            country=CertField(""),
            province=CertField(""),
            locality=CertField(""),
            policy=None,
            key_type=None
        )
        r.update_from_zone_config(z)
        self.assertEqual(r.organization, "Venafi")

    def test_request_with_csr(self):
        req = CertificateRequest(common_name="test.example.com", csr=EXAMPLE_CSR)
        self.assertEqual(req.common_name, "test.example.com")
        with self.assertRaises(Exception):
            CertificateRequest(common_name="test2.example.com", csr=EXAMPLE_CSR)
        req = CertificateRequest(csr=EXAMPLE_CSR)
        self.assertEqual(req.common_name, None)

    def test_generate_rsa_csr(self):
        req = CertificateRequest(common_name="test.example.com", key_type=KeyType("rsa", 2048))
        req.build_csr()
        req = x509.load_pem_x509_csr(req.csr.encode(), default_backend())
        self.assertEqual(req.public_key().key_size, 2048)

    def test_generate_ecdsa_csr(self):
        req = CertificateRequest(common_name="test.exampe.com", key_type=KeyType("ecdsa", "p384"))
        req.build_csr()
        req = x509.load_pem_x509_csr(req.csr.encode(), default_backend())
        self.assertEqual(req.public_key().curve.name, "secp384r1")

    def test_generate_rsa_key(self):
        req = CertificateRequest(common_name="test.example.com", key_type=KeyType("rsa", 2048))
        req._gen_key()
        self.assertEqual(req.public_key.key_size, 2048)

    def test_generate_ecdsa_key(self):
        req = CertificateRequest(common_name="test.exampe.com", key_type=KeyType("ecdsa", "p384"))
        req._gen_key()
        self.assertEqual(req.public_key.curve.name, "secp384r1")

    def test_parse_key_arguments(self):
        k = KeyType("rsa", 2048)
        self.assertEqual(k.key_type, k.RSA)
        self.assertEqual(k.option, 2048)
        k = KeyType("Rsa", 4096)
        self.assertEqual(k.key_type, k.RSA)
        self.assertEqual(k.option, 4096)
        k = KeyType("ecdsa", "secp256r1")
        self.assertEqual(k.key_type, k.ECDSA)
        self.assertEqual(k.option, "p256")
        with self.assertRaises(Exception):
            k = KeyType("ololo", 2048)
        with self.assertRaises(Exception):
            k = KeyType("ecdsa", 2048)
        with self.assertRaises(Exception):
            k = KeyType("ecdsa", "secp256k1")
        with self.assertRaises(Exception):
            k = KeyType("rsa", "")
        with self.assertRaises(Exception):
            k = KeyType("rsa", 1024)
        with self.assertRaises(Exception):
            k = KeyType("rsa", None)

    def test_pass_invalid_key_type_to_request(self):
        with self.assertRaises(Exception):
            req = CertificateRequest(common_name="test.example.com", key_type="rsa")

    def test_return_pem_private_key(self):
        req = CertificateRequest(common_name="test.example.com", key_password="ololo")
        req.build_csr()
        self.assertIn("ENCRYPTED", req.private_key_pem)
        req = CertificateRequest(common_name="test.example.com")
        req.build_csr()
        self.assertNotIn("ENCRYPTED", req.private_key_pem)

    def test_return_pem_csr(self):
        req = CertificateRequest(common_name="test.example.com")
        req.build_csr()
        self.assertIn("CERTIFICATE REQUEST", req.csr)

    def test_return_pem_cert(self):
        conn = FakeConnection()
        req = CertificateRequest(common_name="test.example.com")
        conn.request_cert(req, "")
        cert = conn.retrieve_cert(req)
        self.assertIn("BEGIN CERTIFICATE", cert.cert)

    def test_tpp_url_normalization(self):
        conn = TPPConnection(url="localhost", user="user", password="password")
        self.assertEqual(conn._base_url, "https://localhost/")
        conn._base_url = "http://localhost:8080"
        self.assertEqual(conn._base_url, "https://localhost:8080/")
        conn._base_url = "http://localhost:8080/vedsdk"
        self.assertEqual(conn._base_url, "https://localhost:8080/")
        with self.assertRaises(Exception):
            conn._base_url = "ftp://example.com"
        with self.assertRaises(Exception):
            conn._base_url = ""
        with self.assertRaises(Exception):
            conn._base_url = "https://"

    def test_parse_pem_chain(self):
        cert = parse_pem(EXAMPLE_CHAIN, "last")
        self.assertEqual(len(cert.chain), 2)
        self.assertIn("PRIVATE", cert.key)
        c = x509.load_pem_x509_certificate(cert.cert.encode(), default_backend())
        for a in c.subject:
            if a.oid == x509.NameOID.COMMON_NAME:
                subject = a.value
        self.assertEqual(subject, "test2.example.com")

    def test_pkcs12_enc_pk(self):
        certificate = Certificate(cert=pkcs12_enc_cert, chain=chain, key=pkcs12_enc_pk)
        output = certificate.as_pkcs12(passphrase=pkcs12_enc_pk_pass)
        log.info("PKCS12 created successfully:\n%s" % output)

    def test_pkcs12_plain_pk(self):
        cert = Certificate(cert=pkcs12_plain_cert, chain=chain, key=pkcs12_plain_pk)
        output = cert.as_pkcs12()
        log.info("PKCS12 created successfully:\n%s" % output)
        pass
