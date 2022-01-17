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
import random
import re
import string

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from .errors import VenafiError
from .logger import get_logger

_PEM_TYPES = [
    "CERTIFICATE",
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "RSA PRIVATE KEY",
    "CERTIFICATE REQUEST",
]

_PEM_RE = re.compile(
    "-----BEGIN ("
    + "|".join(_PEM_TYPES)
    + """)-----\r?
.+?\r?
-----END \\1-----\r?\n?""",
    re.DOTALL,
)


def parse_pem(pem_str, order):
    parsed = [
        (match.group(1), (match.group(0)))
        for match in _PEM_RE.finditer(pem_str)
    ]
    certs = []
    key = None
    for p in parsed:
        if p[0] == 'CERTIFICATE':
            certs.append(p[1])
        elif p[0].endswith('PRIVATE KEY'):
            key = p[1]
    if order == 'last':
        return Certificate(certs[0], certs[1:], key)
    else:
        return Certificate(certs[-1], certs[:-1], key)


class Certificate:
    def __init__(self, cert=None, chain=None, key=None):
        """

        :param str cert:
        :param list chain:
        :param str key:
        """
        self.cert = cert
        self.chain = chain
        self.key = key

    @property
    def full_chain(self):
        """

        :rtype: str
        """
        if not self.chain:
            return self.cert
        full_chain = "\n".join(self.chain)
        return f"{self.cert}\n{full_chain}"

    def as_pkcs12(self, passphrase=None):
        """

        :param str passphrase:
        :rtype: str
        """
        if not self.cert or not self.key:
            get_logger().error("PKCS12 output: Certificate or Private Key is None.")
            raise VenafiError("Certificate and Private Key are required for PKCS12 output.")

        certificate = x509.load_pem_x509_certificate(self.cert.encode(), default_backend())
        cas = []
        if self.chain:
            for x in self.chain:
                chain_x509 = x509.load_pem_x509_certificate(x.encode(), default_backend())
                cas.append(chain_x509)
        if passphrase:
            b_pass = passphrase.encode()
            encryption = serialization.BestAvailableEncryption(b_pass)
        else:
            encryption = serialization.NoEncryption()
            b_pass = None
        try:
            p_key = serialization.load_pem_private_key(data=self.key.encode(), password=b_pass,
                                                       backend=default_backend())
        except Exception as e:
            get_logger().error(msg=f"Error parsing Private Key: {e.message}")
            return

        name = random_word(10).encode()
        output = pkcs12.serialize_key_and_certificates(name, p_key, certificate, cas, encryption)
        return output


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))  # nosec
