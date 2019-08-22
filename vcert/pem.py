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

from __future__ import (absolute_import, division, generators, unicode_literals, print_function, nested_scopes,
                        with_statement)
import re


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
        if p[0] == "CERTIFICATE":
            certs.append(p[1])
        elif p[0] == "PRIVATE KEY":
            key = p[1]
    if order == "last":
        return Certificate(certs[0], certs[1:], key)
    else:
        return Certificate(certs[-1], certs[:-1], key)


class Certificate:
    def __init__(self, cert=None, chain=None, key=None):
        self.cert = cert
        self.chain = chain
        self.key = key

    @property
    def full_chain(self):
        if not self.chain:
            return self.cert
        return self.cert + "\n" + "\n".join(self.chain)

