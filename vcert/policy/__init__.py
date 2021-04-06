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

JSON_EXT = ".json"
YAML_EXT = ".yaml"
POLICY_PATH = "Policy\\"
ROOT_PATH = "\\VED\\" + POLICY_PATH
POLICY_CLASS = "Policy"
POLICY_ATTRIBUTE_CLASS = "X509 Certificate"


class CommonPA:
    def __init__(self):
        pass

    TPP_CONTACT = "Contact"
    TPP_APPROVER = "Approver"
    TPP_ORGANIZATION = "Organization"
    TPP_CITY = "City"
    TPP_STATE = "State"
    TPP_COUNTRY = "Country"


# tpp read policy attributes - RPA
class RPA(CommonPA):
    def __init__(self):
        pass

    TPP_CERT_AUTHORITY = "CertificateAuthority"  # "Certificate Authority"
    TPP_WILDCARDS_ALLOWED = "WildcardsAllowed"
    TPP_DOMAIN_SUFFIX_WHITELIST = "WhitelistedDomains"  # "Domain Suffix Whitelist"
    TPP_ORG_UNIT = 'OrganizationalUnit'  # "Organizational Unit"
    TPP_KEY_ALGORITHM = 'KeyAlgorithm'  # "Key Algorithm"
    TPP_KEY_SIZE = 'KeySize'
    TPP_ELLIPTIC_CURVE = 'EllipticCurve'  # "Elliptic Curve"
    TPP_CSR_GENERATION = 'CsrGeneration'
    TPP_ALLOWED_PRIVATE_KEY_REUSE = 'PrivateKeyReuseAllowed'  # "Allow Private Key Reuse"
    TPP_WANT_RENEWAL = "Want Renewal"
    ALLOW_ALL = ".*"

    TPP_DNS_ALLOWED = "SubjAltNameDnsAllowed"
    TPP_EMAIL_ALLOWED = "SubjAltNameEmailAllowed"
    TPP_IP_ALLOWED = "SubjAltNameIpAllowed"
    TPP_UPN_ALLOWED = "SubjAltNameUpnAllowed"
    TPP_URI_ALLOWED = "SubjAltNameUriAllowed"


# tpp set policy attributes - SPA
class SPA(CommonPA):
    def __init__(self):
        pass

    TPP_CERT_AUTHORITY = "Certificate Authority"
    TPP_PROHIBIT_WILDCARD = "Prohibit Wildcard"
    TPP_DOMAIN_SUFFIX_WHITELIST = "Domain Suffix Whitelist"
    TPP_ORG_UNIT = "Organizational Unit"
    TPP_KEY_ALGORITHM = "Key Algorithm"
    TPP_KEY_BIT_STR = "Key Bit Strength"
    TPP_ELLIPTIC_CURVE = "Elliptic Curve"
    TPP_MANUAL_CSR = "Manual Csr"
    TPP_PROHIBITED_SAN_TYPES = "Prohibited SAN Types"
    TPP_ALLOWED_PRIVATE_KEY_REUSE = "Allow Private Key Reuse"
    TPP_WANT_RENEWAL = "Want Renewal"
    ALLOW_ALL = ".*"

    TPP_DNS = "DNS"
    TPP_EMAIL = "Email"
    TPP_IP = "IP"
    TPP_UPN = "UPN"
    TPP_URI = "URI"
