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
ROOT_PATH = "\\VED\\Policy\\"
POLICY_CLASS = "Policy"
POLICY_ATTRIBUTE_CLASS = "X509 Certificate"

# tpp policy_mngmnt attributes
TPP_CONTACT = "Contact"
TPP_APPROVER = "Approver"
TPP_CA = "Certificate Authority"
TPP_PROHIBIT_WILDCARD = "Prohibit Wildcard"
TPP_DOMAIN_SUFFIX_WHITELIST = "Domain Suffix Whitelist"
TPP_ORG = "Organization"
TPP_ORG_UNIT = "Organizational Unit"
TPP_CITY = "City"
TPP_STATE = "State"
TPP_COUNTRY = "Country"
TPP_KEY_ALGORITHM = "Key Algorithm"
TPP_KEY_BIT_STR = "Key Bit Strength"
TPP_ELLIPTIC_CURVE = "Elliptic Curve"
TPP_MANUAL_CSR = "Manual Csr"
TPP_PROHIBITED_SAN_TYPES = "Prohibited SAN Types"
TPP_ALLOWED_PRIVATE_KEY_REUSE = "Allow Private Key Reuse"
TPP_WANT_RENEWAL = "Want Renewal"
TPP_DNS_ALLOWED = "DNS"
TPP_IP_ALLOWED = "IP"
TPP_EMAIL_ALLOWED = "Email"
TPP_URI_ALLOWED = "URI"
TPP_UPN_ALLOWED = "UPN"
ALLOW_ALL = ".*"
