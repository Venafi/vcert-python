#
# Copyright 2020 Venafi, Inc.
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
import logging as log
import re
from pprint import pprint

from vcert.common import CertField, CommonConnection
from vcert.errors import VenafiError, ServerUnexptedBehavior, ClientBadData
from vcert.http import HTTPStatus
from vcert.policy import RPA, POLICY_CLASS, ROOT_PATH, SPA
from vcert.policy.pm_tpp import TPPPolicy, is_service_generated_csr, SetAttrResponse, validate_policy_spec, \
    get_int_value

POLICY_ATTR_CLASS = "X509 Certificate"  # type: str


class URLS:
    API_TOKEN_URL = "vedauth/"  # type: str  # nosec
    API_BASE_URL = "vedsdk/"  # type: str  # nosec

    AUTHORIZE_TOKEN = API_TOKEN_URL + "authorize/oauth"  # type: str
    REFRESH_TOKEN = API_TOKEN_URL + "authorize/token"  # type: str
    REVOKE_TOKEN = API_TOKEN_URL + "revoke/token"  # type: str

    AUTHORIZE = API_BASE_URL + "authorize/"
    CERTIFICATE_REQUESTS = API_BASE_URL + "certificates/request"
    CERTIFICATE_RETRIEVE = API_BASE_URL + "certificates/retrieve"
    FIND_POLICY = API_BASE_URL + "config/findpolicy"
    CERTIFICATE_REVOKE = API_BASE_URL + "certificates/revoke"
    CERTIFICATE_RENEW = API_BASE_URL + "certificates/renew"
    CERTIFICATE_SEARCH = API_BASE_URL + "certificates/"
    CERTIFICATE_IMPORT = API_BASE_URL + "certificates/import"
    ZONE_CONFIG = API_BASE_URL + "certificates/checkpolicy"
    CONFIG_READ_DN = API_BASE_URL + "Config/ReadDn"

    POLICY_IS_VALID = API_BASE_URL + "config/isvalid"
    POLICY_CREATE = API_BASE_URL + "config/create"
    POLICY_SET_ATTRIBUTE = API_BASE_URL + "config/writepolicy"
    POLICY_CLEAR_ATTRIBUTE = API_BASE_URL + "config/clearpolicyattribute"

    def __init__(self):
        pass


class AbstractTPPConnection(CommonConnection):

    def get_policy_specification(self, zone):
        # get policy spec from name
        policy_name = self._normalize_zone(zone)
        exists = self._policy_exists(policy_name)
        if not exists:
            log.error('The Policy %s does not exist', policy_name)
            raise VenafiError

        status, data = self._post(URLS.ZONE_CONFIG, {"PolicyDN": policy_name})
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior("Server returns %d status on reading policy configuration." % status)

        if not ('Policy' in data):
            raise VenafiError("Policy structure not found in response data for [%s] policy", policy_name)
        p = data['Policy']
        tpp_policy = TPPPolicy()

        value = 'Value'
        locked = 'Locked'

        # Contact
        if RPA.TPP_CONTACT in p:
            tpp_policy.contact = [p[RPA.TPP_CONTACT][value]]

        # Approver
        if RPA.TPP_APPROVER in p:
            tpp_policy.approver = [p[RPA.TPP_APPROVER][value]]

        # Prohibited wildcard
        if RPA.TPP_WILDCARDS_ALLOWED in p:
            tpp_policy.wildcards_allowed = p[RPA.TPP_WILDCARDS_ALLOWED]

        # Domain suffix whitelist
        if RPA.TPP_DOMAIN_SUFFIX_WHITELIST in p:
            tpp_policy.domain_suffix_whitelist = p[RPA.TPP_DOMAIN_SUFFIX_WHITELIST]

        # Certification Authority
        if RPA.TPP_CERT_AUTHORITY in p:
            tpp_policy.cert_authority = p[RPA.TPP_CERT_AUTHORITY][value]

        # Management Type
        if RPA.TPP_MANAGEMENT_TYPE in p:
            tpp_policy.management_type = p[RPA.TPP_MANAGEMENT_TYPE][value]

        if not ('Subject' in p):
            raise VenafiError("Subject structure not found in response data for [%s] policy", policy_name)
        subject = p['Subject']

        # Organization
        if RPA.TPP_ORGANIZATION in subject:
            org = subject[RPA.TPP_ORGANIZATION]
            tpp_policy.org = CertField(org[value], org[locked])

        # Organizational Unit
        if RPA.TPP_ORG_UNIT in subject:
            ou = subject[RPA.TPP_ORG_UNIT]
            tpp_policy.org_unit = CertField(ou[value+"s"], ou[locked])

        # City
        if RPA.TPP_CITY in subject:
            city = subject[RPA.TPP_CITY]
            tpp_policy.city = CertField(city[value], city[locked])

        # State
        if RPA.TPP_STATE in subject:
            st = subject[RPA.TPP_STATE]
            tpp_policy.state = CertField(st[value], st[locked])

        # Country
        if RPA.TPP_COUNTRY in subject:
            country = subject[RPA.TPP_COUNTRY]
            tpp_policy.country = CertField(country[value], country[locked])

        if not ('KeyPair' in p):
            raise VenafiError("KeyPair structure not found in response data for [%s] policy", policy_name)
        kp = p['KeyPair']

        # Key Algorithm
        if RPA.TPP_KEY_ALGORITHM in kp:
            tpp_policy.key_algo = CertField(kp[RPA.TPP_KEY_ALGORITHM][value], kp[RPA.TPP_KEY_ALGORITHM][locked])

        # Key Bit Strength
        if RPA.TPP_KEY_SIZE in kp:
            tpp_policy.key_bit_str = CertField(kp[RPA.TPP_KEY_SIZE][value], kp[RPA.TPP_KEY_SIZE][locked])

        # Elliptic Curve
        if RPA.TPP_ELLIPTIC_CURVE in kp:
            tpp_policy.elliptic_curve = CertField(kp[RPA.TPP_ELLIPTIC_CURVE][value], kp[RPA.TPP_ELLIPTIC_CURVE][locked])

        # Manual CSR
        if RPA.TPP_CSR_GENERATION in p:
            bool_val = is_service_generated_csr(p[RPA.TPP_CSR_GENERATION][value])
            tpp_policy.service_generated = CertField(bool_val, p[RPA.TPP_CSR_GENERATION][locked])

        # ALLOWED SANS
        if RPA.TPP_DNS_ALLOWED in p:
            tpp_policy.dns_allowed = p[RPA.TPP_DNS_ALLOWED]
        if RPA.TPP_EMAIL_ALLOWED in p:
            tpp_policy.email_allowed = p[RPA.TPP_EMAIL_ALLOWED]
        if RPA.TPP_IP_ALLOWED in p:
            tpp_policy.ip_allowed = p[RPA.TPP_IP_ALLOWED]
        if RPA.TPP_UPN_ALLOWED in p:
            tpp_policy.upn_allowed = p[RPA.TPP_UPN_ALLOWED]
        if RPA.TPP_URI_ALLOWED in p:
            tpp_policy.uri_allowed = p[RPA.TPP_URI_ALLOWED]

        # Allow Private Key Reuse
        if RPA.TPP_ALLOWED_PRIVATE_KEY_REUSE in p:
            tpp_policy.allow_private_key_reuse = p[RPA.TPP_ALLOWED_PRIVATE_KEY_REUSE]

        # TPP Want Renewal
        # tpp_want_renewal, _ = self._get_policy_attr(policy_name, TPPPolicyAttr.TPP_WANT_RENEWAL)
        # if tpp_want_renewal:
        #     tpp_policy.want_renewal = tpp_want_renewal[0]

        log.info("Building Policy Specification")
        spec = tpp_policy.to_policy_spec()

        return spec

    def set_policy(self, zone, policy_spec):
        """
        :param str zone:
        :param PolicySpecification policy_spec:
        :rtype: PolicySpecification
        """
        validate_policy_spec(policy_spec)
        tpp_policy = TPPPolicy.build_tpp_policy(policy_spec)
        name = self._normalize_zone(zone)
        tpp_policy.name = name

        create_policy = False
        policy_exists = self._policy_exists(name)
        if not policy_exists:
            log.info("Policy [%s] does not exist, validating parent existence", name)
            parent_name = self._get_policy_parent(name)
            if self._policy_exists(parent_name) or parent_name == ROOT_PATH:
                log.info("Parent policy [%s] exists", parent_name)
                create_policy = True
            else:
                raise VenafiError("Parent Policy [%s] does not exist", parent_name)

        # Create the policy if necessary
        if create_policy:
            log.info("Creating Policy [%s]", name)
            policy_request_data = {
                "Class": POLICY_CLASS,
                "ObjectDN": name
            }
            status, resp_data = self._post(URLS.POLICY_CREATE, data=policy_request_data)
            if status != HTTPStatus.OK:
                raise VenafiError("Failed to create policy [%s]. Status %s" % (name, status))

        # Set attributes to policy
        if tpp_policy.contact:
            self._set_policy_attr(name, SPA.TPP_CONTACT, tpp_policy.contact, True)
        if tpp_policy.approver:
            self._set_policy_attr(name, SPA.TPP_APPROVER, tpp_policy.approver, True)

        # Reset all values for existing policy before setting the new ones.
        # This way, values that do not get updated will be inherited from parent.
        if policy_exists:
            self._reset_policy(name)

        if tpp_policy.domain_suffix_whitelist:
            self._set_policy_attr(name, SPA.TPP_DOMAIN_SUFFIX_WHITELIST, tpp_policy.domain_suffix_whitelist, True)
        if tpp_policy.cert_authority:
            self._set_policy_attr(name, SPA.TPP_CERT_AUTHORITY, [tpp_policy.cert_authority], False)
        if tpp_policy.org:
            self._set_policy_attr(name, SPA.TPP_ORGANIZATION, [tpp_policy.org.value], tpp_policy.org.locked)
        if tpp_policy.org_unit:
            self._set_policy_attr(name, SPA.TPP_ORG_UNIT, [tpp_policy.org_unit.value], tpp_policy.org_unit.locked)
        if tpp_policy.city:
            self._set_policy_attr(name, SPA.TPP_CITY, [tpp_policy.city.value], tpp_policy.city.locked)
        if tpp_policy.state:
            self._set_policy_attr(name, SPA.TPP_STATE, [tpp_policy.state.value], tpp_policy.state.locked)
        if tpp_policy.country:
            self._set_policy_attr(name, SPA.TPP_COUNTRY, [tpp_policy.country.value], tpp_policy.state.locked)
        if tpp_policy.key_algo:
            self._set_policy_attr(name, SPA.TPP_KEY_ALGORITHM, [tpp_policy.key_algo.value], tpp_policy.key_algo.locked)
        if tpp_policy.key_bit_str:
            self._set_policy_attr(name, SPA.TPP_KEY_BIT_STR, [tpp_policy.key_bit_str.value],
                                  tpp_policy.key_bit_str.locked)
        if tpp_policy.elliptic_curve:
            self._set_policy_attr(name, SPA.TPP_ELLIPTIC_CURVE, [tpp_policy.elliptic_curve.value],
                                  tpp_policy.elliptic_curve.locked)
        if tpp_policy.management_type:
            self._set_policy_attr(name, SPA.TPP_MANAGEMENT_TYPE, [tpp_policy.management_type.value],
                                  tpp_policy.management_type.locked)

        if tpp_policy.wildcards_allowed is not None:
            int_val = get_int_value(not tpp_policy.wildcards_allowed)
            self._set_policy_attr(name, SPA.TPP_PROHIBIT_WILDCARD, [int_val], False)
        if tpp_policy.service_generated is not None:
            int_val = get_int_value(not tpp_policy.service_generated)
            self._set_policy_attr(name, SPA.TPP_MANUAL_CSR, [int_val], tpp_policy.service_generated.locked)
        if tpp_policy.allow_private_key_reuse is not None:
            int_val = get_int_value(tpp_policy.allow_private_key_reuse)
            self._set_policy_attr(name, SPA.TPP_ALLOWED_PRIVATE_KEY_REUSE, [int_val], True)
        if tpp_policy.want_renewal is not None:
            int_val = get_int_value(tpp_policy.want_renewal)
            self._set_policy_attr(name, SPA.TPP_WANT_RENEWAL, [int_val], True)

        prohibited_sans = tpp_policy.get_prohibited_sans()
        if len(prohibited_sans) > 0:
            self._set_policy_attr(name, SPA.TPP_PROHIBITED_SAN_TYPES, prohibited_sans, False)

        return

    def _policy_exists(self, zone):
        """
        :param str zone:
        :rtype bool:
        """
        req_data = {"ObjectDN": zone}
        status, data = self._post(URLS.POLICY_IS_VALID, data=req_data)

        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior('Could not complete request. Status %s. %s' % (status, pprint(data)))

        if data['Result'] == 1 and data['Object']['TypeName'] == POLICY_CLASS:
            return True
        elif data['Result'] == 400 and 'Error' in data:
            return False

        log.error("Unknown error while executing. Status: %s.Data: %s." % (status, pprint(data)))
        raise VenafiError

    def _set_policy_attr(self, zone, attr_name, attr_values, locked):
        """
        :param str zone: The policy name
        :param str attr_name: The name of the attribute to be set
        :param any attr_values: The values assigned to the attr_name
        :param bool locked: Whether the attribute should be policy locked
        :rtype: tuple[str, SetAttrResponse]
        """
        data = {
            'Locked': locked,
            'ObjectDN': zone,
            'Class': POLICY_ATTR_CLASS,
            'AttributeName': attr_name,
            'Values': attr_values
        }

        status, response = self._post(URLS.POLICY_SET_ATTRIBUTE, data=data)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior('Got status %s from server', status)

        response = self._parse_attr_response(response)

        if response.error:
            raise VenafiError('Error while setting attribute [%s] in policy [%s]' % (attr_name, zone))

        return status, response

    def _reset_policy_attr(self, zone, attr_name):
        """
        :param str zone:
        :param str attr_name:
        :rtype: tuple[str, SetAttrResponse]
        """
        data = {
            'ObjectDN': zone,
            'Class':  POLICY_ATTR_CLASS,
            'AttributeName': attr_name,
        }

        status, response = self._post(URLS.POLICY_CLEAR_ATTRIBUTE, data=data)
        if status != HTTPStatus.OK:
            raise ServerUnexptedBehavior('Got status %s from server', status)

        response = self._parse_attr_response(response)

        if response.error:
            raise VenafiError('Error while setting attribute [%s] in policy [%s]' % (attr_name, zone))

        return status, response

    def _reset_policy(self, zone):
        self._reset_policy_attr(zone, SPA.TPP_DOMAIN_SUFFIX_WHITELIST)
        self._reset_policy_attr(zone, SPA.TPP_PROHIBIT_WILDCARD)
        self._reset_policy_attr(zone, SPA.TPP_CERT_AUTHORITY)
        self._reset_policy_attr(zone, SPA.TPP_ORGANIZATION)
        self._reset_policy_attr(zone, SPA.TPP_ORG_UNIT)
        self._reset_policy_attr(zone, SPA.TPP_CITY)
        self._reset_policy_attr(zone, SPA.TPP_STATE)
        self._reset_policy_attr(zone, SPA.TPP_COUNTRY)
        self._reset_policy_attr(zone, SPA.TPP_KEY_ALGORITHM)
        self._reset_policy_attr(zone, SPA.TPP_KEY_BIT_STR)
        self._reset_policy_attr(zone, SPA.TPP_ELLIPTIC_CURVE)
        self._reset_policy_attr(zone, SPA.TPP_MANUAL_CSR)
        self._reset_policy_attr(zone, SPA.TPP_PROHIBITED_SAN_TYPES)
        self._reset_policy_attr(zone, SPA.TPP_ALLOWED_PRIVATE_KEY_REUSE)
        self._reset_policy_attr(zone, SPA.TPP_WANT_RENEWAL)
        self._reset_policy_attr(zone, SPA.TPP_MANAGEMENT_TYPE)

    @staticmethod
    def _parse_attr_response(response):
        """
        :param dict response:
        :rtype: SetAttrResponse
        """
        if not response:
            raise VenafiError('Response is empty')

        err = response['Error'] if 'Error' in response else None
        result = response['Result'] if 'Result' in response else None

        return SetAttrResponse(result, err)


    @staticmethod
    def _normalize_zone(zone):
        if zone is None:
            log.error("Bad zone: %s" % zone)
            raise ClientBadData
        if re.match(r"^\\VED\\Policy\\.*", zone):
            return zone
        else:
            if re.match(r"^\\", zone):
                return "\\VED\\Policy" + zone
            else:
                return "\\VED\\Policy\\" + zone

    @staticmethod
    def _get_policy_parent(zone):
        """
        :param str zone:
        """
        if zone is None:
            raise ClientBadData('Zone is empty:')
        index = zone.rindex('\\')
        # Return a substring of zone that starts at 0 and ends at index. Zone here is treated as an slice
        # zone[0:index] returns the same result
        return zone[:index]
