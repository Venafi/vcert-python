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
from vcert.common import Policy as Cit
from vcert.errors import VenafiError
from vcert.policy.policy_spec import Policy, Subject, KeyPair, DefaultSubject, DefaultKeyPair, PolicySpecification, \
    Defaults


def build_policy_spec(cit):
    """
    :param Cit cit:
    :rtype: PolicySpecification
    """
    if not cit:
        raise VenafiError("Certificate issuing template is empty")

    p = Policy()
    p.domains = cit.SubjectCRegexes if len(cit.SubjectCRegexes) > 0 else None
    p.certificate_authority = cit.cert_authority_account_id if cit.cert_authority_account_id else None
    if cit.validity_period:
        # getting days in format P#D
        days = cit.validity_period[1:len(cit.validity_period)-1]
        int_value = int(days)
        p.max_valid_days = int_value

    s = Subject()
    create_subject = False
    if len(cit.SubjectORegexes) > 0:
        create_subject = True
        s.organizations = cit.SubjectORegexes
    if len(cit.SubjectOURegexes) > 0:
        create_subject = True
        s.org_units = cit.SubjectOURegexes
    if len(cit.SubjectLRegexes) > 0:
        create_subject = True
        s.localities = cit.SubjectLRegexes
    if len(cit.SubjectSTRegexes) > 0:
        create_subject = True
        s.states = cit.SubjectSTRegexes
    if len(cit.SubjectCRegexes) > 0:
        create_subject = True
        s.countries = cit.SubjectCRegexes

    p.subject = s if create_subject else None

    kp = KeyPair()
    create_kp = False
    if len(cit.key_types) > 0:
        key_types = []
        key_sizes = []
        for allowed_kt in cit.key_types:
            kt = allowed_kt.key_type
            kl = allowed_kt.option
            key_types.append(kt)
            key_sizes.append(kl)
        create_kp = True
        kp.key_types = key_types
        kp.rsa_key_sizes = key_sizes

    kp.reuse_allowed = cit.key_reuse
    p.key_pair = kp if create_kp else None

    rs = cit.recommended_settings
    if rs:
        d = Defaults()
        ds = DefaultSubject()
        create_ds = False
        if rs.subjectOValue:
            ds.organization = rs.subjectOValue
            create_ds = True
        if rs.subjectOUValue:
            ds.org_units = [rs.subjectOUValue]
            create_ds = True
        if rs.subjectLValue:
            ds.locality = rs.subjectLValue
            create_ds = True
        if rs.subjectSTValue:
            ds.state = rs.subjectSTValue
            create_ds = True
        if rs.subjectCValue:
            ds.country = rs.subjectCValue
            create_ds = True

        d.subject = ds if create_ds else None

        kt = rs.keyType
        if kt:
            dkp = DefaultKeyPair()
            create_dkp = False
            if kt.key_type:
                dkp.key_type = kt.key_type
                create_dkp = True
            if kt.option:
                dkp.rsa_key_size = kt.option
                create_dkp = True
            d.key_pair = dkp if create_dkp else None

    ps = PolicySpecification()
    ps.policy = p
    ps.defaults = d

    return ps
