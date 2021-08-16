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
TEST_KEY_RSA_2048_ENCRYPTED = ("""
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,4C68B019B2BFC3E7E2C390A3A6751E00

mLrpIxg4S287bNYhpcO18R05ODFy0qlBY3prko0OI9nXRlxaCVa2knEBmU9S6VNR
7dtxIghXn4T6hwHP12hgNLQFoIFe9JWCPjH2rmxYUuYrYkVK4FvpYYBtubiJbCmn
hkXhHTXhieZ3AMgaXfFsTwX2DZAcjz3kAnMh/G7Yygr1IS3FANOT1lFU3jUFoOyz
EUBw5+ez1NP0K9i7115B4c/axZScTP/9hbXESA6n1Ky942OkahfKOwcT5nrgou9M
djaOqLcBNpZH6XVZsf87IhrJltThso6+lFSL2EwFnP4V/Gaq2dNbEjXQorsRKmX9
/RQG5TIp/3HG311jOKJLw+6/mUGU0Wkkr0f+pL/FyvrxS61pQzo/KZ6kcidtNouY
okMaWwP4IYXkr3YboQ4R6NrsnjQiQGfaDOazbIzlX8oPSbeRv1jaKIxCQK9WGEMj
tY/swWy3kSMZIqcglqJzpeKysxZO6WHP230Zohhp2Q8lBLggQjJCMmYiSnq8WQ6r
02YvHNRMyYBoVvUaA5ruCNJkBEIJrJcPA66e7yUqFfR4En2FlwVQPIWugo3fOnU1
3CIknfsDzy28gjb9fk3WNEIUZMEdjbf0djqYw5z6v9ksOYwWwUvvwBMnyFLlEuet
2zH5DTDxUhP0zD2qxY/3/+wZ3c1X1WRg6zZB0CfZRWcCtUs/VSP4+ltDdin08CX8
13UOF2GKks8iAhQSyIyrRHfFSROAJ7eDYHs/tCVeIjv0qS4SYTiEhR13A1GFzJzd
GfjIBh7496uLCEgoYC4KkeKWoXG6o8WTwLld/dcBxgn5vBwheMVdZG/5gKypHDNe
RHcSbmNsE18dIhpGDIuutEiNGypWQnQajM97cdGr3R8O1WmbIo1P1F7fAjH8kre+
iUU896nbvqEZ6xvhoWxwPp4dyEktajE5+purlS27XIXXprTFFSpmHS709EzFmrHS
iZZjWuqCuvFneCc8nkk1+F1RBrqoHW6ZEFyI9B4y4czs0t0NJeIK5+RX9vDuvA3Y
j9QVTg5xVx2WYkll0YWRlZmSzfxpucDYN6TStSNk2LeoEnirsmxppRb9doqk8juA
NNDUJSZTUtCRYOcuKvg7mks3Jh46xIDwhbNM1MvacB3IB0ZUCKIrQ7UWj6JmRWnF
/S3wvqEUsavIuGAqEVJAq8qz/eoGYlffTluQXTuwl2tx9n36hMbwRPtsq/iLkQHz
IXKU/bzfjJN5QiOEoL8tu9o1T8kvT8bRsLaIFiAR9o3azKonZEY11HE46W9B6qIx
Qh6NSvyRIpMUt9BShkGlo9kA/hWLDA9nRJ+b4wbmvvFxfJg75cCrewvRGijBDJ35
vMQck6r5K7WA8gZgzJv4juP9ik6BssqnCb7tdUWyei725Uh3CRzwjiYzGCrArzp/
48GSM9QntGrPF4lFymjm030zsYDPzEtAsR3pmjJXP9oT/dPR5SCWzM9E2AwSgap1
FfEaT87Jbir/OjG7kuwPKPC0JMwZ1a5dNQic36RYY1Uu6Riv2nJLYHuIVDcmyiRU
JpNJPumQuxhY9KPxRPq89hsh8+UjAaoF6gGET+YsVWFQDAfR8uKAjyoFe2U0aOu6
-----END RSA PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAul48ENeuw+Zv7lynNpcU
s+vNyRAIZXj2cxepO+uefZewyadDjZRDvw43PAHizaN7IX2D4N81SnlLShMqc/gc
jGAze2pxU+GkiMcW2hph6AX60b6Na3GmozeZlVWpz+kfv8hYcRdSL4HoknVOVYU5
vEDK1GH2Jrv59ZlzL1z6Qyyc7OCDCXaHFp0Ft4/lQtB5vFQBva/+RM5QJEaeM2mY
CLmbDPc1IZcRJNDLqstTyVD13rO+v48pnkxxGV4RCvsTvA4QbSo4X63doYxPrrvZ
wWueQ2fTDs+gUGRj4VGC9PQuAdTIvpkUIQr28vyb+O6q/fO8oeXNYuzXbKjXRxpZ
2wIDAQAB
-----END PUBLIC KEY-----
""")

TEST_KEY_RSA_4096 = ("""
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApoRGAyYvB8v3uD+oHCfE
Dv7MQlKeOl3mUJKLC4BOuAbYLf35xsy0+pIQSQkuU+HSSBPkw/8nH8nFn+YjcYPY
ZS2mhxVYyGwaHqz7l5xA/u3SF7Y7tv0YdtfDFNHR8PH4e6oLP3cx2xVsXPQib8az
yOHuei5320Hsv5xRBlOrK7gtlv4c+9OvGbJZa6VnZ83s4SvtrXlgqpiwYCiFMKrJ
y0zy1CuqXpCRqHRmOwcX9o63+QxgvZGCo+E3Jz/E1HrQQkmdC7rsLDcrTde5bV1K
dk/+zXHTuCb8mi7ticShXSv93qSMUIhAp81zFa5Ys+ueMctCl0YnFLQsCAPsQprE
SPKqhweq8W8RkFEvfSioeIo/qlU5clCSWwaFdX0ZPJV3yS90cEYIh5dc/Yt+bJka
oFwO+fswiDaMkQ9wd18Mk4QyWaqp1p6EphXx6wvUm11EgkNFjgIJo/FY6v9Tyz2i
zH35Z02EDjyVoEuz8M7iZvDVBmz5N2Hqre72KgZobRrpH+vXO0zP3SqbfYUaG5L6
IKu9AVJcWGnaQn2RRc4ruXYDnzpJgt4y9RScBTaLHPNLeG0edPv49N2Kfhfm5ziK
PSwN1jd7DmUmtcOaQhgtl+1Tp7bFpDmUBTyFQ3wxDJFnVFjTsofJsdSW33g0+DtX
b/G8hnsWUukvxRXg8TJJIFsCAwEAAQ==
-----END PUBLIC KEY-----
""")

TEST_KEY_ECDSA = ("""
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAhS7UG/d7YwTg/pOnmyGGzmt/YFVCAOIiu18Mo+/3ZFc/Kb50ky2q
UzHfCWy+tcpWkzIT7FO/eAeUqy7Xzu/lqB+gBwYFK4EEACOhgYkDgYYABADLRK7k
tpl+AyP2f8MDiVgawDp84WV7qyqHa+aidct/1CMu7KHGKg+LXSCY2VXbxkY6mrV/
c22Vv6i3GH9pzxFzQwBw6whrrMos5MMDVvQSE1pAjT6fajVzD3sNz6BBlTzUxeLe
kbm18LiyjLSlxy+taObmfdoraG7/3AdhMcWGP2pp2A==
-----END EC PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAy0Su5LaZfgMj9n/DA4lYGsA6fOFl
e6sqh2vmonXLf9QjLuyhxioPi10gmNlV28ZGOpq1f3Ntlb+otxh/ac8Rc0MAcOsI
a6zKLOTDA1b0EhNaQI0+n2o1cw97Dc+gQZU81MXi3pG5tfC4soy0pccvrWjm5n3a
K2hu/9wHYTHFhj9qadg=
-----END PUBLIC KEY-----
""")


POLICY_CLOUD1 = """{
 "id": "3da4ba30-c370-11e9-9e69-99559a9ae32a",
 "companyId": "f1ac2ae0-c36b-11e9-a3ea-b31f650e1d77",
 "certificateAuthority": "BUILTIN",
 "name": "DevOps",
 "certificateAuthorityAccountId": "f3cc4bc0-c36b-11e9-9e69-99559a9ae32a",
 "certificateAuthorityProductOptionId": "f3ce6ea0-c36b-11e9-9e69-99559a9ae32a",
 "product": {
  "certificateAuthority": "BUILTIN",
  "productName": "Default Product"
 },
 "systemGenerated": false,
 "creationDate": "2019-08-20T17:30:44.947+0000",
 "modificationDate": "2019-08-30T14:01:44.127+0000",
 "status": "AVAILABLE",
 "reason": "",
 "subjectCNRegexes": [
  ".*.example.com",
  ".*.example.org",
  ".*.example.net",
  ".*.invalid",
  ".*.local",
  ".*.localhost",
  ".*.test"
 ],
 "subjectORegexes": [
  ".*"
 ],
 "subjectOURegexes": [
  ".*"
 ],
 "subjectSTRegexes": [
  ".*"
 ],
 "subjectLRegexes": [
  ".*"
 ],
 "subjectCValues": [
  ".*"
 ],
 "sanRegexes": [
  ".*"
 ],
 "keyTypes": [
  {
   "keyType": "RSA",
   "keyLengths": [
    2048,
    4096
   ]
  }
 ],
 "keyReuse": true
}"""

POLICY_CLOUD2 = """{
 "id": "3da4ba30-c370-11e9-9e69-99559a9ae32a",
 "companyId": "f1ac2ae0-c36b-11e9-a3ea-b31f650e1d77",
 "certificateAuthority": "BUILTIN",
 "name": "DevOps",
 "certificateAuthorityAccountId": "f3cc4bc0-c36b-11e9-9e69-99559a9ae32a",
 "certificateAuthorityProductOptionId": "f3ce6ea0-c36b-11e9-9e69-99559a9ae32a",
 "product": {
  "certificateAuthority": "BUILTIN",
  "productName": "Default Product"
 },
 "systemGenerated": false,
 "creationDate": "2019-08-20T17:30:44.947+0000",
 "modificationDate": "2019-08-30T14:01:44.127+0000",
 "status": "AVAILABLE",
 "reason": "",
 "subjectCNRegexes": [
  ".*.example.com",
  ".*.example.org",
  ".*.example.net",
  ".*.invalid",
  ".*.local",
  ".*.localhost",
  ".*.test"
 ],
 "subjectORegexes": [
  ".*"
 ],
 "subjectOURegexes": [
  ".*"
 ],
 "subjectSTRegexes": [
  ".*"
 ],
 "subjectLRegexes": [
  ".*"
 ],
 "subjectCValues": [
  ".*"
 ],
 "sanRegexes": [
  ".*"
 ],
 "keyTypes": [
  {
   "keyType": "EC",
   "keyCurve": [
    "p521"
   ]
  },
  {
   "keyType": "RSA",
   "keyLengths": [
    2048,
    4096
   ]
  }
 ],
 "keyReuse": true
}"""

POLICY_TPP1 = """
{
 "Error": null,
 "Policy": {
  "CertificateAuthority": {
   "Locked": false,
   "Value": "\\\\VED\\\\Policy\\\\devops\\\\msca_template"
  },
  "CsrGeneration": {
   "Locked": false,
   "Value": "UserProvided"
  },
  "KeyGeneration": {
   "Locked": false,
   "Value": "Central"
  },
  "KeyPair": {
   "KeyAlgorithm": {
    "Locked": false,
    "Value": "RSA"
   },
   "KeySize": {
    "Locked": false,
    "Value": 2048
   }
  },
  "ManagementType": {
   "Locked": false,
   "Value": "Enrollment"
  },
  "PrivateKeyReuseAllowed": true,
  "SubjAltNameDnsAllowed": true,
  "SubjAltNameEmailAllowed": true,
  "SubjAltNameIpAllowed": true,
  "SubjAltNameUpnAllowed": true,
  "SubjAltNameUriAllowed": true,
  "Subject": {
   "City": {
    "Locked": false,
    "Value": "Salt Lake"
   },
   "Country": {
    "Locked": false,
    "Value": "US"
   },
   "Organization": {
    "Locked": false,
    "Value": "Venafi Inc."
   },
   "OrganizationalUnit": {
    "Locked": false,
    "Values": [
     "Integrations"
    ]
   },
   "State": {
    "Locked": false,
    "Value": "Utah"
   }
  },
  "UniqueSubjectEnforced": false,
  "WhitelistedDomains": [],
  "WildcardsAllowed": true
 }
}"""

EXAMPLE_CSR = """-----BEGIN CERTIFICATE REQUEST-----
MIIC5TCCAc0CAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxFzAVBgNV
BAcMDlNhbHQgTGFrZSBDaXR5MQ8wDQYDVQQKDAZWZW5hZmkxFDASBgNVBAsMC0lu
dGVncmF0aW9uMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsowsaelHobgjtTdvPM/cbdxyb9HDxNA0+cMg
X0vXhrlb4gDa1ZpNGNh26uVBlxDIf63HaNEJyphrX48Lr3b/vViLW0/yVx/zqi0/
hwEnjlqMfKiBLq4pihxnCPVhUTXToFVBsYTURgu1CMS6LM0BBJK4sqf3cjLVyUH9
EKMz0HxbRJc9IcxirLLfDu580GiN8ggeRBKfZjnyZImbXEmjk9q0bZP8UySMi1fI
JpfeXyKHo/6HnB09qAtq71afzZOUABhZpXScmYNweDsQZTTW6hgf4WyxoywqdSiT
W5CmLdX/P4Vf4RYe0saDL1sHFrCiIibFBjxrtxTEXhfZbMSv2QIDAQABoCkwJwYJ
KoZIhvcNAQkOMRowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0B
AQsFAAOCAQEAQ++sKylm66h/iTXRVJxNiIdOIAsCD+Vdis091/EKJzVBF6bbHMo5
PUli1wm+PSaCbkiHClCziP9JKQkgeURLHNnvOidr3BX0n3AZ9i/s03yNlH3IiXSi
0QOc5Xl3REm9G341y40G8J3NjsJ2lZftjDb86LB6iOlkGmy7FHe/inkq4bA+Xlrp
AilzNOkXEeBwCT79bdpc3xh/hrjf9PeItLMpS7lVUUYQH18JK203BMGOE76EaELA
fk2X1wGedpdby5XRW0a7qozvwdBBTfI6/yMTP+iF5ghzvpCGtX2tYkyQ0I2GT/hV
YuWiOhL8NVOxPWFbiKWghQ2qH3hE0arsDA==
-----END CERTIFICATE REQUEST-----
"""

EXAMPLE_CHAIN = """
cert CN=test2.example.com
-----BEGIN CERTIFICATE-----
MIIDVDCCAjygAwIBAgIIYdpPxQjU7qwwDQYJKoZIhvcNAQELBQAwJzElMCMGA1UE
AxMcSW50ZXJtZWRhdGUgVmVuYWZpIERldm9wcyBDQTAeFw0yMDA0MTcxMjUwMDBa
Fw0yMTA0MTcxMjUwMDBaMBwxGjAYBgNVBAMTEXRlc3QyLmV4YW1wbGUuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz0gfSlj/fiGs/bldIurGK3h9
9hlsAZ1vK4J12o4Ss2gqxN5C9sIRWy7lZRdDD7B53swLAmgSTU8zK/yvr/U06h1A
pLctOZmc/R3ys7F24mwO0f04Nfi5/cjaux52/Qiup81RJPr4zQ+liOoXWTZRzfvZ
45uRGI+AoSosSflV9UU9QaJcLndzpw1ZosFllxUmAPOK5ic8YIUg0Uo8Qp6TT1ae
szYBvRfe0bw+qmL5BPVEDYVHM9I7MSlV/ZBQ83JBq3MyKrYV3i/SNYQiw40+oOZi
IudVDoi3jLvKe1NQplrz37Mab+KQE3/5P0fIsNYx9cncFKF1h48y0eRxYlQiYQID
AQABo4GOMIGLMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFAlVEHaVbfyh3WErVzmU
cEveiHLlMAsGA1UdDwQEAwIF4DAcBgNVHREEFTATghF0ZXN0Mi5leGFtcGxlLmNv
bTARBglghkgBhvhCAQEEBAMCBkAwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZp
Y2F0ZTANBgkqhkiG9w0BAQsFAAOCAQEAxTvLQU5AV0Fue7rHI8Bb+NOtY0iaZPp4
ouhDKoZxMuiiYnmAgtDhYy5o+uJZ8ff2UCBp6EpRt9IK2hP9NW8HbTHP0T5GhhRE
JAwMj6loeiB69z4B4R3ZT5JRQe2+Mxh9bpllV6Y6ecsc5cybwT2RHKCRUxCf3XgL
BSR/E8BQTYbEK7iQR5qO5YDTMqW2SrO7Vx2co74XkVjG5EDlibU7qjVMyUGxH79S
nKG5vJjiK3Hxj52XSHGOSsTiHTivg1UtmEu1DXU1mUy7ivobVqLKVUOFTCn6n0Rs
A/flG+it6xDbOTdAf3fHlKkM38u/+d759CJZrImhYRsHM7Dx3ySk5A==
-----END CERTIFICATE-----
intermediate
-----BEGIN CERTIFICATE-----
MIIClDCCAhugAwIBAgIIWc/+I0ikBsUwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAxMQ
VmVuYWZpIERldm9wcyBDQTAeFw0yMDA0MTcxMjQ4MDBaFw0yOTEyMDMxNDAyMDBa
MCcxJTAjBgNVBAMTHEludGVybWVkYXRlIFZlbmFmaSBEZXZvcHMgQ0EwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDduG4j1oyr1OqkeYHKIbirEzg2XqJ+
EkaGWMGPkD/he5D5n6iaM9lb76eDpEDqyxl0/yAHeWygFeg0NmFLBaRdTLJ/l81g
LsUTzHQTb10fWDwlyGb/lmAToh8TqC5rMLpOcgQwQEncn6NuCJAYynR/YVJUza8/
G8Ky0td5Bs5EWV3Z8NUsHajW4ZIy9jmGw8luaB4/0thWR2hOPmqBLNqbRemqr4i8
GYMCFdKhS2kraJrcnNBG9bQXK8HL1SEu6+BkneBU5fVqDWExs3uh6d8c5iNYzoxe
YNld0uObdh6PBFDD+R+xLx/mcJM0sZCi7dY9e0+r00QqeCkV/8DVY5LhAgMBAAGj
cjBwMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFARnA6M8tusnIrJjUYHR4Mz2
VQCHMAsGA1UdDwQEAwIBBjARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgEN
BBEWD3hjYSBjZXJ0aWZpY2F0ZTAKBggqhkjOPQQDAgNnADBkAjBCz33KnrpuIDAM
j/d59jBWCq6P4a2SXd2uFAFkJ13z6QlsEK/VDniuxAema8m3JSkCMG1SPQmswALC
hosHazaeVfIjflszznomps37c5GZmCozoqGSDQB3fB5dTy2wCpAhxg==
-----END CERTIFICATE-----
root
-----BEGIN CERTIFICATE-----
MIIB2jCCAWGgAwIBAgIIHBdg1Vhj9LEwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAxMQ
VmVuYWZpIERldm9wcyBDQTAeFw0xOTEyMDMxNDAyMDBaFw0yOTEyMDMxNDAyMDBa
MBsxGTAXBgNVBAMTEFZlbmFmaSBEZXZvcHMgQ0EwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATcfzZDskglHlCeuEH56R0AbmNiQgQYqxYRq4tzBUn4Bf81dhwPeM5wXqCB
hfmvVVMtAae1hqDb4oh1woK2Lfqc72IYmEUD0DeAprEQDMhaho61r90ElUU57Zk4
pzpD1hajcjBwMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGQ6TItGcDc979y8
OUbB9auUXmjgMAsGA1UdDwQEAwIBBjARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZI
AYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0ZTAKBggqhkjOPQQDAgNnADBkAjByDGia
p1Nb2Z3aMNvjCllwkRVVaitT4yzaeZK3+NwI99vGeSkB797kVKUKxZ5B0hkCMGmJ
e9lbirRHtK1eXshyCPo6+AumQlL5b3VBo/ghJlh2nD6OSnhO887GfruZ9dZSGw==
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz0gfSlj/fiGs/bldIurGK3h99hlsAZ1vK4J12o4Ss2gqxN5C
9sIRWy7lZRdDD7B53swLAmgSTU8zK/yvr/U06h1ApLctOZmc/R3ys7F24mwO0f04
Nfi5/cjaux52/Qiup81RJPr4zQ+liOoXWTZRzfvZ45uRGI+AoSosSflV9UU9QaJc
Lndzpw1ZosFllxUmAPOK5ic8YIUg0Uo8Qp6TT1aeszYBvRfe0bw+qmL5BPVEDYVH
M9I7MSlV/ZBQ83JBq3MyKrYV3i/SNYQiw40+oOZiIudVDoi3jLvKe1NQplrz37Ma
b+KQE3/5P0fIsNYx9cncFKF1h48y0eRxYlQiYQIDAQABAoIBAHLEHf8OM7fkcWGy
Bi1VDA/5kNR30uM6BdlzTEmMLDKFVFjYLv9tCCsSVhSYwpqnPXLsSpQ0hx2i4lRS
ffvQqlGNjMMmYLXppZBHyp9PfOF0ruf5aewIIQKw+Nptzbff3MQv2+O7yZHQPfkG
k5LjjnucHFH3Smjs221galEy6jL3+eelz4wqWeWcOEh5J815YXhhmenAYgaSLvqd
aClOJ2d1oE9yGHy3QnseYNxyvAwHyybbZ+GEvltPg7svJ/gjTjnAdM2PEyfAIOY0
sDM++Xbx3MADRrph2edo4VLZZGp2UELekeL4Pcnvhpd/qm6KJsOg5/Bsid++vVu3
zfrlwoECgYEA7tILYr/dMTp4diBYxhXq1Q7VUB3l08J38mkDF01S/X369isHug5d
lz4Sw9XqVwUTwGrZJBOZzx1EIwrxwQS+8aZuPDN/pVm+Vb6m4nTKv6ikJAuDqTN+
jEkYISta2U4O+CTsq1SNZ2dNr6tzENnrRxw+1lEDHh3FnaClR4DdoekCgYEA3jFI
DEiIv5TLbNMCelkgY95/WPfnPxzfL3lcz+Iab0WMMuNmXkRhpTy1mb1KiBLnCXrA
PSqoUPxjhQV6ddylBDZqA3uqToxoDli2veb/7Suf1k/xShbHJNXQjfuktrNNTfgb
IbrnNRo3yWE3UfaFLJckpHrDuy8VwWykZEqrebkCgYEA3HGKDPbpZ91/ABrPltj4
UP5GLJPMZ3FkYqBIOCQp7M9y7fO+SCGmhkrH63jzvKt1FfIKyWBGY4WyNV6O1Qpa
bpifvHYU5z41kNRRG0uPMuapzJPMTky4DSoTWdq5G0kQTEFZLLT5aW9TqEnsBqwA
nz0VS6Kv7AazONLmfWAYNLECgYAMGMLDaG+JfqBUnGhWIOQSi9qDDXwZg4jjHMhg
yP6HcFHhs1+vYimuxU9dv2B/aAgMDBLLQbdIMXV5mILCR/Dz+cJrzh/Hhv1jSpEo
ZZspXmalVFTeo77T0pA4KqsdB0X+KLPRckuEKJlA7XoFjFZTxybHjad6WWXl0fRh
QW90gQKBgHvstJu5qczb3mUSMpAq4qhgM5YC1wg9Q6OQNWdyT9g6j/65oV/4KG8a
J8t2CsPaxK4aPGMDTOfooDeUKYy+OzEalSAh2ntuyLd1ZSbN/qjvwOdfqvJJq4TM
mFFkM+qC8o8G9zXULydK1DBnWJqBfHGoFu9+JkEcykPsANjHRoG9
-----END RSA PRIVATE KEY-----

"""

SSH_CERT_DATA = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAggY7TIQpWzhBFShMZLR0mh2/" \
                "5aK5S3xxNUVaK3EP0XI0AAAADAQABAAABgQDFCm9cWkABjag9XaoFoV50U7EK+v69jm9qa6aY53XWYY1V9E8vOk21zQD2+ROC623" \
                "yrVv59JanFSmgrFfQpDhUKwrMAqLuzloSYtaKH7Ft3A9uIx78D862zFykW0oTs7uR2kG2DIGWupAL469CHv4S0ljtZ5pYyU3m5Pm" \
                "EwaFn+lndfSe+aju1qhtbNrIib/F96tg/0f8KcDxU+ilb2kl30vaNa/zvga/x+kJKE1A3VSjy97n7uSJji7fcN8WnEGOsDEL4dZQ" \
                "RIzCXx0aKlMr1bkAxQ0h5QK5rE1RPhIlfckxrsOw9yEoXMnU7qv/IGZ9EaIpxVhK5SlNGnFo0pTs5OE5FdlZvW3IBJzKci+gRD8Z" \
                "DHqk4Wf4zlS9whb/kz7XsaJBreIz0M8V50FNbpn09tHUNYkKvynElO8BC5X1YkoAoRwysk3WrTCo7UJQ8Q+whle0LUCXcdJqs0NN" \
                "O4kKLwA/6IrCJirhZi1RGp3CDIEfl5wUs62HVLeB94h/3jF353sgvoJOo4AAAAAEAAAAfdmNlcnQtZ28tMTYyNjgwNTg2OC1zeHp" \
                "zU1NIQ2VydAAAABAAAAAFYWxpY2UAAAADYm9iAAAAAGES4REAAAAAYRMZUQAAACIAAAAOc291cmNlLWFkZHJlc3MAAAAMAAAACHR" \
                "lc3QuY29tAAAAKAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAACFwAAAAdzc2gtcnNhAAAAAwE" \
                "AAQAAAgEAtP5TdyYaXn9EsihnCRuXOeAcplCrr7G4eUmpgxI/iOo8PyO3LcfeeSwgecEcZZCEZRZGLl0i0GrHS4Y5wxz14lvJ4/s" \
                "w7hwdUC4+BNh5kCscC5YhtUU9SWliaSCutz1NvGsRoBPk/6R/aScuBpEepggbL9ol7ObICuvGyvoSvFoZbYCD8kpCHxbnBNxLCuI" \
                "Rx3DAnsMyfT9V/jdj3+lxJSYDMtWhQ01f4EjON4esrz/gMmU/Yl9R1qSK6TM/T0r2RYNEq3f9XfywLDBry+gEKrvkwlhBPkPSC+1" \
                "onx66rSXUqsHhK09bn8FrVGVDFd4Cl/xhdLld8BHbxV6dI7qj0Fop7P/v/d7Iqvd1LExOoqTRqM6ZhmFa147ocksTxpxJDe+XvVk" \
                "fW8H6/89HqcERGrlmQTxGmh6W9JbuDbHJoTmrF6igcwDRBY5BrU0fYLXTqQenA60YqJD1iO6Cde2WsWa/HyoAdF2O837oRVNze9V" \
                "rHD/tKypN+w0aF7gglG0KVJxu29B34mspx2xSUuafqLeSq5j3EXZbeapDoCkS+7U8yXDQSD5P8sB/9XvyCkbxMv6H2yKhWYooGYX" \
                "6F/s3nHLd5wooRwLN5DVDd74WrVoSnuHfQEhUrq3iHWALW0Jl54yJWdVqVBCY6JCT0GnvzZRNKMP8G255qVqetSk7/qkAAAIUAAA" \
                "ADHJzYS1zaGEyLTUxMgAAAgB43MnV/s1iyt0KPnfyAqvvvX3xUlO83gKJQe3vgGnGwGfo0hS3Rg53BCUjGTVUGvHyH/Lxj4F7wqA" \
                "WuK0Fs3EzsIIIKD/pyJPWaDSgj2yPP9ElNBCqhwOYXgvDyPSKjsxjDqDhINAna8cdQdD+wDrckc/SX/Jt7DgBrD8WRy3Otr+FKnA" \
                "zJeEZe4MwSa4WjGcMnfwH4hStI6hwuuX3i486EYyrC3Kl6t2TUUF3YosOu09eIAMDDw5PDtp8Uhmzz+n1rQNyTn6L4vq2j9P01I8" \
                "ynmOwq1+DgyGb4bcMDRStNIiBb1qhLAW+nxeL2Mw68w4LkGh0UT0T+ivGbEWuZWD2VniPLZjqjWCHdpdWW8SW27UQF9ypsjxiIVF" \
                "kALulljvFIztOR7ZN5bFgxtMTHJb5mHogjWCzcs0xY1olJuYdNsGkoOoSQnkE/M4JmVoDOjBwSQLkSx54nLJPgxf10ZCiEqIk/dq" \
                "R4jBmv39skpb1DIo0Jgm4fE1czNPmYJldYhSbMud1RNyyFAmLmkVxcqV0dPQ50aFHOl/LG2CpOn9l2qYvhEs9iXEpua5sWR/R31O" \
                "q6ahPWfA4Wfn2tKtOIgJaZTOLgfys4QUhbRpZ8btV79hjrOlPzryg5pflQe8dx63Iut9HR+SOZzxnE2pFYJSgcJO8prnlIfdNq5B" \
                "xPpHQqA== vcert-go-1626805868-sxzsSSHCert"

SSH_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFCm9cWkABjag9XaoFoV50U7EK+v69jm9qa6aY53XWYY1V9E8vOk21zQD2+RO" \
                 "C623yrVv59JanFSmgrFfQpDhUKwrMAqLuzloSYtaKH7Ft3A9uIx78D862zFykW0oTs7uR2kG2DIGWupAL469CHv4S0ljtZ5pYyU" \
                 "3m5PmEwaFn+lndfSe+aju1qhtbNrIib/F96tg/0f8KcDxU+ilb2kl30vaNa/zvga/x+kJKE1A3VSjy97n7uSJji7fcN8WnEGOsD" \
                 "EL4dZQRIzCXx0aKlMr1bkAxQ0h5QK5rE1RPhIlfckxrsOw9yEoXMnU7qv/IGZ9EaIpxVhK5SlNGnFo0pTs5OE5FdlZvW3IBJzKc" \
                 "i+gRD8ZDHqk4Wf4zlS9whb/kz7XsaJBreIz0M8V50FNbpn09tHUNYkKvynElO8BC5X1YkoAoRwysk3WrTCo7UJQ8Q+whle0LUCX" \
                 "cdJqs0NNO4kKLwA/6IrCJirhZi1RGp3CDIEfl5wUs62HVLeB94h/3jF0= vcert-go-1626805868-sxzsSSHCert"

SSH_PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwA" \
                  "AAAdz\r\nc2gtcnNhAAAAAwEAAQAAAYEAxQpvXFpAAY2oPV2qBaFedFOxCvr+vY5vamummOd1\r\n1mGNVfRPLzpNtc0A9vkTg" \
                  "utt8q1b+fSWpxUpoKxX0KQ4VCsKzAKi7s5aEmLWih+x\r\nbdwPbiMe/A/OtsxcpFtKE7O7kdpBtgyBlrqQC+OvQh7+EtJY7We" \
                  "aWMlN5uT5hMGh\r\nZ/pZ3X0nvmo7taobWzayIm/xferYP9H/CnA8VPopW9pJd9L2jWv874Gv8fpCShNQ\r\nN1Uo8ve5+7kiY" \
                  "4u33DfFpxBjrAxC+HWUESMwl8dGipTK9W5AMUNIeUCuaxNUT4SJ\r\nX3JMa7DsPchKFzJ1O6r/yBmfRGiKcVYSuUpTRpxaNKU" \
                  "7OThORXZWb1tyAScynIvo\r\nEQ/GQx6pOFn+M5UvcIW/5M+17GiQa3iM9DPFedBTW6Z9PbR1DWJCr8pxJTvAQuV9\r\nWJKAK" \
                  "EcMrJN1q0wqO1CUPEPsIZXtC1Al3HSarNDTTuJCi8AP+iKwiYq4WYtURqdw\r\ngyBH5ecFLOth1S3gfeIf94xdAAAFeG7jGyt" \
                  "u4xsrAAAAB3NzaC1yc2EAAAGBAMUK\r\nb1xaQAGNqD1dqgWhXnRTsQr6/r2Ob2prppjnddZhjVX0Ty86TbXNAPb5E4LrbfKt" \
                  "\r\nW/n0lqcVKaCsV9CkOFQrCswCou7OWhJi1oofsW3cD24jHvwPzrbMXKRbShOzu5Ha\r\nQbYMgZa6kAvjr0Ie/hLSWO1nml" \
                  "jJTebk+YTBoWf6Wd19J75qO7WqG1s2siJv8X3q\r\n2D/R/wpwPFT6KVvaSXfS9o1r/O+Br/H6QkoTUDdVKPL3ufu5ImOLt9w3" \
                  "xacQY6wM\r\nQvh1lBEjMJfHRoqUyvVuQDFDSHlArmsTVE+EiV9yTGuw7D3IShcydTuq/8gZn0Ro\r\ninFWErlKU0acWjSlOz" \
                  "k4TkV2Vm9bcgEnMpyL6BEPxkMeqThZ/jOVL3CFv+TPtexo\r\nkGt4jPQzxXnQU1umfT20dQ1iQq/KcSU7wELlfViSgChHDKyT" \
                  "datMKjtQlDxD7CGV\r\n7QtQJdx0mqzQ007iQovAD/oisImKuFmLVEancIMgR+XnBSzrYdUt4H3iH/eMXQAA\r\nAAMBAAEAAA" \
                  "GBAI0npZFOYg360ixr/hIcgRLqpakNGBLph+2AAxAEuIkEx4BtDZDy\r\nvprfqrJCyvR9/fzcrkhJLOezJGgjLqGcE3JQh2KQ" \
                  "/PIAx8vmHHVEsRHXlQI8jMTb\r\n+iVAD5n6f/3PQy8AYRSuruMw8WJjELlYhIEtSWGBV7QFOhaPsCSnph5b3abrMt6Z\r\nMf" \
                  "85RnG4pDJBaYngBFzr7j4nG0FxGNHhdcIuUkwLsV5O1KGPu49feJa7HiO4zfaD\r\nsRwJCoTrO2AsP0f3StiKbyGZt98WHXqS" \
                  "9DDdLKBB8O0YSm1uCs0mVn1CkWJMseg+\r\naCa6m5MmOmIU7wFQV87/Up0S/ym+Q9pOERgYn50NCJsY9S/1ORgxo9/fsj1KSb" \
                  "xK\r\nae2b3brRcueJ6rtQsNlm9wjYcYSzDiwl8AQhGEx8lF0RwnMF7AKgkpMKyFfQ2Tbu\r\n9zqlXSoSUI9aAbItVjDfM1Kd" \
                  "tuRHSs7CRcqRVC+1D2xQ/Knu8fje84hCQIk22iyr\r\nBOd+1kLGii1izQAAAMEApzivPz6hZHAfXmCf3EUxTXFxOekOCbpmkv" \
                  "hE3m+6THTH\r\nIa034I8S2D79sILL10VcevRjbHmYcwlHNIR2U6Wvl8asq4YKk9P2Yoqx3XZMsjOO\r\ncNCPPs9voSGzFDyx" \
                  "TfSZ91zIy1YOsuhvq9eXCdyusx4vq2TqpfhXCe4AK+P/pyp/\r\nA6KGrGPT8lxreVyQMWC5Nt/sEWuYGg02lMd9VC+sHMUKZi" \
                  "9h6ENAPrLcUmkU3GvS\r\nksCH3bPwszdeL89+yCEeAAAAwQD1w+Nkx+dn69z4v8E2IUJG2g7wy1zRKkqix8Sa\r\noXig893l" \
                  "0fJQC7Y9c0dTr0YwnEwkPjjU7cqi7nMS93CaRDhd7ad3IgR+3a5obB5m\r\nOxPWVR7HNOyqCcJDt9ADIkWV341Nzh2l1R8mmB" \
                  "i4jbvPvU7xtCFLWCt5+Rfc0yFP\r\n1FHnUw3L6wuhKdlRY5jP5stRjz7zd2ChoSk7x11Azb4agAd+k1v6GsujD4tYaOvl\r\n" \
                  "oOdJNU+X8erSqfTDKS/hxKYo+QcAAADBAM0/GAWL0JgiMHaNyoVuR11f+XOlBkQE\r\nkqfSVclk15zW3xWSWnxg0odmq0Vn6k" \
                  "AMRHZAQ+2f/oRad7qbkv6KXi70TcaRDe1G\r\nyyeQC7bs147nudDwoO9Iq4V7sj1TyU1TOOk4t95S6sOo4+crd7kq+l1g5ed5" \
                  "GRqv\r\nMKfg4Ae8NEiJLSbKcB4nDzFzk03JND6gJY8YiwQK6GYnBLEaPtuTIhb6XAUr4aSa\r\nw3elZMPNVE0KryHBahiIZq" \
                  "vpeKD5f71qewAAAAAB\r\n-----END OPENSSH PRIVATE KEY-----\r\n"
