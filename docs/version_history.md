# VCert Python

## Version History

#### 0.21.0
* Added certificate revocation (`revoke_cert`) for CyberArk Certificate Manager, SaaS (Cloud/VaaS) and NGTS (Strata Cloud Manager), via the GraphQL CA-operations `revokeCertificate` mutation (keyed by SHA-1 thumbprint)
* Cloud `revoke_cert` no longer raises `NotImplementedError`; NGTS inherits the same implementation
* Added the public `CertificateRevokeError` exception and an optional `ca_account_name` field on `RevocationRequest`

#### 0.20.0
* Added policy management (`get_policy`/`set_policy`) for NGTS (Strata Cloud Manager), operating on the CIT-only zone

#### 0.19.0
* Added support for NGTS (Strata Cloud Manager)

#### 0.18.0
* Added support for CyberArk Certificate Manager, Self-Hosted 25.1
* Upgraded dependencies
#### 0.17.0
* Added ability to retire certificates in both TLSPDC and TLSPC
* Dropped certvalidator dependency as it has not been needed for a long time
#### 0.16.2
* Fixed an issue whereby retrieving a certificate may fail in TLSPC when the CA takes too much time to process a certificate request
* #### 0.16.1
* CertificateType set to Auto by default when requesting certificates to TLSPDC 
#### 0.16.0
* Fixed **[Issue 124](https://github.com/Venafi/vcert-python/issues/124)**: Fixed an issue where adding a Certificate Issuing Template to an existing Application failed
* Upgraded cryptography dependency to 40.0.2 to cover a security risk CVE-2023-23931
* Removed orgUnit field from AppDetails, as CyberArk Certificate Manager, SaaS dropped the use of the field
#### 0.15.0
* Fixed **[Issue 100](https://github.com/Venafi/vcert-python/issues/100)**: Updated behavior for 'serviceGenerated' attribute on CyberArk Certificate Manager, SaaS
* Fixed **[Issue 101](https://github.com/Venafi/vcert-python/issues/101)**: Added support for the following Subject Alternative Names when creating a policy on CyberArk Certificate Manager, SaaS: email, IP, URI
* Closed **[Issue 102](https://github.com/Venafi/vcert-python/issues/102)**: Added support for EC private keys on CyberArk Certificate Manager, SaaS
* Closed **[Issue 108](https://github.com/Venafi/vcert-python/issues/108)**: Added ability to add contacts(CyberArk Certificate Manager, Self-Hosted)/owners(CyberArk Certificate Manager, SaaS) to a policy when is created
* Closed **[Issue 113](https://github.com/Venafi/vcert-python/issues/113)**: Added support for legacy PKCS1 format on private keys when requesting a certificate. Default now is PKCS8 for both CyberArk Certificate Manager, Self-Hosted and CyberArk Certificate Manager, SaaS
* Closed **[Issue 116](https://github.com/Venafi/vcert-python/issues/116)**: Added ability to disable the following Subject fields when creating a policy on CyberArk Certificate Manager, SaaS: organizations, org units, localities, states, countries
* Updated README.md links to work on sites other than GitHub
#### 0.14.0
* Closed **[Issue 90](https://github.com/Venafi/vcert-python/issues/90)**: **Dropped support for Python2. New baseline is Python 3.6+**
* Closed **[Issue 98](https://github.com/Venafi/vcert-python/issues/98)**: Added integration with sonarcloud for code analysis
* Created version history file
* Minor bug fixes on Policy Management

