# VCert Python

## Version History

#### 0.15.0
* Fixed **[Issue 100](https://github.com/Venafi/vcert-python/issues/100)**: Updated behavior for 'serviceGenerated' attribute on VaaS
* Fixed **[Issue 101](https://github.com/Venafi/vcert-python/issues/101)**: Added support for the following Subject Alternative Names when creating a policy on VaaS: email, IP, URI
* Closed **[Issue 102](https://github.com/Venafi/vcert-python/issues/102)**: Added support for EC private keys on VaaS
* Closed **[Issue 108](https://github.com/Venafi/vcert-python/issues/108)**: Added ability to add contacts(TPP)/owners(VaaS) to a policy when is created
* Closed **[Issue 113](https://github.com/Venafi/vcert-python/issues/113)**: Added support for legacy PKCS1 format on private keys when requesting a certificate. Default now is PKCS8 for both TPP and VaaS
* Closed **[Issue 116](https://github.com/Venafi/vcert-python/issues/116)**: Added ability to disable the following Subject fields when creating a policy on VaaS: organizations, org units, localities, states, countries
* Updated README.md links to work on sites other than GitHub
#### 0.14.0
* Closed **[Issue 90](https://github.com/Venafi/vcert-python/issues/90)**: **Dropped support for Python2. New baseline is Python 3.6+**
* Closed **[Issue 98](https://github.com/Venafi/vcert-python/issues/98)**: Added integration with sonarcloud for code analysis
* Created version history file
* Minor bug fixes on Policy Management

