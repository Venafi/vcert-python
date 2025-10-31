
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with CyberArk Certificate Manager, Self-Hosted+ & CyberArk Certificate Manager, SaaS](https://img.shields.io/badge/Compatibility-Certificate%20Manager%2C%20Self--Hosted_2017.3%2B_%26Certificate%20Manager%2C%20SaaS-f9a90c)
[![pypi Downloads](https://img.shields.io/pypi/dw/vcert)](https://pypi.org/project/vcert/)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Venafi_vcert-python&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Venafi_vcert-python)

_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](https://github.com/Venafi/vcert-python/issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](https://github.com/Venafi/vcert-python/pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# VCert Python
 
VCert Python is a Python library and SDK  designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[CyberArk Certificate Manager, Self-Hosted](https://www.cyberark.com/products/certificate-manager/) or
[CyberArk Certificate Manager, SaaS](https://www.cyberark.com/products/certificate-manager/).

This implementation is based on the original Go library, https://github.com/Venafi/vcert.

#### Compatibility
***Starting version 0.14.0 vcert-python only supports Python 3.6 or higher*** 

VCert releases are tested using the latest version of CyberArk Certificate Manager, Self-Hosted.  The [latest VCert release](https://github.com/Venafi/vcert-python/releases/latest) should be compatible with CyberArk Certificate Manager, Self-Hosted 17.3 or higher based on the subset of API methods it consumes.

## Installation
Get the library using pip:  
`pip install vcert`  

You also can install latest version from github:  
`pip install https://github.com/Venafi/vcert-python/archive/master.zip`

If installation fails collecting dependancies, make sure your python setuptools is up to date. Run the following command to upgrade to the latest version of setuptools.
`pip install setuptools -U`

## Usage example

For code samples of programmatic use, please review the files in [/examples](https://github.com/Venafi/vcert-python/tree/master/examples).
- For CyberArk Certificate Manager, Self-Hosted, the `zone` format is the DN of a policy with or without the "\VED\Policy\" prefix (e.g. "\VED\Policy\Certificates\VCert" or simply "Certificates\VCert")
- For CyberArk Certificate Manager, SaaS, the `zone` format is the name of an OutagePREDICT Application and the API Alias of an Issuing Template assigned to it delimited by a single backslash character (e.g. "My Application\My CIT")

## Prerequisites for using with CyberArk Certificate Manager, Self-Hosted

1. A user account that has an authentication token with "certificate:manage,revoke" scope (i.e.
access to the "CyberArk VCert SDK" API Application as of 20.1) or has been granted WebSDK Access
2. A folder (zone) where the user has been granted the following permissions: View, Read, Write,
Create, Revoke (for the revoke action), and Private Key Read (for the pickup action when CSR is
service generated)
3. Policy applied to the folder which specifies:
    1. CA Template that CyberArk Certificate Manager, Self-Hosted will use to enroll certificate requests submitted by VCert
    2. Subject DN values for Organizational Unit (OU), Organization (O), City (L), State (ST) and Country (C)
    3. Management Type not locked or locked to 'Enrollment'
    4. Certificate Signing Request (CSR) Generation not locked or locked to 'Service Generated CSR'
    5. Generate Key/CSR on Application not locked or locked to 'No'
    6. (Recommended) Disable Automatic Renewal set to 'Yes'
    7. (Recommended) Key Bit Strength set to 2048 or higher
    8. (Recommended) Domain Whitelisting policy appropriately assigned

The requirement for the CA Template to be assigned by policy follows a long standing CyberArk best
practice which also met our design objective to keep the certificate request process simple for
VCert users. If you require the ability to specify the CA Template with the request you can use the
CyberArk Certificate Manager, Self-Hosted REST APIs but please be advised this goes against CyberArk recommendations.

## Prerequisites for using with CyberArk Certificate Manager, SaaS

1. The CyberArk Certificate Manager, SaaS REST API is accessible from the system where VCert
will be executed. Currently, we support the following regions:
   - `https://api.venafi.cloud` [US]
   - `https://api.venafi.eu` [EU]
   - `https://api.au.venafi.cloud` [AU]
   - `https://api.uk.venafi.cloud` [UK]
   - `https://api.sg.venafi.cloud`[SG]
   - `https://api.ca.venafi.cloud` [CA]
2. You have successfully registered for a CyberArk Certificate Manager, SaaS account, have been granted at least the
"Resource Owner" role, and know your API key.
3. A CA Account and Issuing Template exist and have been configured with:
    1. Recommended Settings values for:
        1. Organizational Unit (OU)
        2. Organization (O)
        3. City/Locality (L)
        4. State/Province (ST)
        5. Country (C)
    2. Issuing Rules that:
        1. (Recommended) Limits Common Name and Subject Alternative Name to domains that are allowed by your organization
        2. (Recommended) Restricts the Key Length to 2048 or higher
        3. (Recommended) Does not allow Private Key Reuse
4. An Application exists where you are among the owners, and you know the Application Name.
5. An Issuing Template is assigned to the Application, and you know its API Alias.

## Contributing to VCert

CyberArk welcomes contributions from the developer community.

1. Fork it to your account (https://github.com/Venafi/vcert-python/fork)
2. Clone your fork (`git clone git@github.com:youracct/vcert-python.git`)
3. Create a feature branch (`git checkout -b your-branch-name`)
4. Implement and test your changes
5. Commit your changes (`git commit -am 'Added some cool functionality'`)
6. Push to the branch (`git push origin your-branch-name`)
7. Create a new Pull Request (https://github.com/youracct/vcert-python/pull/new/your-branch-name)

NOTE: While developing with vcert-python, it is helpful if you are using a virtualenv to
install the vcert-python library from source in development mode with `pip install --editable`.
See https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/

## Version History

[Check version history here](https://github.com/Venafi/vcert-python/blob/master/docs/version_history.md)

## License

Copyright &copy; Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")

VCert is licensed under the Apache License, Version 2.0. See [`LICENSE`](https://github.com/Venafi/vcert-python/blob/master/LICENSE) for the full license text.

Please direct questions/comments to mis-opensource@cyberark.com.
