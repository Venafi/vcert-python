[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)

[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)
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
[Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform) or
[Venafi as a Service](https://www.venafi.com/venaficloud).

This implementation is based on the original Go library, https://github.com/Venafi/vcert.

#### Compatibility
***Starting version 0.14.0 vcert-python only supports Python 3.6 or higher*** 

VCert releases are tested using the latest version of Trust Protection Platform.  The [latest VCert release](https://github.com/Venafi/vcert-python/releases/latest) should be compatible with Trust Protection Platform 17.3 or higher based on the subset of API methods it consumes.

## Installation
Get the library using pip:  
`pip install vcert`  

You also can install latest version from github:  
`pip install https://github.com/Venafi/vcert-python/archive/master.zip`

If installation fails collecting dependancies, make sure your python setuptools is up to date. Run the following command to upgrade to the latest version of setuptools.
`pip install setuptools -U`

## Usage example

For code samples of programmatic use, please review the files in [/examples](https://github.com/Venafi/vcert-python/tree/master/examples).
- For Trust Protection Platform, the `zone` format is the DN of a policy with or without the "\VED\Policy\" prefix (e.g. "\VED\Policy\Certificates\VCert" or simply "Certificates\VCert")
- For Venafi as a Service, the `zone` format is the name of an OutagePREDICT Application and the API Alias of an Issuing Template assigned to it delimited by a single backslash character (e.g. "My Application\My CIT")

## Prerequisites for using with Trust Protection Platform

1. A user account that has an authentication token with "certificate:manage,revoke" scope (i.e.
access to the "Venafi VCert SDK" API Application as of 20.1) or has been granted WebSDK Access
2. A folder (zone) where the user has been granted the following permissions: View, Read, Write,
Create, Revoke (for the revoke action), and Private Key Read (for the pickup action when CSR is
service generated)
3. Policy applied to the folder which specifies:
    1. CA Template that Trust Protection Platform will use to enroll certificate requests submitted by VCert
    2. Subject DN values for Organizational Unit (OU), Organization (O), City (L), State (ST) and Country (C)
    3. Management Type not locked or locked to 'Enrollment'
    4. Certificate Signing Request (CSR) Generation not locked or locked to 'Service Generated CSR'
    5. Generate Key/CSR on Application not locked or locked to 'No'
    6. (Recommended) Disable Automatic Renewal set to 'Yes'
    7. (Recommended) Key Bit Strength set to 2048 or higher
    8. (Recommended) Domain Whitelisting policy appropriately assigned

The requirement for the CA Template to be assigned by policy follows a long standing Venafi best
practice which also met our design objective to keep the certificate request process simple for
VCert users. If you require the ability to specify the CA Template with the request you can use the
TPP REST APIs but please be advised this goes against Venafi recommendations.

## Prerequisites for using with Venafi as a Service

1. The Venafi as a Service REST API is accessible at [https://api.venafi.cloud](https://api.venafi.cloud/vaas) or [https://api.venafi.eu](https://api.venafi.eu/vaas) (if you have an EU account) from the system where VCert
will be executed.
2. You have successfully registered for a Venafi as a Service account, have been granted at least the
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

Venafi welcomes contributions from the developer community.

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

Copyright &copy; Venafi, Inc. All rights reserved.

VCert is licensed under the Apache License, Version 2.0. See [`LICENSE`](https://github.com/Venafi/vcert-python/blob/master/LICENSE) for the full license text.

Please direct questions/comments to opensource@venafi.com.
