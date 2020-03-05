![Venafi](Venafi_logo.png)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_This open source project is community-supported. To report a problem or share an idea, use the
**[Issues](../../issues)** tab; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use the **[Pull requests](../../pulls)** tab to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions._

# VCert Python
 
VCert Python is a Python library and SDK  designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/).

This implementation is based on the original Go library, https://github.com/Venafi/vcert.

#### Compatibility
VCert supports Python 3, and Python 2.7.  VCert releases are tested using the latest version of Trust Protection Platform.  The [latest VCert release](../../releases/latest) should be compatible with Trust Protection Platform 17.3 or higher based on the subset of API methods it consumes.

## Installation
Get the library using pip:  
`pip install vcert`  

You also can install latest version from github:  
`pip install https://github.com/Venafi/vcert-python/archive/master.zip`

If installation fails collecting dependancies, make sure your python setuptools is up to date. Run the following command to upgrade to the latest version of setuptools.
`pip install setuptools -U`

## Usage example

For code samples of programmatic use, please review the files in [/examples](/examples).

## Prerequisites for using with Trust Protection Platform

1. A user account that has been granted WebSDK Access
2. A folder (zone) where the user has been granted the following permissions: View, Read, Write, Create, Revoke (for the revoke action), and Private Key Read (for the pickup action when CSR is service generated)
3. Policy applied to the folder which specifies:
    1. CA Template that Trust Protection Platform will use to enroll certificate requests submitted by VCert
    2. Subject DN values for Organizational Unit (OU), Organization (O), City (L), State (ST) and Country (C)
    3. Management Type not locked or locked to 'Enrollment'
    4. Certificate Signing Request (CSR) Generation not locked or locked to 'Service Generated CSR'
    5. Generate Key/CSR on Application not locked or locked to 'No'
    6. (Recommended) Disable Automatic Renewal set to 'Yes'
    7. (Recommended) Key Bit Strength set to 2048 or higher
    8. (Recommended) Domain Whitelisting policy appropriately assigned

## Contributing to VCert

Venafi welcomes contributions from the developer community.

1. Fork it to your account (https://github.com/Venafi/vcert-python/fork)
2. Clone your fork (`git clone git@github.com:youracct/vcert-python.git`)
3. Create a feature branch (`git checkout -b your-branch-name`)
4. Implement and test your changes
5. Commit your changes (`git commit -am 'Added some cool functionality'`)
6. Push to the branch (`git push origin your-branch-name`)
7. Create a new Pull Request (https://github.com/youracct/vcert-python/pull/new/your-branch-name)

## License

Copyright &copy; Venafi, Inc. All rights reserved.

VCert is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
