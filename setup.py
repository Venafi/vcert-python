#!/usr/bin/env python

import os
from setuptools import setup

# The directory containing this file
base_dir = os.path.dirname(__file__)

# The text of the README file
with open(os.path.join(base_dir, "README.md")) as f:
    long_description = f.read()
# README = (HERE / "README.md").read_text()

setup(name='vcert',
      version='0.12.5',
      url="https://github.com/Venafi/vcert-python",
      packages=['vcert', 'vcert.parser', 'vcert.policy'],
      install_requires=['requests<=2.25.1', 'python-dateutil<=2.8.1', 'certvalidator<=0.11.1', 'six<=1.15.0',
                        'enum34;python_version<"3.4"', 'ipaddress;python_version<"3.3"',
                        'cryptography<=3.3.2', 'future;python_version<"3"', 'ruamel.yaml<0.17', 'pynacl>=1.4.0'],
      description='Python client library for Venafi Trust Protection Platform and Venafi Cloud.',
      long_description=long_description,
      long_description_content_type="text/markdown",
      author='Venafi, Inc.',
      author_email='opensource@venafi.com',
      license='ASL',
      classifiers=[
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Operating System :: OS Independent',
          "License :: OSI Approved :: Apache Software License",
      ])

