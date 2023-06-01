#!/usr/bin/env python

import os
from setuptools import setup

# The directory containing this file
base_dir = os.path.dirname(__file__)

# The text of the README file
with open(os.path.join(base_dir, "README.md")) as f:
    long_description = f.read()

setup(name='vcert',
      version='0.15.0',
      url="https://github.com/Venafi/vcert-python",
      packages=['vcert', 'vcert.parser', 'vcert.policy'],
      install_requires=['requests==2.31.0', 'python-dateutil==2.8.2', 'certvalidator<=0.11.1', 'six==1.16.0',
                        'cryptography==40.0.2', 'ruamel.yaml==0.17.31', 'pynacl==1.5.0'],
      description='Python client library for Venafi Trust Protection Platform and Venafi Cloud.',
      long_description=long_description,
      long_description_content_type="text/markdown",
      author='Venafi, Inc.',
      author_email='opensource@venafi.com',
      license='ASL',
      classifiers=[
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Operating System :: OS Independent',
          "License :: OSI Approved :: Apache Software License",
      ])

