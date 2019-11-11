#!/usr/bin/env python

from setuptools import setup


setup(name='vcert',
      version='0.6.8',
      url="https://github.com/Venafi/vcert-python",
      packages=['vcert'],
      install_requires=['requests', 'python-dateutil>=2.6.1', 'certvalidator', 'six',
                        'enum34;python_version<"3.4"', 'ipaddress;python_version<"3.3"', 'cryptography'],
      description='Python bindings for Venafi TPP/Venfi Cloud API.',
      author='Denis Subbotin',
      author_email='denis.subbotin@venafi.com',
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

