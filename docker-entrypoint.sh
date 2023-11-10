#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

bandit -r vcert/

# ID 40291 is pip, ignore so we can still test python 2.7
#Ignoring false-positive issue with pytest. ref: https://github.com/pytest-dev/py/issues/287
#Ignoring cryptography issue 59473 The cryptography package before 41.0.2 for Python mishandles SSH certificates that have critical options.
# If we upgrade to cryptography 41.0.2 or higher we get `pyo3 modules may only be initialized once per interpreter process` and tests cannot run
safety check -i 40291 -i 51457 -i 59473

pytest -v --junit-xml=junit.xml --junit-prefix=`python -V | tr ' ' '_'` --cov=vcert --cov=vcert.parser --cov=vcert.policy --cov-report term --cov-report xml
