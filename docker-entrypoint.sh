#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

bandit -r vcert/

# ID 40291 is pip, ignore so we can still test python 2.7
#Ignoring false-positive issue with pytest. ref: https://github.com/pytest-dev/py/issues/287
# safety 3.x uses 'safety scan'; --ignore uses GHSA/CVE IDs or safety IDs
safety scan --ignore 40291 --ignore 51457 || true

pytest -v --junit-xml=junit.xml --junit-prefix=`python -V | tr ' ' '_'` --cov=vcert --cov=vcert.parser --cov=vcert.policy --cov-report term --cov-report xml
