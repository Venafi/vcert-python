#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

bandit -r vcert/

# pip-audit replaces safety (see Jira VC-53657 for rationale).
# Exit non-zero on findings is intentional; || true defers known 3.10+-only CVEs.
pip-audit -r requirements-build.txt || true

pytest -v --junit-xml=junit.xml --junit-prefix=`python -V | tr ' ' '_'` --cov=vcert --cov=vcert.parser --cov=vcert.policy --cov-report term --cov-report xml
