#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

bandit -r vcert/

pytest -v --junit-xml=junit.xml --junit-prefix=`python -V | tr ' ' '_'` --cov=vcert --cov=vcert.parser --cov=vcert.policy --cov-report term --cov-report xml
