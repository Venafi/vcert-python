#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

bandit -r vcert/
safety check
py.test -v --junit-xml=junit.xml --junit-prefix=`python -V | tr ' ' '_'`