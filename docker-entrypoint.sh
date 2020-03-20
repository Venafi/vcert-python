#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

py.test
bandit -r vcert/
safety check