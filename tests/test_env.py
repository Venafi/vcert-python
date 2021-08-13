#!/usr/bin/env python3
#
# Copyright 2021 Venafi, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import random
import string
from os import environ

from future.backports.datetime import datetime
from six import text_type

FAKE = environ.get("FAKE")
RANDOM_DOMAIN = environ.get("RANDOM_DOMAIN")
TPP_URL = environ.get("TPP_URL")
TPP_USER = environ.get("TPP_USER")
TPP_PASSWORD = environ.get("TPP_PASSWORD")
TPP_ZONE = environ.get("TPP_ZONE")
TPP_ZONE_ECDSA = environ.get("TPP_ZONE_ECDSA")
TPP_TOKEN_URL = environ.get("TPP_TOKEN_URL")
TPP_ACCESS_TOKEN = environ.get("TPP_ACCESS_TOKEN")
CLOUD_URL = environ.get("CLOUD_URL")
CLOUD_APIKEY = environ.get("CLOUD_APIKEY")
CLOUD_ZONE = environ.get("CLOUD_ZONE")

TPP_PM_ROOT = environ.get("TPP_PM_ROOT")
TPP_CA_NAME = environ.get("TPP_CA_NAME")
CLOUD_ENTRUST_CA_NAME = environ.get("CLOUD_ENTRUST_CA_NAME")
CLOUD_DIGICERT_CA_NAME = environ.get("CLOUD_DIGICERT_CA_NAME")

TPP_SSH_CADN = environ.get("TPP_SSH_CADN")

if RANDOM_DOMAIN and not isinstance(RANDOM_DOMAIN, text_type):
    RANDOM_DOMAIN = RANDOM_DOMAIN.decode()


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


def timestamp():
    return datetime.today().strftime('%Y.%m.%d-%Hh%Mm%Ss')