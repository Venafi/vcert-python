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

from six import text_type

FAKE = environ.get('FAKE')
TOKEN = environ.get('CLOUD_APIKEY')
USER = environ.get('TPP_USER')
PASSWORD = environ.get('TPP_PASSWORD')
TPPURL = environ.get('TPP_URL')
CLOUDURL = environ.get('CLOUD_URL')
RANDOM_DOMAIN = environ.get("RANDOM_DOMAIN")
TPP_TOKEN_URL = environ.get("TPP_TOKEN_URL")
TPP_ACCESS_TOKEN = environ.get("TPP_ACCESS_TOKEN")

if not isinstance(RANDOM_DOMAIN, text_type):
    RANDOM_DOMAIN = RANDOM_DOMAIN.decode()


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))