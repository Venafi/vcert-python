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
from enum import IntEnum


class IssuerHint(IntEnum):
    def __new__(cls, value, json_value):
        """

        :param int value:
        :param str json_value:
        """
        obj = int.__new__(cls, value)
        obj._value_ = value

        obj.json_value = json_value
        return obj

    MICROSOFT = 1, 'Microsoft CA:Specific End Date'
    DIGICERT = 2, 'DigiCert CA:Specific End Date'
    ENTRUST = 3, 'EntrustNET CA:Specific End Date'
    DEFAULT = 4, 'Specific End Date'
