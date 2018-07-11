# Copyright (c) 2015-2016 OpenStack Foundation
# Copyright (c) 2018 OpenIO SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from oioswift.common.middleware.crypto import crypto_utils


class TestModuleMethods(unittest.TestCase):

    def test_decode_secret_too_long(self):
        self.assertRaises(ValueError, crypto_utils.decode_secret, 'a' * 45)

    def test_decode_secret_too_short(self):
        self.assertRaises(ValueError, crypto_utils.decode_secret, 'a' * 4)

    def test_decode_secret_not_base64(self):
        self.assertRaises(ValueError, crypto_utils.decode_secret,
                          '-' + 'a' * 43)

    def test_decode_secret_ok(self):
        decoded = crypto_utils.decode_secret(
            'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=')
        self.assertEqual('a' * 32, decoded)
