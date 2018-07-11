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

import os
import sys

from swift.common.swob import HTTPBadRequest, HTTPCreated, Request
from swift.common.middleware.crypto.crypto_utils import CRYPTO_KEY_CALLBACK

from oioswift.common.middleware.crypto import encrypter

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__,
                                                '../../../../../..')))
from test.unit import FakeLogger  # noqa
from test.unit.common.middleware.helpers import FakeSwift  # noqa
from test.unit.common.middleware.crypto.test_encrypter import \
    TestEncrypter as OrigTestEncrypter  # noqa


class TestEncrypter(OrigTestEncrypter):
    def setUp(self):
        self.app = FakeSwift()
        self.encrypter = encrypter.Encrypter(self.app, {})
        self.encrypter.logger = FakeLogger()

    def test_PUT_missing_key_in_header(self):
        def raise_exc():
            raise HTTPBadRequest(
                'Missing X-Amz-Server-Side-Encryption-Customer-Key header')

        body = 'FAKE APP'
        env = {'REQUEST_METHOD': 'PUT',
               CRYPTO_KEY_CALLBACK: raise_exc}
        hdrs = {'content-type': 'text/plain',
                'content-length': str(len(body))}
        req = Request.blank('/v1/a/c/o', environ=env, body=body, headers=hdrs)
        self.app.register('PUT', '/v1/a/c/o', HTTPCreated, {})
        resp = req.get_response(self.encrypter)
        # If it does not find a key, no problem,
        # oioswift's encrypter let the request pass through,
        # and does not encrypt the object.
        self.assertEqual('201 Created', resp.status)
