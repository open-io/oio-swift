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

from swift.common.middleware.crypto.encrypter import Encrypter as OrigEncrypter
from swift.common.swob import header_to_environ_key, HTTPBadRequest, Request
from swift.common.utils import config_true_value

from oioswift.common.middleware.crypto.crypto_utils import KEY_HEADER, \
    decode_secret


ENCRYPTION_KEY_ENV_KEY = header_to_environ_key(KEY_HEADER)


class Encrypter(OrigEncrypter):

    def check_key(self, b64_key):
        """Check that the key has the proper format and length."""
        try:
            decode_secret(b64_key)
        except ValueError:
            raise HTTPBadRequest('Invalid secret key')

    def __call__(self, env, start_response):
        if config_true_value(env.get('swift.crypto.override')):
            return self.app(env, start_response)

        req = Request(env)

        if self.disable_encryption and req.method in ('PUT', 'POST'):
            return self.app(env, start_response)
        try:
            req.split_path(4, 4, True)
        except ValueError:
            return self.app(env, start_response)

        b64_key = env.get(ENCRYPTION_KEY_ENV_KEY)
        if b64_key is None:
            env['swift.crypto.override'] = True
        else:
            self.check_key(b64_key)
        res = super(Encrypter, self).__call__(env, start_response)
        return res
