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

from swift.common.swob import HTTPException, Request
from swift.common.utils import config_true_value
from swift.common.middleware.crypto.crypto_utils import CRYPTO_KEY_CALLBACK
from swift.common.middleware.crypto.encrypter import Encrypter as OrigEncrypter

from oioswift.common.middleware.crypto.keymaster import MISSING_KEY_MSG


class Encrypter(OrigEncrypter):

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

        fetch_crypto_keys = env.get(CRYPTO_KEY_CALLBACK)
        if fetch_crypto_keys is not None:
            try:
                fetch_crypto_keys()
            except HTTPException as exc:
                if MISSING_KEY_MSG in exc.body:
                    if req.method in ('PUT', 'POST'):
                        # No key, just upload without encryption
                        env['swift.crypto.override'] = True
                    # else:
                    #   let the thing fail later,
                    #   if a key is required for decoding
                else:
                    raise
            except Exception:
                # Let the parent class handle other exceptions
                pass
        res = super(Encrypter, self).__call__(env, start_response)
        return res
