# Copyright (c) 2015 OpenStack Foundation
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

import hashlib
import hmac
import os

from swift.common.swob import Request, HTTPException, HTTPBadRequest
from swift.common import wsgi
from swift.common.middleware.crypto import keymaster

from oioswift.common.middleware.crypto.crypto_utils import decode_secret, \
    KEY_HEADER, ALGO_ENV_KEY, KEY_ENV_KEY, KEY_MD5_ENV_KEY

MISSING_KEY_MSG = 'Missing %s header' % KEY_HEADER


def make_encrypted_env(env, method=None, path=None, agent='Swift',
                       query_string=None, swift_source=None):
    """Same as :py:func:`make_env` but with encryption env, if available."""
    newenv = wsgi.make_env(
        env, method=method, path=path, agent=agent, query_string=query_string,
        swift_source=swift_source)
    for name in (ALGO_ENV_KEY, KEY_ENV_KEY, KEY_MD5_ENV_KEY):
        if name in env:
            newenv[name] = env[name]
    return newenv


def make_encrypted_subrequest(env, method=None, path=None, body=None,
                              headers=None, agent='Swift', swift_source=None,
                              make_env=make_encrypted_env):
    """
    Same as :py:func:`make_subrequest` but with encryption env, if available.
    """
    return wsgi.make_subrequest(
        env, method=method, path=path, body=body, headers=headers, agent=agent,
        swift_source=swift_source, make_env=make_env)


class KeyMasterContext(keymaster.KeyMasterContext):

    def __init__(self, keymaster, req, account, container, obj=None):
        super(KeyMasterContext, self).__init__(keymaster, account,
                                               container, obj)
        self.req = req

    def _fetch_object_secret(self):
        b64_secret = self.req.headers.get(KEY_HEADER)
        if not b64_secret:
            raise HTTPBadRequest(MISSING_KEY_MSG)
        try:
            secret = decode_secret(b64_secret)
        except ValueError:
            raise HTTPBadRequest('%s header must be a base64 '
                                 'encoding of exactly 32 raw bytes' %
                                 KEY_HEADER)
        return secret

    def fetch_crypto_keys(self, *args, **kwargs):
        """
        Setup container and object keys based on the request path and
        header-provided encryption secret.

        :returns: A dict containing encryption keys for 'object' and
                  'container' and a key 'id'.
        """
        if self._keys:
            return self._keys

        self._keys = {}
        account_path = os.path.join(os.sep, self.account)

        if self.container:
            path = os.path.join(account_path, self.container)
            self._keys['container'] = self.keymaster.create_key(path, None)

            if self.obj:
                secret = self._fetch_object_secret()
                path = os.path.join(path, self.obj)
                self._keys['object'] = self.keymaster.create_key(path, secret)

            self._keys['id'] = {'v': '1', 'path': path}

        return self._keys


class KeyMaster(keymaster.KeyMaster):

    def __call__(self, env, start_response):
        req = Request(env)

        try:
            parts = req.split_path(2, 4, True)
        except ValueError:
            return self.app(env, start_response)

        if req.method in ('PUT', 'POST', 'GET', 'HEAD'):
            # handle only those request methods that may require keys
            km_context = KeyMasterContext(self, req, *parts[1:])
            try:
                return km_context.handle_request(req, start_response)
            except HTTPException as err_resp:
                return err_resp(env, start_response)
            except KeyError as err:
                if 'object' in err.args:
                    self.app.logger.debug(
                        'Missing encryption key, cannot handle request')
                    raise HTTPBadRequest(MISSING_KEY_MSG)
                else:
                    raise

        # anything else
        return self.app(env, start_response)

    def create_key(self, key_id, secret=None):
        """
        Derive an encryption key.

        :param key_id: initialization vector for the new key
        :param secret: secret key to derive. If `None`, use
            `self.root_secret`.
        """
        return hmac.new(secret or self.root_secret, key_id,
                        digestmod=hashlib.sha256).digest()


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def keymaster_filter(app):
        # The default make_subrequest function won't let the encryption
        # headers pass through, therefore we must patch it.
        from swift.common import request_helpers
        request_helpers.make_subrequest = make_encrypted_subrequest
        return KeyMaster(app, conf)

    return keymaster_filter
