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

from swift.common.swob import Request, HTTPException
from swift.common.middleware.crypto.decrypter import \
    Decrypter as OrigDecrypter, DecrypterObjContext as OrigDecrypterObjContext
from swift.common.utils import config_true_value
from swift.proxy.controllers.base import get_object_info


class DecrypterObjContext(OrigDecrypterObjContext):

    def get_decryption_keys(self, req):
        """
        Determine if a response should be decrypted, and if so then fetch keys.

        :param req: a Request object
        :returns: a dict of decryption keys
        """
        if config_true_value(req.environ.get('swift.crypto.override')):
            self.logger.debug('No decryption is necessary because of override')
            return None

        info = get_object_info(req.environ, self.app, swift_source='DCRYPT')
        if 'crypto-etag' not in info['sysmeta']:
            # object is not cyphered
            return None

        try:
            return self.get_keys(req.environ)
        except HTTPException:
            # FIXME(FVE): check swift_source, accept if it is internal
            # FIXME(FVE): move that code to avoid printing an error
            if req.method == 'HEAD':
                return None
            else:
                raise


class Decrypter(OrigDecrypter):
    """Middleware for decrypting data and user metadata."""

    def __call__(self, env, start_response):
        req = Request(env)
        try:
            parts = req.split_path(3, 4, True)
        except ValueError:
            return self.app(env, start_response)

        if parts[3] and req.method == 'GET':
            handler = DecrypterObjContext(self, self.logger).handle_get
        elif parts[3] and req.method == 'HEAD':
            handler = DecrypterObjContext(self, self.logger).handle_head
        # Only difference with the base middleware: do not decrypt
        # object metadata in object listings.
        else:
            # url and/or request verb is not handled by decrypter
            return self.app(env, start_response)

        try:
            return handler(req, start_response)
        except HTTPException as err_resp:
            return err_resp(env, start_response)