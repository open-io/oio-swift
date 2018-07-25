# Copyright (c) 2011-2014 OpenStack Foundation
# Copyright (C) 2018 OpenIO SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Based on swift/common/middleware/tempauth.py
"""

from time import time
from hashlib import sha1
import hmac
import base64

from swift.common.utils import cache_from_env

from swift.common.middleware.tempauth import TempAuth


class OioTempAuth(TempAuth):
    def __init__(self, app, conf):
        super(OioTempAuth, self).__init__(app, conf)
        self.logger.warning("oioswift.tempauth in use")

    def get_groups(self, env, token):
        """
        Get groups for the given token.

        :param env: The current WSGI environment dictionary.
        :param token: Token to validate and return a group string for.
        :returns: None if the token is invalid or a string containing a comma
                  separated list of groups the authenticated user is a member
                  of. The first group in the list is also considered a unique
                  identifier for that user.
        """
        groups = None
        memcache_client = cache_from_env(env)
        if not memcache_client:
            raise Exception('Memcache required')
        memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token)
        cached_auth_data = memcache_client.get(memcache_token_key)
        if cached_auth_data:
            expires, groups = cached_auth_data
            if expires < time():
                groups = None

        s3_auth_details = env.get('swift3.auth_details')
        if s3_auth_details:
            account_user = s3_auth_details['access_key']
            signature_from_user = s3_auth_details['signature']
            if account_user not in self.users:
                return None
            account, user = account_user.split(':', 1)
            account_id = self.users[account_user]['url'].rsplit('/', 1)[-1]
            path = env['PATH_INFO']
            env['PATH_INFO'] = path.replace(account_user, account_id, 1)
            if 'check_signature' in s3_auth_details:
                if not s3_auth_details['check_signature'](
                        self.users[account_user]['key']):
                    return None
            else:
                valid_signature = base64.encodestring(hmac.new(
                    self.users[account_user]['key'],
                    s3_auth_details['string_to_sign'],
                    sha1).digest()).strip()
                if signature_from_user != valid_signature:
                    return None
            groups = self._get_user_groups(account, account_user, account_id)

        return groups


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def tempauth_filter(app):
        return OioTempAuth(app, conf)

    return tempauth_filter
