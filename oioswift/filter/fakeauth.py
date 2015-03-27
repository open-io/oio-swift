# Copyright (C) 2015 OpenIO SAS

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from logging import getLogger

from webob import exc
from webob import Request
from webob import Response
from eventlet import Timeout

from oioswift.utils import split_path
from oioswift.utils import config_true_value


"""
Fakeauth filter provides a very basic authentication support.
Simplified version of tempauth middleware from Swift.
"""


class FakeAuth(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = getLogger('fakeauth')
        self.reseller_prefix = 'AUTH_'
        self.auth_prefix = conf.get('auth_prefix', '/auth/')

        if self.auth_prefix[0] != '/':
            self.auth_prefix += '/'
        if self.auth_prefix[-1] != '/':
            self.auth_prefix += '/'
        self.auth_override = config_true_value(conf.get('auth_override'))
        self.users = {}
        self.token = conf.get('token', 'DummyToken')
        for conf_key in conf:
            if conf_key.startswith('user_'):
                account, username = conf_key.split('_', 1)[1].split('_')
                key = conf[conf_key]
                if not key:
                    raise ValueError('%s has no key set' % conf_key)

                url = '$HOST/v1/%s%s' % (self.reseller_prefix, account)
                self.users[account + ':' + username] = {
                    'key': key, 'url': url}

    def __call__(self, env, start_response):
        if self.auth_override:
            return self.app(env, start_response)
        if env.get('PATH_INFO', '').startswith(self.auth_prefix):
            return self.handle(env, start_response)
        return self.app(env, start_response)

    def handle(self, env, start_response):
        try:
            req = Request(env)
            if self.auth_prefix:
                req.path_info_pop()
            if 'x-storage-token' in req.headers and \
                    'x-auth-token' not in req.headers:
                req.headers['x-auth-token'] = req.headers['x-storage-token']
            return self.handle_request(req)(env, start_response)
        except (Exception, Timeout):
            self.logger.exception('ERROR Unhandled exception in request')
            start_response('500 Server Error',
                           [('Content-Type', 'text/plain')])
            return ['Internal server error.\n']

    def handle_request(self, req):
        handler = None
        try:
            version, account, user, _junk = split_path(req.path, 1, 4, True)
        except ValueError:
            return exc.HTTPNotFound()
        if version in ('v1', 'v1.0', 'auth'):
            if req.method == 'GET':
                handler = self.handle_get_token
        if not handler:
            req.response = exc.HTTPBadRequest()
        else:
            req.response = handler(req)
        return req.response

    def handle_get_token(self, req):
        try:
            pathsegs = split_path(req.path, 1, 3, True)
        except ValueError:
            return exc.HTTPNotFound()
        if pathsegs[0] == 'v1' and pathsegs[2] == 'auth':
            account = pathsegs[1]
            user = req.headers.get('x-storage-user')
            if not user:
                user = req.headers.get('x-auth-user')
                if not user or ':' not in user:
                    return exc.HTTPUnauthorized()
                account2, user = user.split(':', 1)
                if account != account2:
                    return exc.HTTPUnauthorized()
            key = req.headers.get('x-storage-pass')
            if not key:
                key = req.headers.get('x-auth-key')
        elif pathsegs[0] in ('auth', 'v1.0'):
            user = req.headers.get('x-auth-user')
            if not user:
                user = req.headers.get('x-storage-user')
            if not user or ':' not in user:
                return exc.HTTPUnauthorized()
            account, user = user.split(':', 1)
            key = req.headers.get('x-auth-key')
            if not key:
                key = req.headers.get('x-storage-pass')
        else:
            return exc.HTTPBadRequest()
        if not all((account, user, key)):
            return exc.HTTPUnauthorized()

        account_user = account + ':' + user
        if account_user not in self.users:
            return exc.HTTPUnauthorized()
        if self.users[account_user]['key'] != key:
            return exc.HTTPUnauthorized()

        resp = Response(headers={
            'x-auth-token': self.token, 'x-storage-token': self.token})
        url = self.users[account_user]['url'].replace('$HOST', req.host_url)
        resp.headers['x-storage-url'] = url
        return resp


def filter_factory(global_config, **local_conf):
    conf = global_config.copy()
    conf.update(local_conf)

    def fakeauth_filter(app):
        app = FakeAuth(app, conf)
        return app

    return fakeauth_filter