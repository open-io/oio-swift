# Copyright (C) 2016 OpenIO SAS
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

from urlparse import parse_qs
from swift.common.utils import split_path
from oio.common.autocontainer import AutocontainerBuilder


class AutocontainerMiddleware(object):

    BYPASS_QS = "bypass-autocontainer"
    BYPASS_HEADER = "X-bypass-autocontainer"
    TRUE_VALUES = ["true", "yes", "1"]

    def __init__(self, app, default_account=None, *_args, **kwargs):
        self.app = app
        self.default_account = default_account
        self.con_builder = AutocontainerBuilder(**kwargs)
        self.bypass_header_key = ("HTTP_" +
                                  self.BYPASS_HEADER.upper().replace('-', '_'))

    def should_bypass(self, env):
        """Should we bypass this filter?"""
        header = env.get(self.bypass_header_key, "").lower()
        query = parse_qs(env.get('QUERY_STRING', "")).get(self.BYPASS_QS, [""])
        return header in self.TRUE_VALUES or query[0] in self.TRUE_VALUES

    def __call__(self, env, start_response):
        if self.should_bypass(env):
            return self.app(env, start_response)

        if self.default_account:
            obj = env.get('PATH_INFO').strip('/')
            acc = self.default_account
        else:
            acc, obj = split_path(env.get('PATH_INFO'), 1, 2, True)

        con = self.con_builder(obj)
        path = "/v1/%s/%s/%s" % (acc, con, obj)
        env['PATH_INFO'] = path
        return self.app(env, start_response)


def filter_factory(_global_config, **local_config):
    default_account = local_config.get('default_account')
    offset = int(local_config.get('offset', 0))
    size = local_config.get('size')
    if size is not None:
        size = int(size)
    base = int(local_config.get('base', 16))
    mask = int(local_config.get('mask', 0xFFFFFFFFFF0000FF), 16)
    con_format = local_config.get('format', "%016X")

    def factory(app):
        return AutocontainerMiddleware(app, default_account=default_account,
                                       offset=offset, size=size, mask=mask,
                                       base=base, con_format=con_format)
    return factory
