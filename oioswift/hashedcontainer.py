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
from swift.common.swob import HTTPBadRequest
from oio.cli.clientmanager import ClientManager


class HashedcontainerMiddleware(object):

    BYPASS_QS = "bypass-autocontainer"
    BYPASS_HEADER = "X-bypass-autocontainer"
    TRUE_VALUES = ["true", "yes", "1"]

    def __init__(self, app, ns, acct, proxy, *_args, **_kwargs):
        self.app = app
        self.account = acct
        self.bypass_header_key = ("HTTP_" +
                                  self.BYPASS_HEADER.upper().replace('-', '_'))
        climgr = ClientManager({
            "namespace": ns,
            "proxyd_url": proxy,
        })
        self.con_builder = climgr.get_flatns_manager()

    def should_bypass(self, env):
        """Should we bypass this filter?"""
        header = env.get(self.bypass_header_key, "").lower()
        query = parse_qs(env.get('QUERY_STRING', "")).get(self.BYPASS_QS, [""])
        return header in self.TRUE_VALUES or query[0] in self.TRUE_VALUES

    def __call__(self, env, start_response):
        if self.should_bypass(env):
            return self.app(env, start_response)

        path = env.get('PATH_INFO')
        version, obj = split_path(path, 1, 2, True)
        if version != 'v1':
            # TODO(jfs) Let someone return an error, someone who knows how
            return self.app(env, start_response)

        container = self.con_builder(obj)
        path = "/v1/%s/%s/%s" % (self.account, container, obj)
        env['PATH_INFO'] = path
        return self.app(env, start_response)


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    ns = conf.get('sds_namespace')
    acct = conf.get('sds_default_account')
    proxy = conf.get('sds_proxy_url')

    if ns is None:
        raise Exception('No OIO-SDS namespace configured')
    if acct is None:
        raise Exception('No OIO-SDS account configured')
    if proxy is None:
        raise Exception('No OIO-SDS proxy URL configured')

    def factory(app):
        return HashedcontainerMiddleware(app, ns, acct, proxy)
    return factory
