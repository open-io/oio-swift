# Copyright (C) 2020 OpenIO SAS
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

import re

from swift.common.middleware.proxy_logging import ProxyLoggingMiddleware
from swift.common.swob import Request
from swift.common.utils import config_true_value, get_logger


def flat_dict_from_dict(dict_):
    """
    Create a dictionary without depth.

    {
        'depth0': {
            'depth1': {
                'depth2': 'test1',
                'depth2': 'test2'
            }
        }
    }
    =>
    depth0.depth1.depth2:test1;depth0.depth1.depth2:test2
    """
    flat_dict = dict()
    for key, value in dict_.items():
        if not isinstance(value, dict):
            flat_dict[key] = value
            continue

        flat_dict_ = flat_dict_from_dict(value)
        for key_, value_ in flat_dict_.items():
            flat_dict[key + '.' + key_] = value_
    return flat_dict


def perfdata_to_str(perfdata):
    flat_perfdata = flat_dict_from_dict(perfdata)
    perfdata_list = list()
    perfdata_list.append('PERFDATA')
    for key, value in sorted(flat_perfdata.items()):
        if key.startswith('rawx.'):
            if 'http' in key[5:]:
                key = key[:key.index('http') + 4]
        perfdata_list.append(key + ':' + '%.4f' % value)
    return '...'.join(perfdata_list)


class OioProxyLoggingMiddleware(ProxyLoggingMiddleware):
    """
    Keep the same behavior as ProxyLoggingMiddleware,
    but add the values of 'perfdata' if it is enabled.
    """

    def __init__(self, app, conf):
        super(OioProxyLoggingMiddleware, self).__init__(app, conf)
        self.logger = get_logger(conf)
        self.perfdata = config_true_value(conf.get('oio_perfdata', 'false'))
        self.perfdata_user_agents = None
        if self.perfdata:
            pattern_dict = {k: v for k, v in conf.items()
                            if k.startswith("oio_perfdata_user_agent")}
            self.perfdata_user_agents = [re.compile(pattern_dict[k])
                                         for k in sorted(pattern_dict.keys())]
            if not self.perfdata_user_agents:
                self.logger.warn('No user_agent pattern defined, '
                                 'all clients will add perfdata.')

    def log_request(self, req, *args, **kwargs):
        oio_perfdata = req.environ.get('oio.perfdata')
        if oio_perfdata is not None:
            req.environ.setdefault('swift.log_info', []).append(
                    perfdata_to_str(oio_perfdata))
        super(OioProxyLoggingMiddleware, self).log_request(
            req, *args, **kwargs)

    def __call__(self, env, start_response):
        if self.perfdata:
            add_perfata = False
            if not self.perfdata_user_agents:
                add_perfata = True
            else:
                req = Request(env)
                if req.user_agent:
                    for pat in self.perfdata_user_agents:
                        if pat.match(req.user_agent):
                            add_perfata = True
                            break
            if add_perfata:
                env.setdefault('oio.perfdata', dict())
        return super(OioProxyLoggingMiddleware, self).__call__(
            env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def proxy_logger(app):
        return OioProxyLoggingMiddleware(app, conf)
    return proxy_logger
