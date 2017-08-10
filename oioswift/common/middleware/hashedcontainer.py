# Copyright (C) 2016-2017 OpenIO SAS
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

from swift.common.utils import config_true_value
from oio.common.exceptions import ConfigurationException
# TODO(jfs): currently in oio.cli, need to adapt as sson as it has been
#            factorized
from oio.cli.clientmanager import ClientManager


class HashedContainerMiddleware(object):

    BYPASS_QS = "bypass-autocontainer"
    BYPASS_HEADER = "X-bypass-autocontainer"
    TRUE_VALUES = ["true", "yes", "1"]

    def __init__(self, app, ns, acct, proxy,
                 strip_v1=False, account_first=False):
        super(HashedContainerMiddleware, self).__init__(
            app, acct, strip_v1=strip_v1, account_first=account_first)
        climgr = ClientManager({
            "namespace": ns,
            "proxyd_url": proxy,
        })
        self.con_builder = climgr.get_flatns_manager()


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    ns = conf.get('sds_namespace')
    acct = conf.get('sds_default_account')
    proxy = conf.get('sds_proxy_url')

    if ns is None:
        raise ConfigurationException('No OIO-SDS namespace configured')
    if acct is None:
        raise ConfigurationException('No OIO-SDS account configured')
    if proxy is None:
        raise ConfigurationException('No OIO-SDS proxy URL configured')

    strip_v1 = config_true_value(local_config.get('strip_v1'))
    account_first = config_true_value(local_config.get('account_first'))

    def factory(app):
        return HashedContainerMiddleware(app, ns, acct, proxy,
                                         strip_v1=strip_v1,
                                         account_first=account_first)
    return factory
