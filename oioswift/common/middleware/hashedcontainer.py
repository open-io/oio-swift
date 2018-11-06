# Copyright (C) 2016-2018 OpenIO SAS
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
from oioswift.common.middleware.autocontainerbase import AutoContainerBase
from oio.common.exceptions import ConfigurationException


class HashedContainerMiddleware(AutoContainerBase):

    BYPASS_QS = "bypass-autocontainer"
    BYPASS_HEADER = "X-bypass-autocontainer"
    TRUE_VALUES = ["true", "yes", "1"]
    EXTRA_KEYWORDS = ['offset', 'size', 'bits']

    def __init__(self, app, ns, acct, proxy=None,
                 strip_v1=False, account_first=False,
                 **kwargs):
        super(HashedContainerMiddleware, self).__init__(
            app, acct, strip_v1=strip_v1, account_first=account_first)
        conf = {"namespace": ns, "proxyd_url": proxy}
        try:
            # New API (openio-sds >= 4.2)
            from oio.cli.common.clientmanager import ClientManager
            climgr = ClientManager(conf)
            self.con_builder = climgr.flatns_manager
        except ImportError:
            # Old API
            # pylint: disable=redefined-variable-type,no-member
            from oio.cli.clientmanager import ClientManager
            climgr = ClientManager(conf)
            self.con_builder = climgr.get_flatns_manager()
        for k, v in kwargs.items():
            if k in self.EXTRA_KEYWORDS:
                self.con_builder.__dict__[k] = v


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
                                         account_first=account_first,
                                         **local_config)
    return factory
