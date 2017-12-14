# Copyright (C) 2017 OpenIO SAS
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

from swift.common.utils import config_true_value, get_logger
from oioswift.common.middleware.autocontainerbase import AutoContainerBase
from oio.common.autocontainer import RegexContainerBuilder
from oio.common.exceptions import ConfigurationException


class RegexContainerMiddleware(AutoContainerBase):

    BYPASS_QS = "bypass-autocontainer"
    BYPASS_HEADER = "X-bypass-autocontainer"

    def __init__(self, app, acct, patterns,
                 **kwargs):
        super(RegexContainerMiddleware, self).__init__(
            app, acct, **kwargs)
        self.con_builder = RegexContainerBuilder(patterns)


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    acct = conf.get('sds_default_account')

    if acct is None:
        raise ConfigurationException('No OIO-SDS account configured')

    account_first = config_true_value(local_config.get('account_first'))
    swift3_compat = config_true_value(local_config.get('swift3_compat'))
    strip_v1 = config_true_value(local_config.get('strip_v1'))
    # By default this is enabled, to be compatible with openio-sds < 4.2.
    stop_at_first_match = config_true_value(
        local_config.get('stop_at_first_match', True))
    pattern_dict = {k: v for k, v in local_config.items()
                    if k.startswith("pattern")}

    def factory(app):
        patterns = [pattern_dict[k] for k in sorted(pattern_dict.keys())]
        logger = get_logger(conf)
        logger.info("Using patterns %s", patterns)
        return RegexContainerMiddleware(
            app, acct, patterns,
            strip_v1=strip_v1, account_first=account_first,
            swift3_compat=swift3_compat,
            stop_at_first_match=stop_at_first_match)
    return factory
