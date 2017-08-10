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

from oioswift.common.middleware.autocontainerbase import AutoContainerBase
from oio.common.autocontainer import AutocontainerBuilder


class AutoContainerMiddleware(AutoContainerBase):

    BYPASS_QS = "bypass-autocontainer"
    BYPASS_HEADER = "X-bypass-autocontainer"
    TRUE_VALUES = ["true", "yes", "1"]

    def __init__(self, app, default_account=None,
                 strip_v1=False, account_first=False, **kwargs):
        super(AutoContainerMiddleware, self).__init__(
            app, acct=default_account,
            strip_v1=strip_v1, account_first=account_first)
        self.con_builder = AutocontainerBuilder(**kwargs)


def filter_factory(global_config, **local_config):
    conf = global_config.copy()
    conf.update(local_config)

    default_account = conf.get('sds_default_account')
    # TODO(jfs): remove this block in further releases
    if not default_account:
        default_account = conf.get('default_account')

    # Some options are too specific to be generalized
    offset = int(local_config.get('offset', 0))
    size = local_config.get('size')
    if size is not None:
        size = int(size)
    base = int(local_config.get('base', 16))
    mask = int(local_config.get('mask', 0xFFFFFFFFFF0000FF), 16)
    con_format = local_config.get('format', "%016X")

    def factory(app):
        return AutoContainerMiddleware(app, default_account=default_account,
                                       offset=offset, size=size, mask=mask,
                                       base=base, con_format=con_format)
    return factory
