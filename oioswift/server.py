# Copyright (c) 2016-2018 OpenIO SAS
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

from swift.common import request_helpers, storage_policy
from oioswift.common.request_helpers import OioSegmentedIterable
from oioswift.common.storage_policy import POLICIES
from oioswift.common.ring import FakeRing
from oioswift.proxy.controllers.container import ContainerController
from oioswift.proxy.controllers.account import AccountController
from oioswift.proxy.controllers.obj import ObjectControllerRouter
from oio import ObjectStorageApi
from swift.proxy.server import Application as SwiftApplication
from swift.common.utils import config_true_value
import swift.common.utils
import swift.proxy.server


ring_args = [
    {'replicas': 1}
]


swift.proxy.server.POLICIES = POLICIES
swift.proxy.server.AccountController = AccountController
swift.proxy.server.ContainerController = ContainerController
swift.proxy.server.ObjectControllerRouter = ObjectControllerRouter

request_helpers.SegmentedIterable = OioSegmentedIterable

swift.common.utils.validate_hash_conf = lambda: None


class Application(SwiftApplication):
    def __init__(self, conf, memcache=None, logger=None, account_ring=None,
                 container_ring=None, storage=None):
        for policy, ring_arg in zip(POLICIES, ring_args):
            if ring_arg is not None:
                policy.object_ring = FakeRing(**ring_arg)

        SwiftApplication.__init__(self, conf, memcache=memcache, logger=logger,
                                  account_ring=account_ring,
                                  container_ring=container_ring)
        if conf is None:
            conf = dict()
        sds_conf = {k[4:]: v
                    for k, v in conf.iteritems()
                    if k.startswith("sds_")}

        self.oio_stgpol = []
        if 'auto_storage_policies' in conf:
            for elem in conf['auto_storage_policies'].split(','):
                if ':' in elem:
                    name, offset = elem.split(':')
                    self.oio_stgpol.append((name, int(offset)))
                else:
                    self.oio_stgpol.append((elem, 0))
            self.oio_stgpol.sort(key=lambda x: x[1])

        policies = []
        if 'oio_storage_policies' in conf:
            for i, pol in enumerate(conf['oio_storage_policies'].split(',')):
                policies.append(
                    storage_policy.StoragePolicy(i, pol, is_default=i == 0))
        else:
            policies.append(storage_policy.StoragePolicy(0, 'SINGLE', True))

        self.POLICIES = storage_policy.StoragePolicyCollection(policies)

        # Mandatory, raises KeyError
        sds_namespace = sds_conf['namespace']
        sds_conf.pop('namespace')  # removed to avoid unpacking conflict
        # Loaded by ObjectStorageApi if None
        sds_proxy_url = sds_conf.pop('proxy_url', None)
        # Fix boolean parameter
        if 'autocreate' in sds_conf and not (
                hasattr(ObjectStorageApi, 'EXTRA_KEYWORDS') or
                'autocreate' in ObjectStorageApi.EXTRA_KEYWORDS):
            logger.warn("'autocreate' parameter is ignored by current version"
                        " of OpenIO SDS. Please update to oio>=4.1.23.")
        else:
            sds_conf['autocreate'] = config_true_value(
                sds_conf.get('autocreate', 'true'))

        self.storage = storage or \
            ObjectStorageApi(sds_namespace, endpoint=sds_proxy_url, **sds_conf)
        self.delete_slo_parts = \
            config_true_value(conf.get('delete_slo_parts', False))
        self.check_state = \
            config_true_value(conf.get('check_state', False))


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    account_ring = FakeRing()
    container_ring = FakeRing()
    app = Application(conf, account_ring=account_ring,
                      container_ring=container_ring)
    app.check_config()
    return app
