# Copyright (c) 2016 OpenIO SAS
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

from oioswift.common.storage_policy import POLICIES
from oioswift.common.ring import FakeRing
from oioswift.proxy.controllers.container import ContainerController
from oioswift.proxy.controllers.account import AccountController
from oioswift.proxy.controllers.obj import ObjectControllerRouter
from oio.api.object_storage import ObjectStorageAPI
from swift.proxy.server import Application as SwiftApplication
import swift.common.utils
import swift.proxy.server


ring_args = [
    {'replicas': 1}
]


swift.proxy.server.POLICIES = POLICIES
swift.proxy.server.AccountController = AccountController
swift.proxy.server.ContainerController = ContainerController
swift.proxy.server.ObjectControllerRouter = ObjectControllerRouter


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
            conf = {}
        sds_conf = {k[4:]: v
                    for k, v in conf.iteritems()
                    if k.startswith("sds_")}
        # Mandatory, raises KeyError
        sds_namespace = sds_conf['namespace']
        sds_conf.pop('namespace')  # removed to avoid unpacking conflict
        # Loaded by ObjectStorageAPI if None
        sds_proxy_url = sds_conf.get('proxy_url')
        self.storage = storage or \
            ObjectStorageAPI(sds_namespace, sds_proxy_url, **sds_conf)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    account_ring = FakeRing()
    container_ring = FakeRing()
    app = Application(conf, account_ring=account_ring,
                      container_ring=container_ring)
    app.check_config()
    return app
