# Copyright (c) 2010-2012 OpenStack Foundation
# Copyright (c) 2019 OpenIO SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from swift.common.middleware.healthcheck import HealthCheckMiddleware as HCM
from swift.common.swob import HTTPOk
from swift.common.utils import config_auto_int_value
from oio.common.json import json

STATUS_PATH = '/_status'


class HealthCheckMiddleware(HCM):
    """
    Extension of swift's HealthCheckMiddleware counting the number of
    requests currently being processed.
    """

    def __init__(self, app, conf):
        super(HealthCheckMiddleware, self).__init__(app, conf)
        self.status_path = conf.get('status_path', STATUS_PATH)
        counters = conf.get('oioswift_counters', {})
        self.cur_reqs = counters.get('current_requests')
        self.workers = config_auto_int_value(conf.get('workers'), 1)

    def dump_status(self):
        """
        Build a response with the current status of the server
        as a json object.
        """
        cur_reqs = self.cur_reqs.value if self.cur_reqs else 0
        status = {
            'stat.cur_reqs': cur_reqs,
            'stat.workers': self.workers,
        }
        return HTTPOk(body=json.dumps(status),
                      headers={'Content-Type': 'application/json'})

    def __call__(self, env, start_response):
        path = env.get('PATH_INFO')
        if path == self.status_path:
            return self.dump_status()(env, start_response)
        elif path == '/healthcheck':
            # Do not count health check requests
            return super(HealthCheckMiddleware, self).__call__(
                env, start_response)

        if self.cur_reqs:
            with self.cur_reqs.get_lock():
                self.cur_reqs.value += 1
        try:
            return super(HealthCheckMiddleware, self).__call__(
                env, start_response)
        finally:
            if self.cur_reqs:
                with self.cur_reqs.get_lock():
                    self.cur_reqs.value -= 1


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def healthcheck_filter(app):
        return HealthCheckMiddleware(app, conf)
    return healthcheck_filter
