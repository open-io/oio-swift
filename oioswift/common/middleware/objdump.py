# Copyright (c) 2010-2012 OpenStack Foundation
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

import json
import objgraph

from swift.common.swob import Request, Response


class ObjDumpMiddleware(object):
    """
    Healthcheck middleware used for monitoring.

    If the path is /objdump, it will respond 200 with "OK" as the body.

    If the optional config parameter "disable_path" is set, and a file is
    present at that path, it will respond 503 with "DISABLED BY FILE" as the
    body.
    """

    def __init__(self, app, conf):
        self.app = app
        self.disable_path = conf.get('disable_path', '')

    def GET(self, req):
        """Returns a 200 response with "OK" in the body."""
        stat = {
            'most': objgraph.most_common_types(limit=20, shortnames=False),
        }
        ret = []
        for x in objgraph.get_leaking_objects():
            ret.append([str(x), str(type(x))])
        stat['leak'] = ret
        data = json.dumps(stat)
        return Response(request=req, body=data, content_type="application/json")

    def __call__(self, env, start_response):
        req = Request(env)
        if req.path == '/objdump':
            return self.GET(req)(env, start_response)
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def objdump_filter(app):
        return ObjDumpMiddleware(app, conf)
    return objdump_filter
