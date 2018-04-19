# Copyright (c) 2015 OpenStack Foundation
# Copyright (c) 2018 OpenIO SAS
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
"""
Please check original doc from swift/common/middleware/copy.py
"""

# from oio.common.http import ranges_from_http_header

from six.moves.urllib.parse import unquote

from swift.common.middleware.copy import ServerSideCopyMiddleware
from swift.common.swob import Request
from swift.proxy.controllers.base import get_object_info


class OioServerSideCopyMiddleware(ServerSideCopyMiddleware):

    def __init__(self, app, conf):
        super(OioServerSideCopyMiddleware, self).__init__(app, conf)
        self.logger.warning("oioswift.copy in use")

    def fast_copy_allowed(self, req):
        """Check is fastcopy is possible and allowed."""

        if req.method != 'PUT' or 'X-Copy-From' not in req.headers:
            return False

        fast_copy_forbidden = req.environ.get('oio.forbid_fast_copy')
        if fast_copy_forbidden:
            return False

        self.logger.debug("COPY: checking if fast copy is allowed")

        # Among the several subrequests we may execute, only one can use
        # fast copy. This will prevent subsequent requests to even do
        # the check.
        req.environ['oio.forbid_fast_copy'] = True

        if req.headers.get('Range') or \
                req.headers.get('X-Amz-Copy-Source-Range'):
            self.logger.debug(
                "COPY: fast copy not available (reason=Range header)")
            return False

        # now check if object is a SLO:
        # when a SLO is used as source without range read,
        # it is used to recreate a plain object
        # TODO: we may cheat to create object as appended metachunks?

        try:
            # [0]=v1, [1]=account, [2]=container/obj
            src_path_parts = req.split_path(2, 3, True)
        except ValueError:
            self.logger.debug("COPY: Incomplete path, cannot copy")
            return False

        # Reuse version from original path,
        # take account from header or original path,
        # take /container/obj from headers (with leading slash)
        src_path = '/%s/%s%s' % (src_path_parts[0],
                                 req.environ.get('HTTP_X_COPY_FROM_ACCOUNT',
                                                 src_path_parts[1]),
                                 req.environ['HTTP_X_COPY_FROM'])
        try:
            obj_inf = get_object_info(req.environ, self.app,
                                      path=src_path,
                                      swift_source='COPY')
            is_slo = obj_inf.get('sysmeta', {}).get('slo-size', False)
            if is_slo:
                self.logger.debug(
                    "COPY: fast copy not available (reason=source is a SLO)")
            return not is_slo
        except Exception as exc:
            self.logger.debug("COPY: fast copy not available (reason=%s)", exc)
            # something bad has happened
            # leave other responsabilities to other middleware
            return False

    def __call__(self, env, start_response):
        req = Request(env)
        try:
            req.split_path(4, 4, True)
        except ValueError:
            # If obj component is not present in req, do not proceed further.
            return self.app(env, start_response)

        # Check if fastcopy is possible
        # only plain object as source and destination
        # FIXME: handle COPY method (with Destination-* headers)
        if self.fast_copy_allowed(req):
            self.logger.debug("COPY: fast copy allowed")
            env['HTTP_OIO_COPY_FROM'] = unquote(env['HTTP_X_COPY_FROM'])
            del env['HTTP_X_COPY_FROM']
            return self.app(env, start_response)

        return super(OioServerSideCopyMiddleware, self).__call__(
            env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def copy_filter(app):
        return OioServerSideCopyMiddleware(app, conf)

    return copy_filter
