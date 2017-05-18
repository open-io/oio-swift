# Copyright (c) 2014 OpenStack Foundation
# Copyright (c) 2017 OpenIO SAS
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

from six.moves.urllib.parse import parse_qs, quote, unquote, urlencode
from swift.common.middleware import versioned_writes as vw
from swift.common.swob import Request, HTTPException
from swift.common.utils import config_true_value, json, \
    register_swift_info, split_path
from swift.proxy.controllers.base import get_container_info, get_object_info


VERSIONING_SUFFIX = '+versioning'


def swift3_versioned_object_name(object_name, version_id=None):
    if version_id is not None:
        version_id = '/%s' % version_id
    return '%03x%s%s' % (len(object_name), object_name, version_id)


def swift3_split_object_name_version(object_name):
    if '/' not in object_name or \
            len(object_name) < 3 or \
            not object_name[:3].isdigit():
        return object_name, None
    return object_name[3:].rsplit('/', 1)


def get_unversioned_container(container):
    if container.endswith(VERSIONING_SUFFIX):
        return container[:-len(VERSIONING_SUFFIX)]
    return container


class OioVersionedWritesContext(vw.VersionedWritesContext):

    def handle_container_listing(self, env, start_response):
        # This code may be clearer by using Request(env).get_response()
        # instead of self._app_call(env)
        api_vers, account, container_name = split_path(
            env['PATH_INFO'], 3, 3, True)
        sub_env = env.copy()
        orig_container = get_unversioned_container(container_name)
        if orig_container != container_name:
            # Check that container_name is actually the versioning
            # container for orig_container
            sub_env['PATH_INFO'] = '/%s/%s/%s' % (api_vers, account,
                                                  orig_container)
            info = get_container_info(sub_env, self.app,
                                      swift_source='VW')
            if info.get('sysmeta', {}).get('versions-location') != \
                    container_name:
                # We were wrong, do a standard listing
                orig_container = container_name

        if orig_container != container_name:
            qs = parse_qs(sub_env.get('QUERY_STRING', ''))
            if 'marker' in qs:
                marker, _ = swift3_split_object_name_version(qs['marker'][0])
                qs['marker'] = [marker]
            sub_env['QUERY_STRING'] = urlencode(qs, True)
            sub_env['oio_query'] = {'versions': True}

        resp = super(OioVersionedWritesContext, self).handle_container_request(
            sub_env, lambda x, y, z: None)

        if orig_container != container_name and \
                self._response_status == '200 OK':
            versioned_objects = json.loads("".join(resp))
            for obj in versioned_objects:
                obj['name'] = swift3_versioned_object_name(
                    obj['name'], obj.get('version', ''))
            # XXX: we may need to filter the most recent version
            resp = json.dumps(versioned_objects)
            self._response_headers = [x for x in self._response_headers
                                      if x[0] != 'Content-Length']
            self._response_headers.append(('Content-Length', str(len(resp))))

        start_response(self._response_status, self._response_headers,
                       self._response_exc_info)
        return resp

    def handle_container_request(self, env, start_response):
        method = env.get('REQUEST_METHOD')
        if method in ('HEAD', 'GET'):
            return self.handle_container_listing(env, start_response)
        return super(OioVersionedWritesContext, self).handle_container_request(
            env, start_response)


vw.VersionedWritesContext = OioVersionedWritesContext


class OioVersionedWritesMiddleware(vw.VersionedWritesMiddleware):

    def object_request(self, req, api_version, account, container, obj,
                       allow_versioned_writes):
        container_name = unquote(container)
        object_name = unquote(obj)
        orig_container = get_unversioned_container(container_name)
        if orig_container != container_name:
            orig_object, version = \
                swift3_split_object_name_version(object_name)
            req.environ['oio_query'] = {'version': version}
            req.environ['PATH_INFO'] = '/%s/%s/%s/%s' % (api_version,
                                                         account,
                                                         quote(orig_container),
                                                         quote(orig_object))
        elif req.method == 'DELETE':
            ver_mode = req.headers.get('X-Backend-Versioning-Mode-Override',
                                       'history')
            if ver_mode == 'stack':
                # Do not create a delete marker, delete the latest version
                obj_inf = get_object_info(req.environ, self.app,
                                          swift_source='VW')
                req.environ['oio_query'] = {
                    'version': obj_inf.get('sysmeta', {}).get('version-id')
                }
        return req.get_response(self.app)

    def __call__(self, env, start_response):
        req = Request(env)
        try:
            (api_version, account, container, obj) = req.split_path(3, 4, True)
        except ValueError:
            return self.app(env, start_response)

        # In case allow_versioned_writes is set in the filter configuration,
        # the middleware becomes the authority on whether object
        # versioning is enabled or not. In case it is not set, then
        # the option in the container configuration is still checked
        # for backwards compatibility

        # For a container request, first just check if option is set,
        # can be either true or false.
        # If set, check if enabled when actually trying to set container
        # header. If not set, let request be handled by container server
        # for backwards compatibility.
        # For an object request, also check if option is set (either T or F).
        # If set, check if enabled when checking versions container in
        # sysmeta property. If it is not set check 'versions' property in
        # container_info
        allow_versioned_writes = self.conf.get('allow_versioned_writes')
        if allow_versioned_writes and container and not obj:
            try:
                return self.container_request(req, start_response,
                                              allow_versioned_writes)
            except HTTPException as error_response:
                return error_response(env, start_response)
        elif (obj and (req.method in ('PUT', 'DELETE') and
                       not req.environ.get('swift.post_as_copy') or
                       req.method in ('HEAD', 'GET'))):
            try:
                return self.object_request(
                    req, api_version, account, container, obj,
                    allow_versioned_writes)(env, start_response)
            except HTTPException as error_response:
                return error_response(env, start_response)
        else:
            return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    if config_true_value(conf.get('allow_versioned_writes')):
        register_swift_info('versioned_writes', allowed_flags=(
            vw.CLIENT_VERSIONS_LOC, vw.CLIENT_HISTORY_LOC))

    def obj_versions_filter(app):
        return OioVersionedWritesMiddleware(app, conf)

    return obj_versions_filter
