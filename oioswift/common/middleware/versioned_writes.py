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

from six.moves.urllib.parse import parse_qs, urlencode
from swift.common.middleware import versioned_writes as vw
from swift.common.utils import config_true_value, json, \
    register_swift_info, split_path
from swift.proxy.controllers.base import get_container_info


VERSIONING_SUFFIX = '+versioning'


def swift3_versioned_object_name(object_name, version_id=''):
    if version_id:
        version_id = '/%s' % version_id
    return '%03x%s%s' % (len(object_name), object_name, version_id)


def swift3_split_object_name_version(object_name):
    if '/' not in object_name or \
            len(object_name) < 3 or \
            not object_name[:3].isdigit():
        return object_name, None
    return object_name[3:].rsplit('/', 1)


class OioVersionedWritesContext(vw.VersionedWritesContext):

    def get_listed_container(self, container):
        if container.endswith(VERSIONING_SUFFIX):
            return container[:-len(VERSIONING_SUFFIX)]
        return container

    def handle_container_listing(self, env, start_response):
        # This code may be clearer by using Request(env).get_response()
        # instead of self._app_call(env)
        api_vers, account, container_name = split_path(
            env['PATH_INFO'], 3, 3, True)
        sub_env = env.copy()
        listed_container = self.get_listed_container(container_name)
        if listed_container != container_name:
            # Check that container_name is actually the versioning
            # container for listed_container
            sub_env['PATH_INFO'] = '/%s/%s/%s' % (api_vers, account,
                                                  listed_container)
            info = get_container_info(sub_env, self.app,
                                      swift_source='versioned_writes')
            if info.get('sysmeta', {}).get('versions-location') != \
                    container_name:
                # We were wrong, do a standard listing
                listed_container = container_name

        if listed_container != container_name:
            qs = parse_qs(sub_env.get('QUERY_STRING', ''))
            if 'marker' in qs:
                marker, _ = swift3_split_object_name_version(qs['marker'][0])
                qs['marker'] = [marker]
            sub_env['QUERY_STRING'] = urlencode(qs, True)

        resp = super(OioVersionedWritesContext, self).handle_container_request(
            sub_env, lambda x, y, z: None)

        if listed_container != container_name and \
                self._response_status == '200 OK':
            versioned_objects = json.loads("".join(resp))
            for obj in versioned_objects:
                obj['name'] = swift3_versioned_object_name(obj['name'],
                                                           obj['version'])
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
    pass


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    if config_true_value(conf.get('allow_versioned_writes')):
        register_swift_info('versioned_writes', allowed_flags=(
            vw.CLIENT_VERSIONS_LOC, vw.CLIENT_HISTORY_LOC))

    def obj_versions_filter(app):
        return OioVersionedWritesMiddleware(app, conf)

    return obj_versions_filter
