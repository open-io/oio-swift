# Copyright (c) 2010-2012 OpenStack Foundation
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

import json
from xml.etree.cElementTree import Element, SubElement, tostring

from swift.common.utils import public, Timestamp, \
    override_bytes_from_content_type
from swift.common.constraints import check_metadata
from swift.common import constraints
try:
    from swift.common.middleware.listing_formats import \
        get_listing_content_type
except ImportError:
    # Before Queens
    from swift.common.request_helpers import get_listing_content_type

from swift.common.middleware.versioned_writes import DELETE_MARKER_CONTENT_TYPE
from swift.common.swob import Response, HTTPBadRequest, HTTPNotFound, \
    HTTPNoContent, HTTPConflict, HTTPPreconditionFailed, HTTPForbidden, \
    HTTPCreated
from swift.common.http import is_success, HTTP_ACCEPTED
from swift.common.request_helpers import is_sys_or_user_meta, get_param
from swift.proxy.controllers.container import ContainerController \
        as SwiftContainerController
from swift.proxy.controllers.base import clear_info_cache, \
    delay_denial, cors_validation, set_info_cache

from oio.common import exceptions

from oioswift.utils import \
    handle_oio_no_such_container, handle_oio_timeout, \
    handle_service_busy, REQID_HEADER


class ContainerController(SwiftContainerController):

    pass_through_headers = ['x-container-read', 'x-container-write',
                            'x-container-sync-key', 'x-container-sync-to',
                            'x-versions-location']

    @handle_oio_no_such_container
    @handle_oio_timeout
    @handle_service_busy
    def GETorHEAD(self, req):
        """Handler for HTTP GET/HEAD requests."""
        if self.account_info(self.account_name, req) is None:
            if 'swift.authorize' in req.environ:
                aresp = req.environ['swift.authorize'](req)
                if aresp:
                    return aresp
            return HTTPNotFound(request=req)

        if req.method == 'GET':
            resp = self.get_container_list_resp(req)
        else:
            resp = self.get_container_head_resp(req)
        set_info_cache(self.app, req.environ, self.account_name,
                       self.container_name, resp)
        resp = self.convert_policy(resp)
        if 'swift.authorize' in req.environ:
            req.acl = resp.headers.get('x-container-read')
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        if not req.environ.get('swift_owner', False):
            for key in self.app.swift_owner_headers:
                if key in resp.headers:
                    del resp.headers[key]
        return resp

    def convert_policy(self, resp):
        if 'X-Backend-Storage-Policy-Index' in resp.headers and \
                is_success(resp.status_int):
            policy = self.app.POLICIES.get_by_index(
                resp.headers['X-Backend-Storage-Policy-Index'])
            if policy:
                resp.headers['X-Storage-Policy'] = policy.name
            else:
                self.app.logger.error(
                    'Could not translate %s (%r) from %r to policy',
                    'X-Backend-Storage-Policy-Index',
                    resp.headers['X-Backend-Storage-Policy-Index'])
        return resp

    def get_metadata_resp_headers(self, meta):
        headers = {}
        system = meta.get('system') or {}
        # sys.m2.ctime is microseconds
        ctime = float(system.get('sys.m2.ctime', 0)) / 1000000.0
        headers.update({
            'X-Container-Object-Count': system.get('sys.m2.objects', 0),
            'X-Container-Bytes-Used': system.get('sys.m2.usage', 0),
            'X-Timestamp': Timestamp(ctime).normal,
            # FIXME: save modification time somewhere
            'X-PUT-Timestamp': Timestamp(ctime).normal,
        })
        for (k, v) in meta['properties'].iteritems():
            if v and (k.lower() in self.pass_through_headers or
                      is_sys_or_user_meta('container', k)):
                headers[k] = v
        return headers

    def get_container_list_resp(self, req):
        path = get_param(req, 'path')
        prefix = get_param(req, 'prefix')
        delimiter = get_param(req, 'delimiter')
        if delimiter and (len(delimiter) > 1 or ord(delimiter) > 254):
            # delimiters can be made more flexible later
            return HTTPPreconditionFailed(body='Bad delimiter')
        marker = get_param(req, 'marker', '')
        end_marker = get_param(req, 'end_marker')
        limit = constraints.CONTAINER_LISTING_LIMIT
        given_limit = get_param(req, 'limit')
        if given_limit and given_limit.isdigit():
            limit = int(given_limit)
            if limit > constraints.CONTAINER_LISTING_LIMIT:
                return HTTPPreconditionFailed(
                    request=req,
                    body='Maximum limit is %d'
                         % constraints.CONTAINER_LISTING_LIMIT)

        out_content_type = get_listing_content_type(req)
        if path is not None:
            prefix = path
            if path:
                prefix = path.rstrip('/') + '/'
            delimiter = '/'
        opts = req.environ.get('oio.query', {})
        oio_headers = {REQID_HEADER: self.trans_id}
        result = self.app.storage.object_list(
            self.account_name, self.container_name, prefix=prefix,
            limit=limit, delimiter=delimiter, marker=marker,
            end_marker=end_marker, properties=True,
            versions=opts.get('versions', False),
            deleted=opts.get('deleted', False),
            force_master=opts.get('force_master', False),
            headers=oio_headers)

        resp_headers = self.get_metadata_resp_headers(result)
        resp = self.create_listing(
            req, out_content_type, resp_headers, result,
            self.container_name, **opts)
        return resp

    def create_listing(self, req, out_content_type, resp_headers,
                       result, container, **kwargs):
        container_list = result['objects']
        for p in result.get('prefixes', []):
            record = {'name': p,
                      'subdir': True}
            container_list.append(record)
        container_list.sort(key=lambda x: x['name'])
        ret = Response(request=req, headers=resp_headers,
                       content_type=out_content_type, charset='utf-8')
        versions = kwargs.get('versions', False)
        slo = kwargs.get('slo', False)
        if out_content_type == 'application/json':
            ret.body = json.dumps(
                [self.update_data_record(r, versions, slo)
                 for r in container_list])
        elif out_content_type.endswith('/xml'):
            doc = Element('container', name=container.decode('utf-8'))
            for obj in container_list:
                record = self.update_data_record(obj, versions, slo)
                if 'subdir' in record:
                    name = record['subdir'].decode('utf-8')
                    sub = SubElement(doc, 'subdir', name=name)
                    SubElement(sub, 'name').text = name
                else:
                    obj_element = SubElement(doc, 'object')
                    for field in ["name", "hash", "bytes", "content_type",
                                  "last_modified"]:
                        SubElement(obj_element, field).text = str(
                            record.pop(field)).decode('utf-8')
                    for field in sorted(record):
                        SubElement(obj_element, field).text = str(
                            record[field]).decode('utf-8')
            ret.body = tostring(doc, encoding='UTF-8').replace(
                "<?xml version='1.0' encoding='UTF-8'?>",
                '<?xml version="1.0" encoding="UTF-8"?>', 1)
        else:
            if not container_list:
                return HTTPNoContent(request=req, headers=resp_headers)
            ret.body = '\n'.join(rec['name'] for rec in container_list) + '\n'

        return ret

    def update_data_record(self, record, versions=False, slo=False):
        if 'subdir' in record:
            return {'subdir': record['name']}

        props = record.get('properties', {})
        # This metadata is added by encryption middleware.
        if 'x-object-sysmeta-container-update-override-etag' in props:
            hash_ = props['x-object-sysmeta-container-update-override-etag']
        else:
            hash_ = record.get('hash')
            if hash_ is not None:
                hash_ = hash_.lower()

        response = {'name': record['name'],
                    'bytes': record['size'],
                    'last_modified': Timestamp(record['mtime']).isoformat,
                    'content_type': record.get(
                        'mime_type', 'application/octet-stream')}
        if hash_:
            response['hash'] = hash_
        if record.get('deleted', False):
            response['content_type'] = DELETE_MARKER_CONTENT_TYPE
        if versions:
            response['version'] = record.get('version', 'null')
        if slo:
            response['slo'] = props.get("x-static-large-object")
        override_bytes_from_content_type(response)
        return response

    @public
    @delay_denial
    @cors_validation
    def GET(self, req):
        """Handler for HTTP GET requests."""
        return self.GETorHEAD(req)

    @public
    @delay_denial
    @cors_validation
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""
        return self.GETorHEAD(req)

    def get_container_head_resp(self, req):
        headers = dict()
        out_content_type = get_listing_content_type(req)
        headers['Content-Type'] = out_content_type
        oio_headers = {REQID_HEADER: self.trans_id}
        meta = self.app.storage.container_get_properties(
            self.account_name, self.container_name, headers=oio_headers)
        headers.update(self.get_metadata_resp_headers(meta))
        return HTTPNoContent(request=req, headers=headers, charset='utf-8')

    def properties_from_headers(self, headers):
        metadata = {
            k: v
            for k, v in headers.items()
            if k.lower() in self.pass_through_headers or
            is_sys_or_user_meta('container', k)
        }

        system = dict()
        # This header enables versioning
        ver_loc = headers.get('X-Container-Sysmeta-Versions-Location')
        if ver_loc is not None:
            # When suspending versioning, header has empty string value
            ver_val = "-1" if ver_loc else "1"
            system['sys.m2.policy.version'] = ver_val

        return metadata, system

    def _convert_policy(self, req):
        policy_name = req.headers.get('X-Storage-Policy')
        if not policy_name:
            return
        policy = self.app.POLICIES.get_by_name(policy_name)
        if not policy:
            msg = "Invalid X-Storage-Policy '%s'" % policy_name
            raise HTTPBadRequest(
                request=req, content_type='text/plain', body=msg)
        return policy

    def get_container_create_resp(self, req, headers):
        properties, system = self.properties_from_headers(headers)
        # TODO container update metadata
        oio_headers = {REQID_HEADER: self.trans_id}
        created = self.app.storage.container_create(
            self.account_name, self.container_name,
            properties=properties, system=system,
            headers=oio_headers)
        if created:
            return HTTPCreated(request=req)
        else:
            return HTTPNoContent(request=req)

    @public
    @cors_validation
    @handle_oio_timeout
    @handle_service_busy
    def PUT(self, req):
        """HTTP PUT request handler."""
        error_response = \
            self.clean_acls(req) or check_metadata(req, 'container')
        if error_response:
            return error_response
        if not req.environ.get('swift_owner'):
            for key in self.app.swift_owner_headers:
                req.headers.pop(key, None)
        if len(self.container_name) > constraints.MAX_CONTAINER_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Container name length of %d longer than %d' % \
                        (len(self.container_name),
                         constraints.MAX_CONTAINER_NAME_LENGTH)
            return resp
        account_partition, accounts, container_count = \
            self.account_info(self.account_name, req)

        if not accounts and self.app.account_autocreate:
            self.autocreate_account(req, self.account_name)
            account_partition, accounts, container_count = \
                self.account_info(self.account_name, req)
        if not accounts:
            return HTTPNotFound(request=req)
        if self.app.max_containers_per_account > 0 and \
                container_count >= self.app.max_containers_per_account and \
                self.account_name not in self.app.max_containers_whitelist:
            container_info = \
                self.container_info(self.account_name, self.container_name,
                                    req)
            if not is_success(container_info.get('status')):
                resp = HTTPForbidden(request=req)
                resp.body = 'Reached container limit of %s' % \
                    self.app.max_containers_per_account
                return resp

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name,
                         self.container_name)
        resp = self.get_container_create_resp(req, headers)
        return resp

    @public
    @cors_validation
    @handle_oio_timeout
    @handle_service_busy
    def POST(self, req):
        """HTTP POST request handler."""
        error_response = \
            self.clean_acls(req) or check_metadata(req, 'container')
        if error_response:
            return error_response
        if not req.environ.get('swift_owner'):
            for key in self.app.swift_owner_headers:
                req.headers.pop(key, None)
        account_partition, accounts, container_count = \
            self.account_info(self.account_name, req)
        if not accounts:
            return HTTPNotFound(request=req)

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)

        memcache = getattr(self.app, 'memcache', None) or \
            req.environ.get('swift.cache')
        if memcache is not None:
            key = "/".join(("versioning", self.account_name,
                            self.container_name))
            memcache.delete(key)

        resp = self.get_container_post_resp(req, headers)
        return resp

    def get_container_post_resp(self, req, headers):
        properties, system = self.properties_from_headers(headers)
        if not properties:
            return self.PUT(req)

        oio_headers = {REQID_HEADER: self.trans_id}
        try:
            self.app.storage.container_set_properties(
                self.account_name, self.container_name,
                properties=properties, system=system,
                headers=oio_headers)
            resp = HTTPNoContent(request=req)
        except exceptions.NoSuchContainer:
            resp = self.PUT(req)
        return resp

    def get_container_delete_resp(self, req):
        oio_headers = {REQID_HEADER: self.trans_id}
        try:
            self.app.storage.container_delete(
                self.account_name, self.container_name, headers=oio_headers)
        except exceptions.ContainerNotEmpty:
            return HTTPConflict(request=req)
        resp = HTTPNoContent(request=req)
        return resp

    @public
    @cors_validation
    @handle_oio_no_such_container
    @handle_oio_timeout
    @handle_service_busy
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        account_partition, accounts, container_count = \
            self.account_info(self.account_name, req)
        if not accounts:
            return HTTPNotFound(request=req)
        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)
        resp = self.get_container_delete_resp(req)
        if resp.status_int == HTTP_ACCEPTED:
            return HTTPNotFound(request=req)
        return resp
