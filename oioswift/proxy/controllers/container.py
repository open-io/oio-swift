# Copyright (c) 2010-2012 OpenStack Foundation
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

from urllib import unquote
import json
from xml.etree.cElementTree import Element, SubElement, tostring

from swift.common.utils import public, Timestamp, \
    override_bytes_from_content_type
from swift.common.constraints import check_metadata
from swift.common import constraints
from swift.common.storage_policy import POLICIES
from swift.common.swob import Response, HTTPBadRequest, HTTPNotFound, \
    HTTPServerError, HTTPNoContent, HTTPConflict, HTTPCreated, \
    HTTPPreconditionFailed
from swift.common.request_helpers import is_sys_or_user_meta, get_param
from oiopy import exceptions

from oioswift.utils import get_listing_content_type
from oioswift.proxy.controllers.base import Controller, clear_info_cache, \
    delay_denial, cors_validation, _set_info_cache


def extract_sysmeta(raw):
    sysmeta = {}
    for el in raw.split(';'):
        k, v = el.split('=', 1)
        sysmeta[k] = v
    return sysmeta


def gen_resp_headers(info):
    headers = {}
    headers.update({
        'X-Container-Object-Count': info.get('object_count', 0),
        'X-Container-Bytes-Used': info.get('bytes_used', 0),
        'X-Timestamp': Timestamp(info.get('created_at', 0)).normal,
        'X-PUT-Timestamp': Timestamp(
            info.get('put_timestamp', 0)).normal,
    })
    return headers


class ContainerController(Controller):
    """WSGI controller for container requests"""
    server_type = 'Container'

    # Ensure these are all lowercase
    pass_through_headers = ['x-container-read', 'x-container-write',
                            'x-container-sync-key', 'x-container-sync-to',
                            'x-versions-location']

    def __init__(self, app, account_name, container_name, **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)

    def _x_remove_headers(self):
        st = self.server_type.lower()
        return ['x-remove-%s-read' % st,
                'x-remove-%s-write' % st,
                'x-remove-versions-location']

    def _convert_policy_to_index(self, req):
        """
        Helper method to convert a policy name (from a request from a client)
        to a policy index (for a request to a backend).

        :param req: incoming request
        """
        policy_name = req.headers.get('X-Storage-Policy')
        if not policy_name:
            return
        policy = POLICIES.get_by_name(policy_name)
        if not policy:
            raise HTTPBadRequest(request=req,
                                 content_type="text/plain",
                                 body=("Invalid %s '%s'"
                                       % ('X-Storage-Policy', policy_name)))
        if policy.is_deprecated:
            body = 'Storage Policy %r is deprecated' % (policy.name)
            raise HTTPBadRequest(request=req, body=body)
        return int(policy)

    def clean_acls(self, req):
        if 'swift.clean_acl' in req.environ:
            for header in ('x-container-read', 'x-container-write'):
                if header in req.headers:
                    try:
                        req.headers[header] = \
                            req.environ['swift.clean_acl'](header,
                                                           req.headers[header])
                    except ValueError as err:
                        return HTTPBadRequest(request=req, body=str(err))
        return None

    @public
    @delay_denial
    @cors_validation
    def GET(self, req):
        """Handler for HTTP GET requests."""
        if not self.account_info(self.account_name, req):
            if 'swift.authorize' in req.environ:
                aresp = req.environ['swift.authorize'](req)
                if aresp:
                    return aresp
            return HTTPNotFound(request=req)

        resp = self.get_container_list_resp(req)
        _set_info_cache(self.app, req.environ, self.account_name,
                        self.container_name, resp)
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

    def get_container_list_resp(self, req):
        storage = self.app.storage

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

        if path is not None:
            prefix = path
            if path:
                prefix = path.rstrip('/') + '/'
            delimiter = '/'

        out_content_type = get_listing_content_type(req)

        try:
            metadata, result_list = storage. \
                object_list(self.account_name, self.container_name,
                            prefix=prefix, limit=limit, delimiter=delimiter,
                            marker=marker, end_marker=end_marker,
                            include_metadata=True)
            # TODO get container info
            info = {}
            resp_headers = gen_resp_headers(info)
            info.update(metadata)
            resp = self.create_listing(
                req, out_content_type, resp_headers, info, result_list,
                self.container_name)
        except exceptions.NoSuchContainer:
            return HTTPNotFound(request=req)
        return resp

    def create_listing(self, req, out_content_type, resp_headers,
                       metadata, result_list, container):
        container_list = result_list['objects']
        for p in result_list.get('prefixes', []):
            record = {'name': p,
                      'subdir': True}
            container_list.append(record)
        for (k, v) in metadata.iteritems():
            if v and (k.lower() in self.pass_through_headers or
                          is_sys_or_user_meta('container', k)):
                resp_headers[k] = v
        ret = Response(request=req, headers=resp_headers,
                       content_type=out_content_type, charset='utf-8')
        if out_content_type == 'application/json':
            ret.body = json.dumps([self.update_data_record(record)
                                   for record in container_list])
        elif out_content_type.endswith('/xml'):
            doc = Element('container', name=container.decode('utf-8'))
            for obj in container_list:
                record = self.update_data_record(obj)
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

    def update_data_record(self, record):
        if 'subdir' in record:
            return {'subdir': record['name']}

        sysmeta = extract_sysmeta(record.get('system_metadata', None))
        response = {'name': record['name'],
                    'bytes': record['size'],
                    'hash': record['hash'].lower(),
                    'last_modified': Timestamp(record['ctime']).isoformat,
                    'content_type': sysmeta.get('mime-type',
                                                'application/octet-stream')}
        override_bytes_from_content_type(response)
        return response

    @public
    @delay_denial
    @cors_validation
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""
        if not self.account_info(self.account_name, req):
            if 'swift.authorize' in req.environ:
                aresp = req.environ['swift.authorize'](req)
                if aresp:
                    return aresp
            return HTTPNotFound(request=req)

        resp = self.get_container_head_resp(req)
        _set_info_cache(self.app, req.environ, self.account_name,
                        self.container_name, resp)
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

    def get_container_head_resp(self, req):
        storage = self.app.storage
        try:
            meta = storage.container_show(self.account_name,
                                          self.container_name)
            headers = {}
            # TODO object count
            headers['X-Container-Object-Count'] = '0'
            headers['X-Container-Bytes-Used'] = meta.get('sys.m2.usage', '0')
            headers['Content-Type'] = 'text/plain; charset=utf-8'
            for k, v in meta.iteritems():
                if k.startswith("user."):
                    headers[k[5:]] = v
            resp = HTTPNoContent(headers=headers)
        except exceptions.NoSuchContainer:
            resp = HTTPNotFound(request=req)

        return resp

    def load_container_metadata(self, headers, prefix='user.'):
        metadata = {}
        metadata.update(
            ("%s%s" % (prefix, k.lower()), v)
            for k, v in headers.iteritems()
            if k.lower() in self.pass_through_headers or
            is_sys_or_user_meta('container', k))
        return metadata

    @public
    @cors_validation
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
        container_count = self.account_info(self.account_name, req)

        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)

        storage = self.app.storage

        headers = self.generate_request_headers(req, transfer=True)
        metadata = self.load_container_metadata(headers, '')

        try:
            storage.container_create(
                self.account_name, self.container_name, metadata=metadata)
        except exceptions.OioException:
            return HTTPServerError(request=req)
        resp = HTTPCreated(request=req)
        return resp

    @public
    @cors_validation
    def POST(self, req):
        """HTTP POST request handler."""
        error_response = \
            self.clean_acls(req) or check_metadata(req, 'container')
        if error_response:
            return error_response
        if not req.environ.get('swift_owner'):
            for key in self.app.swift_owner_headers:
                req.headers.pop(key, None)

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)

        storage = self.app.storage

        metadata = self.load_container_metadata(headers)

        try:
            storage.container_set_properties(
                self.account_name, self.container_name, metadata)
            resp = HTTPNoContent(request=req)
        except exceptions.NoSuchContainer:
            resp = self.PUT(req)
        return resp

    @public
    @cors_validation
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)
        storage = self.app.storage
        try:
            storage.container_delete(self.account_name, self.container_name)
        except exceptions.ContainerNotEmpty:
            return HTTPConflict(request=req)
        except exceptions.NoSuchContainer:
            return HTTPNotFound(request=req)
        resp = HTTPNoContent(request=req)
        return resp
