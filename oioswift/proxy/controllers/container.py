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

from swift.common.utils import public, Timestamp
from swift.common.constraints import check_metadata
from swift.common import constraints
from swift.common.storage_policy import POLICIES
from swift.common.swob import Response, HTTPBadRequest, HTTPNotFound, \
    HTTPServerError, HTTPNoContent, HTTPConflict, HTTPCreated
from oiopy import exceptions

from oioswift.utils import get_listing_content_type
from oioswift.proxy.controllers.base import Controller, clear_info_cache, \
    delay_denial, cors_validation, _set_info_cache, get_container_info


def extract_sysmeta(raw):
    sysmeta = {}
    for el in raw.split(';'):
        k, v = el.split('=')
        sysmeta[k] = v
    return sysmeta


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
        info = get_container_info(req.environ, self.app)
        storage = self.app.storage

        marker = req.params.get("marker", None)
        limit = req.params.get("limit", None)
        end_marker = req.params.get("end_marker", None)
        prefix = req.params.get("prefix", None)
        delimiter = req.params.get("delimiter", None)

        try:
            object_list = storage. \
                list_container_objects(self.container_name, prefix=prefix,
                                       limit=limit, delimiter=delimiter,
                                       marker=marker, end_marker=end_marker)
        except exceptions.NoSuchContainer:
            return HTTPNotFound(request=req)
        except exceptions.OioException:
            return HTTPServerError(request=req)

        req_format = get_listing_content_type(req)

        if req_format.endswith('/xml'):
            out = ['<?xml version="1.0" encoding="UTF-8"?>',
                   '<container name="%s">' % self.container_name]
            for obj in object_list:
                out.append('<object>')
                out.append('<name>%s</name>' % obj.name)
                out.append('<bytes>%s</bytes>' % obj.size)
                out.append('<hash>%s</hash>' % obj.hash)
                sysmeta = extract_sysmeta(obj.system_metadata)
                out.append('<content_type>%s</content_type>' % sysmeta[
                    "mime-type"])
                last_modified = Timestamp(obj.ctime).isoformat
                out.append('<last_modified>%s</last_modified>' % last_modified)
                out.append('</object>')
            out.append('</container>')
            result_list = "\n".join(out)
        elif req_format == 'application/json':
            out = []
            for obj in object_list:
                last_modified = Timestamp(obj.ctime).isoformat
                sysmeta = extract_sysmeta(obj.system_metadata)
                out.append({"name": obj.name, "bytes": obj.size,
                            "content_type": sysmeta["mime-type"],
                            "last_modified": last_modified,
                            "hash": obj.hash})
            result_list = json.dumps(out)
        else:
            result_list = "\n".join(obj.name for obj in object_list) + '\n'

        headers = {'X-Container-Object-Count': '0',
                   'X-Container-Meta-Name': self.container_name
        }
        resp = Response(status=200, body=result_list, headers=headers)
        resp.content_type = req_format

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

    @public
    @delay_denial
    @cors_validation
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""
        storage = self.app.storage
        try:
            meta = storage.get_container_metadata(self.container_name)
            headers = {}
            headers['X-Container-Object-Count'] = '0'
            headers['X-Container-Bytes-Used'] = meta.get('sys.m2.usage', '0')
            headers['Content-Type'] = 'text/plain; charset=utf-8'
            for k, v in meta.iteritems():
                if k.startswith("user.meta."):
                    headers['X-Container-Meta-' + k[10:]] = v
            resp = HTTPNoContent(headers=headers)
        except exceptions.NoSuchContainer:
            resp = HTTPNotFound(request=req)
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

        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)

        storage = self.app.storage
        try:
            storage.create(self.container_name)
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

        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)

        storage = self.app.storage
        meta = {}
        for k, v in req.headers.iteritems():
            if k.startswith("X-Container-Meta-"):
                meta["user.meta." + k[17:]] = v

        try:
            storage.set_container_metadata(self.container_name, meta)
        except exceptions.NoSuchContainer:
            self.PUT(req)
        except exceptions.OioException:
            return HTTPServerError(request=req)
        return HTTPNoContent(request=req)

    @public
    @cors_validation
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)
        storage = self.app.storage
        try:
            storage.delete(self.container_name)
        except exceptions.ContainerNotEmpty:
            return HTTPConflict(request=req)
        except exceptions.NoSuchContainer:
            return HTTPNotFound(request=req)
        resp = HTTPNoContent(request=req)
        return resp
