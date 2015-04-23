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

from swift.common.request_helpers import get_listing_content_type
from swift.common.middleware.acl import parse_acl, format_acl
from swift.common.utils import public
from swift.common.constraints import check_metadata
from swift.common import constraints
from swift.common.swob import HTTPBadRequest, HTTPMethodNotAllowed
from swift.common.request_helpers import get_sys_meta_prefix
from swift.common.swob import HTTPNoContent, HTTPOk

from oioswift.proxy.controllers.base import _set_info_cache
from oioswift.proxy.controllers.base import Controller, clear_info_cache


class AccountController(Controller):
    """WSGI controller for account requests"""
    server_type = 'Account'

    def __init__(self, app, account_name, **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        if not self.app.allow_account_management:
            self.allowed_methods.remove('PUT')
            self.allowed_methods.remove('DELETE')

    def add_acls_from_sys_metadata(self, resp):
        if resp.environ['REQUEST_METHOD'] in ('HEAD', 'GET', 'PUT', 'POST'):
            prefix = get_sys_meta_prefix('account') + 'core-'
            name = 'access-control'
            (extname, intname) = ('x-account-' + name, prefix + name)
            acl_dict = parse_acl(version=2, data=resp.headers.pop(intname))
            if acl_dict:  # treat empty dict as empty header
                resp.headers[extname] = format_acl(
                    version=2, acl_dict=acl_dict)

    @public
    def HEAD(self, req):
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                         constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp

        headers = {}
        headers['x-account-container-count'] = '1'
        headers['x-account-object-count'] = '0'
        headers['x-account-bytes-used'] = '0'
        headers['x-account-meta-temp-url-key'] = 'e'
        headers['x-account-sysmeta-core-access-control'] = '{' \
                                                           '"admin":[' \
                                                           '"test:tester"]}'

        resp = HTTPOk(request=req, headers=headers)
        _set_info_cache(self.app, req.environ, self.account_name, None, resp)

        return resp

    @public
    def GET(self, req):
        """Handler for HTTP GET/HEAD requests."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                         constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp

        if req.params.get("marker", "") != "":
            container_list = []
        else:
            container_list = [("test", 0, 0)]

        headers = {}
        headers['x-account-container-count'] = '1'
        headers['x-account-object-count'] = '0'
        headers['x-account-bytes-used'] = '0'
        headers['x-account-meta-temp-url-key'] = 'e'
        headers['x-account-sysmeta-core-access-control'] = '{' \
                                                           '"admin":[' \
                                                           '"test:tester"]}'

        resp = HTTPOk(request=req, headers=headers)
        _set_info_cache(self.app, req.environ, self.account_name, None, resp)

        if not len(container_list):
            return HTTPNoContent(request=req)

        req_format = get_listing_content_type(req)
        if req_format.endswith('/xml'):
            out = ['<?xml version="1.0" encoding="UTF-8"?>',
                   '<account name="%s">' % self.account_name]
            for (name, count, total_bytes) in container_list:
                out.append('<container>')
                out.append('<name>%s</name>' % name)
                out.append('<count>%s</count>' % count)
                out.append('<bytes>%s</bytes>' % total_bytes)
                out.append('</container>')
            out.append('</account>')
            result_list = "\n".join(out)
        elif req_format == 'application/json':
            out = []
            for (name, count, total_bytes) in container_list:
                out.append({"name": name, "count": count,
                            "bytes": total_bytes})
            result_list = json.dumps(out)
        else:
            output = ''
            for (name, count, total_bytes) in container_list:
                output += '\n%s\n' % name
            result_list = output

        resp.body = result_list

        if req.environ.get('swift_owner'):
            self.add_acls_from_sys_metadata(resp)
        else:
            for header in self.app.swift_owner_headers:
                resp.headers.pop(header, None)
        return resp

    @public
    def PUT(self, req):
        """HTTP PUT request handler."""
        if not self.app.allow_account_management:
            return HTTPMethodNotAllowed(
                request=req,
                headers={'Allow': ', '.join(self.allowed_methods)})
        error_response = check_metadata(req, 'account')
        if error_response:
            return error_response
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                         constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp
        account_partition, accounts = \
            self.app.account_ring.get_nodes(self.account_name)
        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.make_requests(
            req, self.app.account_ring, account_partition, 'PUT',
            req.swift_entity_path, [headers] * len(accounts))
        self.add_acls_from_sys_metadata(resp)
        return resp

    @public
    def POST(self, req):
        """HTTP POST request handler."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                         constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp
        error_response = check_metadata(req, 'account')
        if error_response:
            return error_response

        clear_info_cache(self.app, req.environ, self.account_name)
        resp = HTTPNoContent(request=req)
        self.add_acls_from_sys_metadata(resp)
        return resp

    @public
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        # Extra safety in case someone typos a query string for an
        # account-level DELETE request that was really meant to be caught by
        # some middleware.
        if req.query_string:
            return HTTPBadRequest(request=req)
        if not self.app.allow_account_management:
            return HTTPMethodNotAllowed(
                request=req,
                headers={'Allow': ', '.join(self.allowed_methods)})
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = HTTPNoContent(request=req)
        return resp
