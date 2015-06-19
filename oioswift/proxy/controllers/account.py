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

from swift.common.request_helpers import get_listing_content_type
from swift.common.middleware.acl import parse_acl, format_acl
from swift.common.utils import public, Timestamp, json
from swift.common.constraints import check_metadata
from swift.common import constraints
from swift.common.swob import HTTPBadRequest, HTTPMethodNotAllowed
from swift.common.request_helpers import get_sys_meta_prefix
from swift.common.swob import HTTPNoContent, HTTPOk, HTTPNotFound

from oiopy import exceptions
from oioswift.proxy.controllers.base import _set_info_cache
from oioswift.proxy.controllers.base import Controller, clear_info_cache


def get_response_headers(info):
    resp_headers = {
        'X-Account-Container-Count': info['containers'],
        'X-Account-Object-Count': info['objects'],
        'X-Account-Bytes-Used': info['bytes'],
        'X-Timestamp': Timestamp(info['ctime']).normal,
    }

    for k, v in info['metadata'].iteritems():
        if v != '':
            resp_headers.update('X-Account-Meta-%s' % k, v)

def account_listing_response(account, req, response_content_type,
        info=None, listing=None):

    if info is None:
        now = Timestamp(time.time()).internal
        info = {'containers': 0,
                'objects': 0,
                'bytes': 0,
                'ctime': now}
    if listing is None:
        listing = []

    resp_headers = get_response_headers(info)

    if response_content_type  == 'application/json':
        data = []
        for (name, object_count, bytes_used, is_subdir) in listing:
            if is_subdir:
                data.append({'subdir': name})
            else:
                data.append({'name': name, 'count': object_count,
                    'bytes': bytes_used})
        account_list = json.dumps(data)
    elif response_content_type.endswith('/xml'):
        output_list = ['<?xml version="1.0" encoding="UTF-8"?>',
                '<account name=%s>' % saxutils.quoteattr(account)]
        for (name, object_count, bytes_used, is_subdir) in listing:
            if is_subdir:
                output_list.append(
                    '<subdir name=%s />' % saxutils.quoteattr(name))
            else:
                item = '<container><name>%s</name><count>%s</count>' \
                        '<bytes>%s</bytes></container>' % \
                output_list.append(item)
        output_list.append('</account>')
        account_list = '\n'.join(output_list)
    else:
        if not account_list:
            resp = HTTPNoContent(request=req, headers=resp_headers)
            resp.content_type = 'utf-8'
            return resp
        account_list = '\n'.join(r[0] for r in account_list) + '\n'
    ret = HTTPOk(body=account_list, request=req, headers=resp_headers)
    ret.charset = 'utf-8'
    return ret

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

    def GETorHEAD(self, req):
        """Handler for HTTP GET/HEAD requests."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                        constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp

        not_found = False

        if req.method == 'GET':
            prefix = get_param(req, 'prefix')
            delimiter = get_param(req, 'prefix')
            if delimiter and (len(delimiter) > 1 or ord(delimiter) > 254):
                return HTTPPreconditionFailed(body='Bad delimiter')
            limit = constraints.ACCOUNT_LISTING_LIMIT
            given_limit = get_param(req, 'limit')
            if given_limit and given_limit.isdigit():
                limit = int(given_limit)
                if limit > constraints.ACCOUNT_LISTING_LIMIT:
                    return HTTPPreconditionFailed(
                        request=req,
                        body='Maximum limit is %d' %
                        constraints.ACCOUNT_LISTING_LIMIT)
            marker = get_param(req, 'marker')
            end_marker = get_param(req, 'end_marker')

            try:
                listing, info  = self.app.storage.list_containers(self.account,
                        limit=limit, marker=marker, end_marker=end_marker,
                        prefix=prefix, delimiter=delimiter)
                resp = account_listing_response(self.account_name, req,
                        get_listing_content_type(req), info=info,
                        listing=listing)

            except exceptions.NotFound:
                not_found = True
        else:
            try:
                info = self.app.storage.get_account(self.account)
            except exceptions.NotFound:
                not_found = True

        if not_found:
            if self.app.account_autocreate:
                resp = account_listing_response(self.account_name, req,
                        get_listing_content_type(req))

        _set_info_cache(self.app, req.environ, self.account_name, None, resp)

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
