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
import time
from xml.sax import saxutils

from swift.common.request_helpers import get_listing_content_type
from swift.common.middleware.acl import parse_acl, format_acl
from swift.common.utils import public, Timestamp, json
from swift.common.constraints import check_metadata
from swift.common import constraints
from swift.common.swob import HTTPBadRequest, HTTPMethodNotAllowed
from swift.common.request_helpers import get_sys_meta_prefix, get_param, \
    is_sys_or_user_meta
from swift.common.swob import HTTPNoContent, HTTPOk, HTTPPreconditionFailed, \
    HTTPNotFound, HTTPCreated, HTTPAccepted
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
            resp_headers[k] = v

    return resp_headers


def account_listing_response(account, req, response_content_type,
                             info=None, listing=None):
    if info is None:
        now = Timestamp(time.time()).internal
        info = {'containers': 0,
                'objects': 0,
                'bytes': 0,
                'metadata': {},
                'ctime': now}
    if listing is None:
        listing = []

    resp_headers = get_response_headers(info)

    if response_content_type == 'application/json':
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
                       (saxutils.escape(name), object_count, bytes_used)
                output_list.append(item)
        output_list.append('</account>')
        account_list = '\n'.join(output_list)
    else:
        if not listing:
            resp = HTTPNoContent(request=req, headers=resp_headers)
            resp.content_type = response_content_type
            resp.charset = 'utf-8'
            return resp
        account_list = '\n'.join(r[0] for r in listing) + '\n'
    ret = HTTPOk(body=account_list, request=req, headers=resp_headers)
    ret.content_type = response_content_type
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

    @public
    def GET(self, req):
        """Handler for HTTP GET requests."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                         constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp

        resp = self.get_account_listing_resp(req)

        _set_info_cache(self.app, req.environ, self.account_name, None, resp)

        if req.environ.get('swift_owner'):
            self.add_acls_from_sys_metadata(resp)
        else:
            for header in self.app.swift_owner_headers:
                resp.headers.pop(header, None)
        return resp

    def get_account_listing_resp(self, req):
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
            listing, info = self.app.storage.container_list(
                self.account_name, limit=limit, marker=marker,
                end_marker=end_marker, prefix=prefix,
                delimiter=delimiter)
            resp = account_listing_response(self.account_name, req,
                                            get_listing_content_type(req),
                                            info=info,
                                            listing=listing)
        except exceptions.NotFound:
            if self.app.account_autocreate:
                resp = account_listing_response(self.account_name, req,
                                                get_listing_content_type(req))
            else:
                resp = HTTPNotFound(request=req)

        return resp

    @public
    def HEAD(self, req):
        """HTTP HEAD request handler."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                         constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp

        resp = self.get_account_head_resp(req)

        _set_info_cache(self.app, req.environ, self.account_name, None, resp)

        if req.environ.get('swift_owner'):
            self.add_acls_from_sys_metadata(resp)
        else:
            for header in self.app.swift_owner_headers:
                resp.headers.pop(header, None)
        return resp

    def get_account_head_resp(self, req):
        try:
            info = self.app.storage.account_show(self.account_name)
            resp = account_listing_response(self.account_name, req,
                                            get_listing_content_type(req),
                                            info=info)
        except exceptions.NotFound:
            if self.app.account_autocreate:
                resp = account_listing_response(self.account_name, req,
                                                get_listing_content_type(req))
            else:
                resp = HTTPNotFound(request=req)

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

        resp = self.get_account_put_resp(req)
        clear_info_cache(self.app, req.environ, self.account_name)
        self.add_acls_from_sys_metadata(resp)
        return resp

    def get_account_put_resp(self, req):
        headers = self.generate_request_headers(req, transfer=True)
        created = self.app.storage.account_create(self.account_name,
                                                  headers=headers)
        metadata = {}
        metadata.update((k, v) for k, v in req.headers.iteritems()
                        if is_sys_or_user_meta('account', k))

        if metadata:
            self.app.storage.account_update(self.account_name, metadata)

        if created:
            resp = HTTPCreated(request=req)
        else:
            resp = HTTPAccepted(request=req)
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
        resp = self.get_account_post_resp(req)
        self.add_acls_from_sys_metadata(resp)
        return resp

    def get_account_post_resp(self, req):
        headers = self.generate_request_headers(req, transfer=True)

        metadata = {}
        metadata.update((k, v) for k, v in req.headers.iteritems()
                        if is_sys_or_user_meta('account', k))
        try:
            self.app.storage.account_update(self.account_name, metadata,
                                            headers=headers)
            return HTTPNoContent(request=req)
        except exceptions.NotFound:
            if self.app.account_autocreate:
                self.autocreate_account(req, self.account_name)
                if metadata:
                    self.app.storage.account_update(self.account_name,
                                                    metadata, headers=headers)
                resp = HTTPNoContent(request=req)
            else:
                resp = HTTPNotFound(request=req)
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
        headers = self.generate_request_headers(req)
        clear_info_cache(self.app, req.environ, self.account_name)
        # TODO delete account
        resp = HTTPNoContent(request=req)
        return resp
