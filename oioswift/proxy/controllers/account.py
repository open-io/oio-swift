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

import time
from xml.sax import saxutils

try:
    from swift.common.middleware.listing_formats import \
        get_listing_content_type
except ImportError:
    # Before Queens
    from swift.common.request_helpers import get_listing_content_type

from swift.common.utils import public, Timestamp, json
from swift.common.constraints import check_metadata
from swift.common import constraints
from swift.common.swob import HTTPBadRequest, HTTPMethodNotAllowed
from swift.common.request_helpers import get_param, is_sys_or_user_meta
from swift.common.swob import HTTPNoContent, HTTPOk, HTTPPreconditionFailed, \
    HTTPNotFound, HTTPCreated, HTTPAccepted
from swift.proxy.controllers.account import AccountController \
        as SwiftAccountController
from swift.proxy.controllers.base import set_info_cache, clear_info_cache

from oio.common import exceptions

from oioswift.utils import handle_oio_timeout, handle_service_busy, \
    REQID_HEADER
from oioswift.common.middleware.container_hierarchy \
        import ContainerHierarchyMiddleware as CH


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
                             info=None, listing=None, s3_buckets_only=False):
    now = time.time()
    if info is None:
        info = {'containers': 0,
                'objects': 0,
                'bytes': 0,
                'metadata': {},
                'ctime': Timestamp(now).internal}
    if listing is None:
        listing = []
    elif listing and len(listing[0]) < 5:
        # oio-sds < 4.2 does not return mtime
        listing = [x + [now] for x in listing]

    resp_headers = get_response_headers(info)

    if response_content_type == 'application/json':
        data = []
        for (name, object_count, bytes_used, is_subdir, mtime) in listing:
            if is_subdir:
                if not s3_buckets_only:
                    data.append({'subdir': name})
            else:
                data.append({'name': name, 'count': object_count,
                             'bytes': bytes_used,
                             'last_modified': Timestamp(mtime).isoformat})
        account_list = json.dumps(data)
    elif response_content_type.endswith('/xml'):
        output_list = ['<?xml version="1.0" encoding="UTF-8"?>',
                       '<account name=%s>' % saxutils.quoteattr(account)]
        for (name, object_count, bytes_used, is_subdir, mtime) in listing:
            if is_subdir:
                if not s3_buckets_only:
                    output_list.append(
                        '<subdir name=%s />' % saxutils.quoteattr(name))
            else:
                item = '<container><name>%s</name><count>%s</count>' \
                       '<bytes>%s</bytes><last_modified>%s</last_modified>' \
                       '</container>' % \
                       (saxutils.escape(name), object_count, bytes_used,
                        Timestamp(mtime).isoformat)
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


def handle_account_not_found_autocreate(fnc):
    """
    Catch NoSuchAccount and NotFound errors.
    If account_autocreate is enabled, return a dummy listing.
    Otherwise, return a proper '404 Not Found' response.
    """
    def _account_not_found_wrapper(self, req, *args, **kwargs):
        try:
            resp = fnc(self, req, *args, **kwargs)
        except (exceptions.NotFound, exceptions.NoSuchAccount):
            if self.app.account_autocreate:
                resp = account_listing_response(self.account_name, req,
                                                get_listing_content_type(req))
            else:
                resp = HTTPNotFound(request=req)
        return resp
    return _account_not_found_wrapper


class AccountController(SwiftAccountController):
    @public
    @handle_account_not_found_autocreate
    @handle_oio_timeout
    @handle_service_busy
    def GET(self, req):
        """Handler for HTTP GET requests."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                         constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp

        resp = self.get_account_listing_resp(req)
        set_info_cache(self.app, req.environ, self.account_name, None, resp)

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
        s3_buckets_only = False
        if req.environ.get('swift.source') == 'S3':
            s3_buckets_only = True
            delimiter = CH.ENCODED_DELIMITER[0]

        oio_headers = {REQID_HEADER: self.trans_id}
        info = None
        if hasattr(self.app.storage, 'account'):
            # Call directly AccountClient.container_list()
            # because storage.container_list() does not return
            # account metadata
            info = self.app.storage.account.container_list(
                self.account_name, limit=limit, marker=marker,
                end_marker=end_marker, prefix=prefix,
                delimiter=delimiter, headers=oio_headers,
                s3_buckets_only=s3_buckets_only)
            listing = info.pop('listing')
        else:
            # Legacy call to account service
            listing, info = self.app.storage.container_list(
                self.account_name, limit=limit, marker=marker,
                end_marker=end_marker, prefix=prefix,
                delimiter=delimiter, headers=oio_headers)
        return account_listing_response(
            self.account_name, req, get_listing_content_type(req),
            info=info, listing=listing, s3_buckets_only=s3_buckets_only)

    @public
    @handle_account_not_found_autocreate
    @handle_oio_timeout
    @handle_service_busy
    def HEAD(self, req):
        """HTTP HEAD request handler."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name),
                         constraints.MAX_ACCOUNT_NAME_LENGTH)
            return resp

        resp = self.get_account_head_resp(req)

        set_info_cache(self.app, req.environ, self.account_name, None, resp)

        if req.environ.get('swift_owner'):
            self.add_acls_from_sys_metadata(resp)
        else:
            for header in self.app.swift_owner_headers:
                resp.headers.pop(header, None)
        return resp

    def get_account_head_resp(self, req):
        oio_headers = {REQID_HEADER: self.trans_id}
        info = self.app.storage.account_show(
            self.account_name, headers=oio_headers)
        return account_listing_response(self.account_name, req,
                                        get_listing_content_type(req),
                                        info=info)

    @public
    @handle_oio_timeout
    @handle_service_busy
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

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.get_account_put_resp(req, headers)
        self.add_acls_from_sys_metadata(resp)
        return resp

    def get_account_put_resp(self, req, headers):
        oio_headers = {REQID_HEADER: self.trans_id}
        created = self.app.storage.account_create(
            self.account_name, headers=oio_headers)
        metadata = {}
        metadata.update((key, value)
                        for key, value in req.headers.items()
                        if is_sys_or_user_meta('account', key))

        if metadata:
            self.app.storage.account_set_properties(
                self.account_name, metadata, headers=oio_headers)

        if created:
            resp = HTTPCreated(request=req)
        else:
            resp = HTTPAccepted(request=req)
        return resp

    @public
    @handle_oio_timeout
    @handle_service_busy
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

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.get_account_post_resp(req, headers)
        self.add_acls_from_sys_metadata(resp)
        return resp

    def get_account_post_resp(self, req, headers):
        metadata = {}
        metadata.update((key, value)
                        for key, value in req.headers.items()
                        if is_sys_or_user_meta('account', key))
        headers[REQID_HEADER] = self.trans_id
        try:
            self.app.storage.account_set_properties(
                account=self.account_name, properties=metadata,
                headers=headers)
            return HTTPNoContent(request=req)
        except (exceptions.NotFound, exceptions.NoSuchAccount):
            if self.app.account_autocreate:
                self.autocreate_account(req, self.account_name)
                if metadata:
                    self.app.storage.account_set_properties(
                        self.account_name, metadata, headers=headers)
                resp = HTTPNoContent(request=req)
            else:
                resp = HTTPNotFound(request=req)
        self.add_acls_from_sys_metadata(resp)
        return resp

    @public
    @handle_oio_timeout
    @handle_service_busy
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        if req.query_string:
            return HTTPBadRequest(request=req)
        if not self.app.allow_account_management:
            return HTTPMethodNotAllowed(
                request=req,
                headers={'Allow': ', '.join(self.allowed_methods)})
        headers = self.generate_request_headers(req)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.get_account_delete_resp(req, headers)
        return resp

    def get_account_delete_resp(self, req, headers):
        # TODO perform delete
        return HTTPNoContent(request=req)
