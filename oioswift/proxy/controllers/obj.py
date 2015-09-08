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

import mimetypes
import time
import math
from urllib import unquote, quote

from swift.common.utils import (
    clean_content_type, config_true_value, Timestamp,
    normalize_delete_at_timestamp, public, get_expirer_container)
from swift.common.constraints import check_metadata, check_object_creation, \
    check_copy_from_header, check_destination_header, \
    check_account_format
from swift.common import constraints
from swift.common.http import HTTP_CREATED, HTTP_MULTIPLE_CHOICES
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPRequestTimeout, \
    Request, HTTPCreated, HTTPNoContent, Response
from swift.common.request_helpers import is_sys_or_user_meta, is_sys_meta, \
    is_user_meta, remove_items, copy_header_subset
from oiopy import exceptions

from oioswift.proxy.controllers.base import _set_info_cache, \
    _set_object_info_cache, Controller, delay_denial, cors_validation
from oioswift.utils import IterO


def copy_headers_into(from_r, to_r):
    """
    Will copy desired headers from from_r to to_r
    :params from_r: a swob Request or Response
    :params to_r: a swob Request or Response
    """
    pass_headers = ['x-delete-at']
    for k, v in from_r.headers.items():
        if is_sys_or_user_meta('object', k) or k.lower() in pass_headers:
            to_r.headers[k] = v


def check_content_type(req):
    if not req.environ.get('swift.content_type_overridden') and \
                    ';' in req.headers.get('content-type', ''):
        for param in req.headers['content-type'].split(';')[1:]:
            if param.lstrip().startswith('swift_'):
                return HTTPBadRequest("Invalid Content-Type, "
                                      "swift_* is not a valid parameter name.")
    return None


class ObjectController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Object'

    allowed_headers = {'content-disposition', 'content-encoding',
                       'x-delete-at', 'x-object-manifest',
                       'x-static-large-object'}

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)


    @public
    @cors_validation
    @delay_denial
    def HEAD(self, req):
        """Handle HTTP GET or HEAD requests."""
        container_info = self.container_info(self.account_name,
                                             self.container_name, req)
        req.acl = container_info['read_acl']

        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        resp = self.get_object_head_resp(req)
        _set_info_cache(self.app, req.environ, self.account_name,
                        self.container_name, resp)
        _set_object_info_cache(self.app, req.environ, self.account_name,
                               self.container_name, self.object_name, resp)
        if ';' in resp.headers.get('content-type', ''):
            resp.content_type = clean_content_type(
                resp.headers['content-type'])

        return resp

    def get_object_head_resp(self, req):
        storage = self.app.storage
        try:
            metadata = storage.object_show(self.account_name,
                                           self.container_name,
                                           self.object_name)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return HTTPNotFound(request=req)

        resp = self.make_object_response(req, metadata)
        return resp


    @public
    @cors_validation
    @delay_denial
    def GET(self, req):
        """Handler for HTTP GET requests."""
        container_info = self.container_info(self.account_name,
                                             self.container_name, req)
        req.acl = container_info['read_acl']

        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        resp = self.get_object_fetch_resp(req)

        _set_info_cache(self.app, req.environ, self.account_name,
                        self.container_name, resp)
        _set_object_info_cache(self.app, req.environ, self.account_name,
                               self.container_name, self.object_name, resp)
        if ';' in resp.headers.get('content-type', ''):
            resp.content_type = clean_content_type(
                resp.headers['content-type'])

        return resp

    def get_object_fetch_resp(self, req):
        storage = self.app.storage
        try:
            metadata, stream = storage.object_fetch(self.account_name,
                                                    self.container_name,
                                                    self.object_name)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return HTTPNotFound(request=req)
        resp = self.make_object_response(req, metadata, stream)
        return resp

    def make_object_response(self, req, metadata, stream=None):
        conditional_etag = None
        if 'X-Backend-Etag-Is-At' in req.headers:
            conditional_etag = metadata.get(
                req.headers['X-Backend-Etag-Is-At'])

        resp = Response(request=req, conditional_response=True,
                        conditional_etag=conditional_etag)

        resp.headers['Content-Type'] = metadata.get(
            'mime-type', 'application/octet-stream')
        properties = metadata.get('properties')
        if properties:
            for k, v in properties.iteritems():
                if is_sys_or_user_meta('object', k) or \
                        k.lower() in self.allowed_headers:
                            resp.headers[k] = v
        resp.etag = metadata['hash'].lower()
        ts = Timestamp(metadata['ctime'])
        resp.last_modified = math.ceil(float(ts))
        if stream:
            resp.app_iter = stream
        resp.content_length = int(metadata['length'])
        try:
            resp.content_encoding = metadata['encoding']
        except KeyError:
            pass
        return resp

    def load_object_metadata(self, headers):
        metadata = {}
        metadata.update(
            (k.lower(), v) for k, v in headers.iteritems()
            if is_user_meta('object', k))
        for header_key in self.allowed_headers:
            if header_key in headers:
                headers_lower = header_key.lower()
                metadata[headers_lower] = headers[header_key]
        print metadata
        return metadata

    @public
    @cors_validation
    @delay_denial
    def POST(self, req):
        """HTTP POST request handler."""
        if self.app.object_post_as_copy:
            req.method = 'PUT'
            req.path_info = '/v1/%s/%s/%s' % (
                self.account_name, self.container_name, self.object_name)
            req.headers['Content-Length'] = 0
            req.headers['X-Copy-From'] = quote('/%s/%s' % (self.container_name,
                                                           self.object_name))
            req.headers['X-Fresh-Metadata'] = 'true'
            req.environ['swift_versioned_copy'] = True
            if req.environ.get('QUERY_STRING'):
                req.environ['QUERY_STRING'] += '&multipart-manifest=get'
            else:
                req.environ['QUERY_STRING'] = 'multipart-manifest=get'
            resp = self.PUT(req)
            # Older editions returned 202 Accepted on object POSTs, so we'll
            # convert any 201 Created responses to that for compatibility with
            # picky clients.
            if resp.status_int != HTTP_CREATED:
                return resp
            return HTTPAccepted(request=req)
        else:
            error_response = check_metadata(req, 'object')
            if error_response:
                return error_response
            container_info = self.container_info(self.account_name,
                                                 self.container_name, req)
            req.acl = container_info['write_acl']
            if 'swift.authorize' in req.environ:
                aresp = req.environ['swift.authorize'](req)
                if aresp:
                    return aresp

            storage = self.app.storage

            headers = self.generate_request_headers(req, transfer=True)
            metadata = self.load_object_metadata(headers)

            try:
                storage.object_update(self.account_name,
                                      self.container_name, self.object_name,
                                      metadata, clear=True)
            except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
                return HTTPNotFound(request=req)
            resp = HTTPAccepted(request=req)
            return resp

    def _config_obj_expiration(self, req):
        delete_at_container = None
        delete_at_part = None
        delete_at_nodes = None

        req = constraints.check_delete_headers(req)

        if 'x-delete-at' in req.headers:
            x_delete_at = int(normalize_delete_at_timestamp(
                int(req.headers['x-delete-at'])))

            req.environ.setdefault('swift.log_info', []).append(
                'x-delete-at:%s' % x_delete_at)

            delete_at_container = get_expirer_container(
                x_delete_at, self.app.expiring_objects_container_divisor,
                self.account_name, self.container_name, self.object_name)

            delete_at_part, delete_at_nodes = \
                self.app.container_ring.get_nodes(
                    self.app.expiring_objects_account, delete_at_container)

        return req, delete_at_container, delete_at_part, delete_at_nodes

    @public
    @cors_validation
    @delay_denial
    def PUT(self, req):
        """HTTP PUT request handler."""
        if req.if_none_match is not None and '*' not in req.if_none_match:
            # Sending an etag with if-none-match isn't currently supported
            return HTTPBadRequest(request=req, content_type='text/plain',
                                  body='If-None-Match only supports *')
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        # Sometimes the 'content-type' header exists, but is set to None.
        content_type_manually_set = True
        detect_content_type = \
            config_true_value(req.headers.get('x-detect-content-type'))
        if detect_content_type or not req.headers.get('content-type'):
            guessed_type, _junk = mimetypes.guess_type(req.path_info)
            req.headers['Content-Type'] = guessed_type or \
                                          'application/octet-stream'
            if detect_content_type:
                req.headers.pop('x-detect-content-type')
            else:
                content_type_manually_set = False

        error_response = check_object_creation(req, self.object_name) or \
                         check_content_type(req)
        if error_response:
            return error_response

        req.headers['X-Timestamp'] = Timestamp(time.time()).internal

        stream = req.environ['wsgi.input']
        source_header = req.headers.get('X-Copy-From')
        source_resp = None
        if source_header:
            if req.environ.get('swift.orig_req_method', req.method) != 'POST':
                req.environ.setdefault('swift.log_info', []).append(
                    'x-copy-from:%s' % source_header)
            ver, acct, _rest = req.split_path(2, 3, True)
            src_account_name = req.headers.get('X-Copy-From-Account', None)
            if src_account_name:
                src_account_name = check_account_format(req, src_account_name)
            else:
                src_account_name = acct
            src_container_name, src_obj_name = check_copy_from_header(req)
            source_header = '/%s/%s/%s/%s' % (ver, src_account_name,
                                              src_container_name, src_obj_name)
            source_req = req.copy_get()

            # make sure the source request uses it's container_info
            source_req.headers.pop('X-Backend-Storage-Policy-Index', None)
            source_req.path_info = source_header
            source_req.headers['X-Newest'] = 'true'
            orig_obj_name = self.object_name
            orig_container_name = self.container_name
            orig_account_name = self.account_name
            self.object_name = src_obj_name
            self.container_name = src_container_name
            self.account_name = src_account_name
            sink_req = Request.blank(req.path_info,
                                     environ=req.environ, headers=req.headers)
            source_resp = self.GET(source_req)

            # This gives middlewares a way to change the source; for example,
            # this lets you COPY a SLO manifest and have the new object be the
            # concatenation of the segments (like what a GET request gives
            # the client), not a copy of the manifest file.
            hook = req.environ.get(
                'swift.copy_hook',
                (lambda source_req, source_resp, sink_req: source_resp))
            source_resp = hook(source_req, source_resp, sink_req)

            if source_resp.status_int >= HTTP_MULTIPLE_CHOICES:
                return source_resp
            self.object_name = orig_obj_name
            self.container_name = orig_container_name
            self.account_name = orig_account_name
            stream = IterO(source_resp.app_iter)
            sink_req.content_length = source_resp.content_length
            if sink_req.content_length is None:
                # This indicates a transfer-encoding: chunked source object,
                # which currently only happens because there are more than
                # CONTAINER_LISTING_LIMIT segments in a segmented object. In
                # this case, we're going to refuse to do the server-side copy.
                return HTTPRequestEntityTooLarge(request=req)
            if sink_req.content_length > constraints.MAX_FILE_SIZE:
                return HTTPRequestEntityTooLarge(request=req)
            sink_req.etag = source_resp.etag

            # we no longer need the X-Copy-From header
            del sink_req.headers['X-Copy-From']
            if 'X-Copy-From-Account' in sink_req.headers:
                del sink_req.headers['X-Copy-From-Account']
            if not content_type_manually_set:
                sink_req.headers['Content-Type'] = \
                    source_resp.headers['Content-Type']
            if config_true_value(
                    sink_req.headers.get('x-fresh-metadata', 'false')):
                # post-as-copy: ignore new sysmeta, copy existing sysmeta
                condition = lambda k: is_sys_meta('object', k)
                remove_items(sink_req.headers, condition)
                copy_header_subset(source_resp, sink_req, condition)
            else:
                # copy/update existing sysmeta and user meta
                copy_headers_into(source_resp, sink_req)
                copy_headers_into(req, sink_req)

            # copy over x-static-large-object for POSTs and manifest copies
            if 'X-Static-Large-Object' in source_resp.headers and \
                            req.params.get('multipart-manifest') == 'get':
                sink_req.headers['X-Static-Large-Object'] = \
                    source_resp.headers['X-Static-Large-Object']

            req = sink_req

        content_length = req.content_length
        content_type = req.headers.get('content-type', 'octet/stream')
        storage = self.app.storage

        if content_length is None:
            content_length = 0

        headers = self.generate_request_headers(req, transfer=True)
        metadata = self.load_object_metadata(headers)
        try:
            chunks, size, checksum = storage.object_create(
                self.account_name, self.container_name,
                obj_name=self.object_name, file_or_path=stream,
                content_length=content_length, content_type=content_type,
                metadata=metadata)
        except exceptions.NoSuchContainer:
            return HTTPNotFound(request=req)
        except exceptions.ClientReadTimeout:
            return HTTPRequestTimeout(request=req)
        resp = HTTPCreated(request=req, etag=checksum)
        if source_header:
            acct, path = source_header.split('/', 3)[2:4]
            resp.headers['X-Copied-From-Account'] = quote(acct)
            resp.headers['X-Copied-From'] = quote(path)
            if 'last-modified' in source_resp.headers:
                resp.headers['X-Copied-From-Last-Modified'] = \
                    source_resp.headers['last-modified']
            copy_headers_into(req, resp)
        resp.last_modified = math.ceil(
            float(Timestamp(req.headers['X-Timestamp'])))
        return resp

    @public
    @cors_validation
    @delay_denial
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        if 'x-timestamp' in req.headers:
            try:
                req_timestamp = Timestamp(req.headers['X-Timestamp'])
            except ValueError:
                return HTTPBadRequest(
                    request=req, content_type='text/plain',
                    body='X-Timestamp should be a UNIX timestamp float value; '
                         'was %r' % req.headers['x-timestamp'])
            req.headers['X-Timestamp'] = req_timestamp.internal
        else:
            req.headers['X-Timestamp'] = Timestamp(time.time()).internal

        storage = self.app.storage

        try:
            storage.object_delete(self.account_name, self.container_name,
                                  self.object_name)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return HTTPNotFound(request=req)
        resp = HTTPNoContent(request=req)
        return resp

    @public
    @cors_validation
    @delay_denial
    def COPY(self, req):
        """HTTP COPY request handler."""
        if not req.headers.get('Destination'):
            return HTTPPreconditionFailed(request=req,
                                          body='Destination header required')
        dest_account = self.account_name
        if 'Destination-Account' in req.headers:
            dest_account = req.headers.get('Destination-Account')
            dest_account = check_account_format(req, dest_account)
            req.headers['X-Copy-From-Account'] = self.account_name
            self.account_name = dest_account
            del req.headers['Destination-Account']
        dest_container, dest_object = check_destination_header(req)
        source = '/%s/%s' % (self.container_name, self.object_name)
        self.container_name = dest_container
        self.object_name = dest_object
        # re-write the existing request as a PUT instead of creating a new one
        # since this one is already attached to the posthooklogger
        req.method = 'PUT'
        req.path_info = '/v1/%s/%s/%s' % \
                        (dest_account, dest_container, dest_object)
        req.headers['Content-Length'] = 0
        req.headers['X-Copy-From'] = quote(source)
        del req.headers['Destination']
        return self.PUT(req)
