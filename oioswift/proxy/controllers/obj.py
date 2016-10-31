# Copyright (c) 2010-2012 OpenStack Foundation
# Copyright (c) 2016 OpenIO SAS
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
from urllib import quote

from swift import gettext_ as _
from swift.common.utils import (
    clean_content_type, config_true_value, Timestamp, public)
from swift.common.constraints import check_metadata, check_object_creation, \
    check_copy_from_header, check_destination_header, \
    check_account_format
from swift.common import constraints
from swift.common.http import HTTP_CREATED, HTTP_MULTIPLE_CHOICES
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPRequestTimeout, \
    HTTPUnprocessableEntity, HTTPClientDisconnect, Request, HTTPCreated, \
    HTTPNoContent, Response, HTTPInternalServerError, multi_range_iterator
from swift.common.request_helpers import is_sys_or_user_meta, is_sys_meta, \
    is_user_meta, remove_items, copy_header_subset
from swift.proxy.controllers.base import _set_object_info_cache, \
        delay_denial, cors_validation
from swift.proxy.controllers.obj import check_content_type, copy_headers_into

from swift.proxy.controllers.obj import BaseObjectController as \
        BaseObjectController

from oioswift.common.storage_policy import POLICIES
from oio.common import exceptions
from oio.common.utils import quote as oio_quote
from oio.common.http import ranges_from_http_header
from oioswift.utils import IterO


class ObjectControllerRouter(object):
    def __getitem__(self, policy):
        return ObjectController


class StreamRangeIterator(object):
    def __init__(self, stream):
        self.stream = stream

    def app_iter_range(self, _start, _stop):
        # This will be called when there is only one range,
        # no need to check the number of bytes
        return self.stream

    def _chunked_app_iter_range(self, start, stop):
        # The stream generator give us one "chunk" per range,
        # and as we are called once for each range, we must
        # simulate end-of-stream by generating StopIteration
        for dat in self.stream:
            yield dat
            raise StopIteration

    def app_iter_ranges(self, ranges, content_type,
                        boundary, content_size,
                        *_args, **_kwargs):
        for chunk in multi_range_iterator(
                ranges, content_type, boundary, content_size,
                self._chunked_app_iter_range):
            yield chunk

    def __iter__(self):
        return self.stream


class ObjectController(BaseObjectController):
    allowed_headers = {'content-disposition', 'content-encoding',
                       'x-delete-at', 'x-object-manifest',
                       'x-static-large-object'}

    @public
    @cors_validation
    @delay_denial
    def HEAD(self, req):
        """Handle HEAD requests."""
        return self.GETorHEAD(req)

    @public
    @cors_validation
    @delay_denial
    def GET(self, req):
        """Handle GET requests."""
        return self.GETorHEAD(req)

    def GETorHEAD(self, req):
        """Handle HTTP GET or HEAD requests."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)

        req.acl = container_info['read_acl']

        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])
        policy = POLICIES.get_by_index(policy_index)
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        if req.method == 'HEAD':
            resp = self.get_object_head_resp(req)
        else:
            resp = self.get_object_fetch_resp(req)
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

    def get_object_fetch_resp(self, req):
        storage = self.app.storage
        if req.headers.get('Range'):
            ranges = ranges_from_http_header(req.headers.get('Range'))
        else:
            ranges = None
        try:
            metadata, stream = storage.object_fetch(self.account_name,
                                                    self.container_name,
                                                    self.object_name,
                                                    ranges=ranges)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return HTTPNotFound(request=req)
        resp = self.make_object_response(req, metadata, stream, ranges=ranges)
        return resp

    def make_object_response(self, req, metadata, stream=None, ranges=None):
        conditional_etag = None
        if 'X-Backend-Etag-Is-At' in req.headers:
            conditional_etag = metadata.get(
                req.headers['X-Backend-Etag-Is-At'])

        resp = Response(request=req, conditional_response=True,
                        conditional_etag=conditional_etag)

        resp.headers['Content-Type'] = metadata.get(
            'mime_type', 'application/octet-stream')
        properties = metadata.get('properties')
        if properties:
            for k, v in properties.iteritems():
                if is_sys_or_user_meta('object', k) or \
                        k.lower() in self.allowed_headers:
                            resp.headers[str(k)] = oio_quote(v)
        resp.headers['etag'] = metadata['hash'].lower()
        ts = Timestamp(metadata['ctime'])
        resp.last_modified = math.ceil(float(ts))
        if stream:
            if ranges:
                resp.app_iter = StreamRangeIterator(stream)
            else:
                resp.app_iter = stream

        resp.content_length = int(metadata['length'])
        try:
            resp.content_encoding = metadata['encoding']
        except KeyError:
            pass
        resp.accept_ranges = 'bytes'
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
            req.environ['swift.post_as_copy'] = True
            req.environ['swift_versioned_copy'] = True
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
            container_info = self.container_info(
                self.account_name, self.container_name, req)
            containers = container_info['nodes']
            req.acl = container_info['write_acl']
            if 'swift.authorize' in req.environ:
                aresp = req.environ['swift.authorize'](req)
                if aresp:
                    return aresp
            # if not containers:
            #     return HTTPNotFound(request=req)

            policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                           container_info['storage_policy'])
            stgpol = self._stgpol_from_policy_index(policy_index)
            headers = self._prepare_headers(req)
            return self._post_object(req, headers, stgpol)

    def _stgpol_from_policy_index(self, policy_index):
        # TODO actually convert policy_index to oio stgpol
        return 'SINGLE'

    def _post_object(self, req, headers, stgpol):
        # TODO do something with stgpol
        metadata = self.load_object_metadata(headers)

        storage = self.app.storage

        try:
            storage.object_update(
                self.account_name, self.container_name, self.object_name,
                metadata, clear=True)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return HTTPNotFound(request=req)
        resp = HTTPAccepted(request=req)
        return resp

    @public
    @cors_validation
    @delay_denial
    def PUT(self, req):
        """HTTP PUT request handler."""
        if req.if_none_match is not None and '*' not in req.if_none_match:
            # Sending an etag with if-none-match isn't currently supported
            return HTTPBadRequest(request=req, content_type='text/plain',
                                  body='If-None-Match only supports *')

        container_info = self.container_info(
            self.account_name, self.container_name, req)
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])

        containers = container_info['nodes']

        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']

        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        # if not containers:
        #     return HTTPNotFound(request=req)

        self._update_content_type(req)

        error_response = check_object_creation(req, self.object_name) or \
            check_content_type(req)
        if error_response:
            return error_response

        self._update_x_timestamp(req)

        source_header = req.headers.get('X-Copy-From')
        if source_header:
            error_response, req, data_source, update_response = \
                self._handle_copy_request(req)
            if error_response:
                return error_response
        else:
            data_source = req.environ['wsgi.input']
            update_response = lambda req, resp: resp

        headers = self._prepare_headers(req)
        resp = self._store_object(req, data_source, headers)
        return update_response(req, resp)

    def _prepare_headers(self, req):
        req.headers['X-Timestamp'] = Timestamp(time.time()).internal
        headers = self.generate_request_headers(req, additional=req.headers)
        return headers

    def _store_object(self, req, data_source, headers):
        # TODO deal with stgpol
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index')
        policy = POLICIES.get_by_index(policy_index)
        if (req.content_length > 0) or req.is_chunked:
            expect = True
        else:
            expect = False

        content_type = req.headers.get('content-type', 'octet/stream')
        storage = self.app.storage

        metadata = self.load_object_metadata(headers)
        # TODO actually support if-none-match
        try:
            chunks, size, checksum = storage.object_create(
                self.account_name, self.container_name,
                obj_name=self.object_name, file_or_path=data_source,
                mime_type=content_type,
                etag=req.headers.get('etag', '').strip('"'), metadata=metadata)
        except exceptions.PreconditionFailed:
            raise HTTPPreconditionFailed(request=req)
        except exceptions.ClientReadTimeout as err:
            self.app.logger.warning(
                _('ERROR Client read timeout (%ss)'), err.seconds)
            self.app.logger.increment('client_timeouts')
            raise HTTPRequestTimeout(request=req)
        except exceptions.SourceReadError:
            req.client_disconnect = True
            self.app.logger.warning(
                _('Client disconnected without sending last chunk'))
            self.app.logger.increment('client_disconnects')
            raise HTTPClientDisconnect(request=req)
        except exceptions.EtagMismatch:
            return HTTPUnprocessableEntity(request=req)
        except exceptions.OioTimeout:
            self.app.logger.exception(
                _('ERROR Exception causing client disconnect'))
            raise HTTPClientDisconnect(request=req)
        except Exception:
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)

        resp = HTTPCreated(request=req, etag=checksum)
        return resp

    def _handle_copy_request(self, req):
        # TODO rely on oio copy instead?
        if req.environ.get('swift.orig_req_method', req.method) != 'POST':
            req.environ.setdefault('swift.log_info', []).append(
                'x-copy-from:%s' % req.headers['X-Copy-From'])
        ver, acct, _rest = req.split_path(2, 3, True)
        src_account_name = req.headers.get('X-Copy-From-Account', None)
        if src_account_name:
            src_account_name = check_account_format(req, src_account_name)
        else:
            src_account_name = acct
        src_container_name, src_obj_name = check_copy_from_header(req)
        source_header = '/%s/%s/%s/%s' % (
            ver, src_account_name, src_container_name, src_obj_name)
        source_req = req.copy_get()

        # make sure the source request uses it's container_info
        source_req.headers.pop('X-Backend-Storage-Policy-Index', None)
        source_req.path_info = source_header
        source_req.headers['X-Newest'] = 'true'
        if 'swift.post_as_copy' in req.environ:
            # We're COPYing one object over itself because of a POST; rely on
            # the PUT for write authorization, don't require read authorization
            source_req.environ['swift.authorize'] = lambda req: None
            source_req.environ['swift.authorize_override'] = True

        orig_obj_name = self.object_name
        orig_container_name = self.container_name
        orig_account_name = self.account_name
        sink_req = Request.blank(req.path_info,
                                 environ=req.environ, headers=req.headers)

        self.object_name = src_obj_name
        self.container_name = src_container_name
        self.account_name = src_account_name

        source_resp = self.GET(source_req)

        # This gives middlewares a way to change the source; for example,
        # this lets you COPY a SLO manifest and have the new object be the
        # concatenation of the segments (like what a GET request gives
        # the client), not a copy of the manifest file.
        hook = req.environ.get(
            'swift.copy_hook',
            (lambda source_req, source_resp, sink_req: source_resp))
        source_resp = hook(source_req, source_resp, sink_req)

        # reset names
        self.object_name = orig_obj_name
        self.container_name = orig_container_name
        self.account_name = orig_account_name

        if source_resp.status_int >= HTTP_MULTIPLE_CHOICES:
            # this is a bit of ugly code, but I'm willing to live with it
            # until copy request handling moves to middleware
            return source_resp, None, None, None
        if source_resp.content_length is None:
            # This indicates a transfer-encoding: chunked source object,
            # which currently only happens because there are more than
            # CONTAINER_LISTING_LIMIT segments in a segmented object. In
            # this case, we're going to refuse to do the server-side copy.
            raise HTTPRequestEntityTooLarge(request=req)
        if source_resp.content_length > constraints.MAX_FILE_SIZE:
            raise HTTPRequestEntityTooLarge(request=req)

        data_source = IterO(source_resp.app_iter)
        sink_req.content_length = source_resp.content_length
        sink_req.etag = source_resp.etag

        # we no longer need the X-Copy-From header
        del sink_req.headers['X-Copy-From']
        if 'X-Copy-From-Account' in sink_req.headers:
            del sink_req.headers['X-Copy-From-Account']
        if not req.content_type_manually_set:
            sink_req.headers['Content-Type'] = \
                source_resp.headers['Content-Type']

        fresh_meta_flag = config_true_value(
            sink_req.headers.get('x-fresh-metadata', 'false'))

        if fresh_meta_flag or 'swift.post_as_copy' in sink_req.environ:
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
                (req.params.get('multipart-manifest') == 'get' or
                 'swift.post_as_copy' in req.environ):
            sink_req.headers['X-Static-Large-Object'] = \
                source_resp.headers['X-Static-Large-Object']

        req = sink_req

        def update_response(req, resp):
            acct, path = source_resp.environ['PATH_INFO'].split('/', 3)[2:4]
            resp.headers['X-Copied-From-Account'] = quote(acct)
            resp.headers['X-Copied-From'] = quote(path)
            if 'last-modified' in source_resp.headers:
                resp.headers['X-Copied-From-Last-Modified'] = \
                    source_resp.headers['last-modified']
            copy_headers_into(req, resp)
            return resp

        # this is a bit of ugly code, but I'm willing to live with it
        # until copy request handling moves to middleware
        return None, req, data_source, update_response

    def _update_content_type(self, req):
        # Sometimes the 'content-type' header exists, but is set to None.
        req.content_type_manually_set = True
        detect_content_type = \
            config_true_value(req.headers.get('x-detect-content-type'))
        if detect_content_type or not req.headers.get('content-type'):
            guessed_type, _junk = mimetypes.guess_type(req.path_info)
            req.headers['Content-Type'] = guessed_type or \
                'application/octet-stream'
            if detect_content_type:
                req.headers.pop('x-detect-content-type')
            else:
                req.content_type_manually_set = False

    def _update_x_timestamp(self, req):
        if 'x-timestamp' in req.headers:
            try:
                req_timestamp = Timestamp(req.headers['X-Timestamp'])
            except ValueError:
                raise HTTPBadRequest(
                    request=req, content_type='text/plain',
                    body='X-Timestamp should be a UNIX timestamp float value; '
                         'was %r' % req.headers['x-timestamp'])
            req.headers['X-Timestamp'] = req_timestamp.internal
        else:
            req.headers['X-Timestamp'] = Timestamp(time.time()).internal
        return None

    @public
    @cors_validation
    @delay_denial
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        containers = container_info['nodes']
        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        # if not containers:
        #     return HTTPNotFound(request=req)

        self._update_x_timestamp(req)

        return self._delete_object(req)

    def _delete_object(self, req):
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
