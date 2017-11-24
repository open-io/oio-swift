# Copyright (c) 2010-2012 OpenStack Foundation
# Copyright (c) 2016-2017 OpenIO SAS
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

from swift import gettext_ as _
from swift.common.utils import (
    clean_content_type, config_true_value, Timestamp, public)
from swift.common.constraints import check_metadata, check_object_creation
from swift.common.middleware.versioned_writes import DELETE_MARKER_CONTENT_TYPE
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestTimeout, \
    HTTPUnprocessableEntity, HTTPClientDisconnect, HTTPCreated, \
    HTTPNoContent, Response, HTTPInternalServerError, multi_range_iterator
from swift.common.request_helpers import is_sys_or_user_meta
from swift.proxy.controllers.base import set_object_info_cache, \
        delay_denial, cors_validation
from swift.proxy.controllers.obj import check_content_type

from swift.proxy.controllers.obj import BaseObjectController as \
        BaseObjectController

from oio.common import exceptions
from oio.common.http import ranges_from_http_header
from oio.common.green import SourceReadTimeout
from oio.common.exceptions import SourceReadError

from oioswift.utils import handle_service_busy, ServiceBusy


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


class ExpectedSizeReader(object):
    """Only accept as a valid EOF an exact number of bytes received."""

    def __init__(self, source, expected):
        self.source = source
        self.expected = expected
        self.consumed = 0

    def read(self, *args, **kwargs):
        rc = self.source.read(*args, **kwargs)
        if len(rc) == 0:
            if self.consumed != self.expected:
                raise SourceReadError("Truncated input")
        else:
            self.consumed = self.consumed + len(rc)
        return rc

    def readline(self, *args, **kwargs):
        rc = self.source.readline(*args, **kwargs)
        if len(rc) == 0:
            if self.consumed != self.expected:
                raise SourceReadError("Truncated input")
        else:
            self.consumed = self.consumed + len(rc)
        return rc


class ObjectController(BaseObjectController):
    allowed_headers = {'content-disposition', 'content-encoding',
                       'x-delete-at', 'x-object-manifest',
                       'x-static-large-object'}

    @public
    @cors_validation
    @delay_denial
    @handle_service_busy
    def HEAD(self, req):
        """Handle HEAD requests."""
        return self.GETorHEAD(req)

    @public
    @cors_validation
    @delay_denial
    @handle_service_busy
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
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        if req.method == 'HEAD':
            resp = self.get_object_head_resp(req)
        else:
            resp = self.get_object_fetch_resp(req)
        set_object_info_cache(self.app, req.environ, self.account_name,
                              self.container_name, self.object_name, resp)
        if ';' in resp.headers.get('content-type', ''):
            resp.content_type = clean_content_type(
                resp.headers['content-type'])

        return resp

    def get_object_head_resp(self, req):
        storage = self.app.storage
        oio_headers = {'X-oio-req-id': self.trans_id}
        try:
            metadata = storage.object_show(
                self.account_name, self.container_name, self.object_name,
                version=req.environ.get('oio_query', {}).get('version'),
                headers=oio_headers)
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
        oio_headers = {'X-oio-req-id': self.trans_id}
        try:
            metadata, stream = storage.object_fetch(
                self.account_name, self.container_name, self.object_name,
                ranges=ranges, headers=oio_headers,
                version=req.environ.get('oio_query', {}).get('version'))
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

        if config_true_value(metadata['deleted']):
            resp.headers['Content-Type'] = DELETE_MARKER_CONTENT_TYPE
        else:
            resp.headers['Content-Type'] = metadata.get(
                'mime_type', 'application/octet-stream')
        properties = metadata.get('properties')
        if properties:
            for k, v in properties.iteritems():
                if is_sys_or_user_meta('object', k) or \
                        k.lower() in self.allowed_headers:
                    resp.headers[str(k)] = v
        resp.headers['etag'] = metadata['hash'].lower()
        resp.headers['x-object-sysmeta-version-id'] = metadata['version']
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
            if is_sys_or_user_meta('object', k))
        for header_key in self.allowed_headers:
            if header_key in headers:
                headers_lower = header_key.lower()
                metadata[headers_lower] = headers[header_key]
        return metadata

    @public
    @cors_validation
    @delay_denial
    @handle_service_busy
    def POST(self, req):
        """HTTP POST request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        req.acl = container_info['write_acl']
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        error_response = check_metadata(req, 'object')
        if error_response:
            return error_response

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
        oio_headers = {'X-oio-req-id': self.trans_id}
        try:
            self.app.storage.object_set_properties(
                self.account_name, self.container_name, self.object_name,
                metadata, clear=True, headers=oio_headers)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return HTTPNotFound(request=req)
        resp = HTTPAccepted(request=req)
        return resp

    @public
    @cors_validation
    @delay_denial
    @handle_service_busy
    def PUT(self, req):
        """HTTP PUT request handler."""
        if req.if_none_match is not None and '*' not in req.if_none_match:
            # Sending an etag with if-none-match isn't currently supported
            return HTTPBadRequest(request=req, content_type='text/plain',
                                  body='If-None-Match only supports *')
        container_info = self.container_info(
            self.account_name, self.container_name, req)

        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']

        # is request authorized
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        self._update_content_type(req)

        # check constraints on object name and request headers
        error_response = check_object_creation(req, self.object_name) or \
            check_content_type(req)
        if error_response:
            return error_response

        self._update_x_timestamp(req)

        data_source = req.environ['wsgi.input']
        if req.content_length:
            data_source = ExpectedSizeReader(data_source, req.content_length)

        headers = self._prepare_headers(req)
        resp = self._store_object(req, data_source, headers)
        return resp

    def _prepare_headers(self, req):
        req.headers['X-Timestamp'] = Timestamp(time.time()).internal
        headers = self.generate_request_headers(req, additional=req.headers)
        return headers

    def _get_auto_policy_from_size(self, content_length):
        # the default stgpol has an offset of 0 so should always be choose
        policy = None
        for (name, offset) in self.app.oio_stgpol:
            if offset <= content_length:
                policy = name

        return policy

    def _store_object(self, req, data_source, headers):
        content_type = req.headers.get('content-type', 'octet/stream')
        storage = self.app.storage
        policy = None
        container_info = self.container_info(self.account_name,
                                             self.container_name, req)
        if 'X-Oio-Storage-Policy' in req.headers:
            policy = req.headers.get('X-Oio-Storage-Policy')
            if not self.app.POLICIES.get_by_name(policy):
                raise HTTPBadRequest(
                    "invalid policy '%s', must be in %s" %
                    (policy, self.app.POLICIES.by_name.keys()))
        else:
            try:
                policy_index = int(
                    req.headers.get('X-Backend-Storage-Policy-Index',
                                    container_info['storage_policy']))
            except TypeError:
                policy_index = 0
            if policy_index != 0:
                policy = self.app.POLICIES.get_by_index(policy_index).name
            else:
                content_length = int(req.headers.get('content-length', 0))
                policy = self._get_auto_policy_from_size(content_length)

        metadata = self.load_object_metadata(headers)
        # TODO actually support if-none-match
        oio_headers = {'X-oio-req-id': self.trans_id}
        try:
            chunks, size, checksum = storage.object_create(
                self.account_name, self.container_name,
                obj_name=self.object_name, file_or_path=data_source,
                mime_type=content_type, policy=policy, headers=oio_headers,
                etag=req.headers.get('etag', '').strip('"'), metadata=metadata)
        except exceptions.PreconditionFailed:
            raise HTTPPreconditionFailed(request=req)
        except SourceReadTimeout as err:
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
        except ServiceBusy:
            raise
        except Exception:
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)

        resp = HTTPCreated(request=req, etag=checksum)
        return resp

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
    @handle_service_busy
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        self._update_x_timestamp(req)

        return self._delete_object(req)

    def _delete_object(self, req):
        storage = self.app.storage
        oio_headers = {'X-oio-req-id': self.trans_id}
        try:
            storage.object_delete(
                self.account_name, self.container_name, self.object_name,
                version=req.environ.get('oio_query', {}).get('version'),
                headers=oio_headers)
        except exceptions.NoSuchContainer:
            return HTTPNotFound(request=req)
        except exceptions.NoSuchObject:
            # Swift doesn't consider this case as an error
            pass
        resp = HTTPNoContent(request=req)
        return resp
