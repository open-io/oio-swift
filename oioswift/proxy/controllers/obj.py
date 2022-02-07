# Copyright (c) 2010-2012 OpenStack Foundation
# Copyright (c) 2016-2020 OpenIO SAS
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
import mimetypes
import time
import math

from swift import gettext_ as _
from swift.common.utils import (
    clean_content_type, config_true_value, Timestamp, public,
    close_if_possible, closing_if_possible)
from swift.common.constraints import check_metadata, check_object_creation
from swift.common.header_key_dict import HeaderKeyDict
from swift.common.middleware.versioned_writes import DELETE_MARKER_CONTENT_TYPE
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPConflict, HTTPPreconditionFailed, HTTPRequestTimeout, \
    HTTPUnprocessableEntity, HTTPClientDisconnect, HTTPCreated, \
    HTTPNoContent, Response, HTTPInternalServerError, multi_range_iterator, \
    HTTPServiceUnavailable
from swift.common.request_helpers import is_sys_or_user_meta, \
    is_object_transient_sysmeta, resolve_etag_is_at_header
from swift.common.wsgi import make_subrequest
from swift.proxy.controllers.base import set_object_info_cache, \
        delay_denial, cors_validation, get_object_info
from swift.proxy.controllers.obj import check_content_type

from swift.proxy.controllers.obj import BaseObjectController as \
        BaseObjectController

from oio.common import exceptions
try:
    # supported only by 4.6.0
    from oio.common.constants import FORCEVERSIONING_HEADER
    SUPPORT_VERSIONING = True
except ImportError:
    SUPPORT_VERSIONING = False

from oio.common.http import ranges_from_http_header
from oio.common.storage_method import STORAGE_METHODS
from oio.api.object_storage import _sort_chunks

from oio.common.exceptions import SourceReadTimeout
from oioswift.utils import check_if_none_match, \
    handle_not_allowed, handle_oio_timeout, handle_service_busy, \
    REQID_HEADER, BUCKET_NAME_PROP, MULTIUPLOAD_SUFFIX

SLO = 'x-static-large-object'
BUCKET_NAME_HEADER = 'X-Object-Sysmeta-Oio-Bucket-Name'


class ObjectControllerRouter(object):
    def __getitem__(self, policy):
        return ObjectController


class StreamRangeIterator(object):
    """
    Data stream wrapper that handles range requests and deals with exceptions.
    """

    def __init__(self, request, stream):
        self.req = request
        self._stream = stream

    def app_iter_range(self, _start, _stop):
        # This will be called when there is only one range,
        # no need to check the number of bytes
        return self.stream()

    def _chunked_app_iter_range(self, start, stop):
        # The stream generator give us one "chunk" per range,
        # and as we are called once for each range, we must
        # simulate end-of-stream by generating StopIteration
        for dat in self.stream():
            yield dat
            raise StopIteration

    def app_iter_ranges(self, ranges, content_type,
                        boundary, content_size,
                        *_args, **_kwargs):
        for chunk in multi_range_iterator(
                ranges, content_type, boundary, content_size,
                self._chunked_app_iter_range):
            yield chunk

    def stream(self, *args, **kwargs):
        """
        Get the wrapped data stream.
        """
        try:
            for dat in self._stream:
                yield dat
        except (exceptions.ServiceBusy, exceptions.ServiceUnavailable) as err:
            # We cannot use the handle_service_busy() decorator
            # because it returns the exception object instead of raising it.
            headers = dict()
            headers['Retry-After'] = '1'
            raise HTTPServiceUnavailable(request=self.req, headers=headers,
                                         body=err.message)

    def __iter__(self):
        return self.stream()


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
                raise exceptions.SourceReadError(
                    "Truncated input (%s bytes read, %s bytes expected)" % (
                        self.consumed, self.expected))
        else:
            self.consumed = self.consumed + len(rc)
        return rc

    def readline(self, *args, **kwargs):
        rc = self.source.readline(*args, **kwargs)
        if len(rc) == 0:
            if self.consumed != self.expected:
                raise exceptions.SourceReadError(
                    "Truncated input (%s bytes read, %s bytes expected)" % (
                        self.consumed, self.expected))
        else:
            self.consumed = self.consumed + len(rc)
        return rc

    def close(self):
        return close_if_possible(self.source)


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

    @handle_oio_timeout
    @handle_service_busy
    @check_if_none_match
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

    def enforce_versioning(self, req):
        """
        Enforce the versioning mode of a container just before executing
        an object operation. This is useful when the current object is not
        stored in the "main" container but in a shard, where the versioning
        mode may not have been set yet.
        """
        if not SUPPORT_VERSIONING:
            return None

        # There is no reason to save several versions of segments:
        # a new version of a multipart object manifest will point to a
        # completely different set of segments, with another uploadId.
        root_container = req.headers.get(BUCKET_NAME_HEADER)
        if (root_container is None or
                root_container.endswith(MULTIUPLOAD_SUFFIX)):
            return None

        # We can't use _get_info_from_caches as it would use local worker cache
        # first and an update of versioning mode may not be detected.
        oio_cache = req.environ.get('oio.cache')
        memcache = None
        if oio_cache is None:
            memcache = getattr(self.app, 'memcache', None) or \
                req.environ.get('swift.cache')

            if memcache is not None:
                memcache_key = "/".join(
                    ("versioning", self.account_name, root_container))
                version_policy = memcache.get(memcache_key)
                if version_policy is not None:
                    if version_policy:
                        req.headers[FORCEVERSIONING_HEADER] = version_policy
                    return

        oio_headers = {REQID_HEADER: self.trans_id}
        perfdata = req.environ.get('oio.perfdata')
        try:
            meta = self.app.storage.container_get_properties(
                self.account_name, root_container, headers=oio_headers,
                cache=oio_cache, perfdata=perfdata)
        except exceptions.NoSuchContainer:
            raise HTTPNotFound(request=req)

        version_policy = meta['system'].get('sys.m2.policy.version')
        if memcache is not None:
            memcache.set(memcache_key, version_policy or '')
        if version_policy:
            req.headers[FORCEVERSIONING_HEADER] = version_policy

    def use_bucket_storage_policy(self, req):
        """
        Enforce the storage policy mode of a container just before executing
        an object operation. This is useful when the current object is not
        stored in the "main" container but in a shard,
        where the storage policy mode may not have been set yet.
        """
        if not self.app.use_bucket_storage_policy:
            return None

        root_container = req.headers.get(BUCKET_NAME_HEADER)
        if root_container is None:
            return None
        if root_container.endswith(MULTIUPLOAD_SUFFIX):
            root_container = root_container[:-len(MULTIUPLOAD_SUFFIX)]

        # We can't use _get_info_from_caches as it would use local worker cache
        # first and an update of storage policy mode may not be detected.
        oio_cache = req.environ.get('oio.cache')
        memcache = None
        if oio_cache is None:
            memcache = getattr(self.app, 'memcache', None) or \
                req.environ.get('swift.cache')

            if memcache is not None:
                memcache_key = "/".join(
                    ("storage_policy", self.account_name, root_container))
                storage_policy = memcache.get(memcache_key)
                if storage_policy is not None:
                    return storage_policy or None

        oio_headers = {REQID_HEADER: self.trans_id}
        perfdata = req.environ.get('oio.perfdata')
        try:
            meta = self.app.storage.container_get_properties(
                self.account_name, root_container, headers=oio_headers,
                cache=oio_cache, perfdata=perfdata)
        except exceptions.NoSuchContainer:
            raise HTTPNotFound(request=req)

        storage_policy = meta['system'].get('sys.m2.policy.storage')
        if memcache is not None:
            memcache.set(memcache_key, storage_policy or '')
        return storage_policy

    def get_object_head_resp(self, req):
        storage = self.app.storage
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('oio.perfdata')
        version = req.environ.get('oio.query', {}).get('version')
        force_master = False
        while True:
            try:
                if self.app.check_state:
                    metadata, chunks = storage.object_locate(
                        self.account_name, self.container_name,
                        self.object_name, version=version,
                        headers=oio_headers, force_master=force_master,
                        cache=oio_cache, perfdata=perfdata)
                else:
                    metadata = storage.object_get_properties(
                        self.account_name, self.container_name,
                        self.object_name, version=version,
                        headers=oio_headers, force_master=force_master,
                        cache=oio_cache, perfdata=perfdata)
                break
            except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
                if force_master or not \
                        self.container_name.endswith(MULTIUPLOAD_SUFFIX):
                    # Either the request failed with the master,
                    # or it is not an MPU
                    return HTTPNotFound(request=req)

                # This part appears in the manifest, so it should be there.
                # To be sure, we must go check the master
                # in case of desynchronization.
                force_master = True

        if self.app.check_state:
            storage_method = STORAGE_METHODS.load(metadata['chunk_method'])
            # TODO(mbo): use new property of STORAGE_METHODS
            min_chunks = storage_method.ec_nb_data if storage_method.ec else 1

            chunks_by_pos = _sort_chunks(chunks, storage_method.ec)
            for idx, entries in enumerate(chunks_by_pos.iteritems()):
                if idx != entries[0]:
                    return HTTPBadRequest(request=req)
                nb_chunks_ok = 0
                for entry in entries[1]:
                    try:
                        storage.blob_client.chunk_head(
                            entry['url'], headers=oio_headers)
                        nb_chunks_ok += 1
                    except exceptions.OioException:
                        pass
                    if nb_chunks_ok >= min_chunks:
                        break
                else:
                    return HTTPBadRequest(request=req)

        resp = self.make_object_response(req, metadata)
        return resp

    def get_object_fetch_resp(self, req):
        storage = self.app.storage
        if req.headers.get('Range'):
            ranges = ranges_from_http_header(req.headers.get('Range'))
        else:
            ranges = None
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('oio.perfdata')
        force_master = False
        while True:
            try:
                metadata, stream = storage.object_fetch(
                    self.account_name, self.container_name, self.object_name,
                    ranges=ranges, headers=oio_headers,
                    version=req.environ.get('oio.query', {}).get('version'),
                    force_master=force_master, cache=oio_cache,
                    perfdata=perfdata)
                break
            except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
                if force_master or not \
                        self.container_name.endswith(MULTIUPLOAD_SUFFIX):
                    # Either the request failed with the master,
                    # or it is not an MPU
                    return HTTPNotFound(request=req)

                # This part appears in the manifest, so it should be there.
                # To be sure, we must go check the master
                # in case of desynchronization.
                force_master = True
        resp = self.make_object_response(req, metadata, stream)
        return resp

    def make_object_response(self, req, metadata, stream=None):
        conditional_etag = resolve_etag_is_at_header(
            req, metadata.get('properties'))

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
                        is_object_transient_sysmeta(k) or \
                        k.lower() in self.allowed_headers:
                    resp.headers[str(k)] = v
        hash_ = metadata.get('hash')
        if hash_ is not None:
            hash_ = hash_.lower()
        resp.headers['etag'] = hash_
        resp.headers['x-object-sysmeta-version-id'] = metadata['version']
        resp.last_modified = int(metadata['mtime'])
        if stream:
            # Whether we are bothered with ranges or not, we wrap the
            # stream in order to handle exceptions.
            resp.app_iter = StreamRangeIterator(req, stream)

        length_ = metadata.get('length')
        if length_ is not None:
            length_ = int(length_)
        resp.content_length = length_
        resp.content_encoding = metadata.get('encoding')
        resp.accept_ranges = 'bytes'
        return resp

    def load_object_metadata(self, headers):
        metadata = {}
        metadata.update(
            (k.lower(), v) for k, v in headers.iteritems()
            if is_sys_or_user_meta('object', k) or
            is_object_transient_sysmeta(k))
        for header_key in self.allowed_headers:
            if header_key in headers:
                headers_lower = header_key.lower()
                metadata[headers_lower] = headers[header_key]
        return metadata

    @public
    @cors_validation
    @delay_denial
    @handle_not_allowed
    @handle_oio_timeout
    @handle_service_busy
    @check_if_none_match
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
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('oio.perfdata')
        try:
            # Genuine Swift clears all properties on POST requests.
            # But for convenience, keep them when the request originates
            # from swift3.
            clear = req.environ.get('swift.source') != 'S3'
            self.app.storage.object_set_properties(
                self.account_name, self.container_name, self.object_name,
                metadata, clear=clear, headers=oio_headers,
                version=req.environ.get('oio.query', {}).get('version'),
                cache=oio_cache, perfdata=perfdata)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return HTTPNotFound(request=req)
        resp = HTTPAccepted(request=req)
        return resp

    def _delete_slo_parts(self, req, manifest):
        """Delete parts of an obsolete SLO."""
        # We cannot use bulk-delete here,
        # because we are at the end of the pipeline, after 'bulk'.
        for part in manifest:
            path = '/'.join(('', 'v1', self.account_name)) + part['name']
            try:
                del_req = make_subrequest(req.environ, 'DELETE', path=path)
                del_req.get_response(self.app)
            except Exception as exc:
                self.app.logger.warn('Failed to delete SLO part %s: %s',
                                     path, exc)

    @public
    @cors_validation
    @delay_denial
    @handle_not_allowed
    @handle_oio_timeout
    @handle_service_busy
    @check_if_none_match
    def PUT(self, req):
        """HTTP PUT request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)

        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']

        # is request authorized
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        self.enforce_versioning(req)

        old_slo_manifest = None
        old_slo_manifest_etag = None
        # If versioning is disabled, we must check if the object exists.
        # If it's a NEW SLO (we must check it is not the same manifest),
        # we will have to delete the parts if the current
        # operation is a success.
        if (self.app.delete_slo_parts and
                not container_info['sysmeta'].get('versions-location', None)):
            try:
                dest_info = get_object_info(req.environ, self.app)
                if 'slo-size' in dest_info['sysmeta']:
                    manifest_env = req.environ.copy()
                    manifest_env['QUERY_STRING'] = 'multipart-manifest=get'
                    manifest_req = make_subrequest(manifest_env, 'GET')
                    manifest_resp = manifest_req.get_response(self.app)
                    old_slo_manifest = json.loads(manifest_resp.body)
                    old_slo_manifest_etag = dest_info.get('etag')
            except Exception as exc:
                self.app.logger.warn(('Failed to check existence of %s. If '
                                      'overwriting a SLO, old parts may '
                                      'remain. Error was: %s') %
                                     (req.path, exc))

        self._update_content_type(req)

        self._update_x_timestamp(req)

        # check constraints on object name and request headers
        error_response = check_object_creation(req, self.object_name) or \
            check_content_type(req)
        if error_response:
            return error_response

        if req.headers.get('Oio-Copy-From'):
            return self._link_object(req)

        data_source = req.environ['wsgi.input']
        if req.content_length:
            data_source = ExpectedSizeReader(data_source, req.content_length)

        headers = self._prepare_headers(req)

        with closing_if_possible(data_source):
            resp = self._store_object(req, data_source, headers)
        if (resp.is_success and
                old_slo_manifest and resp.etag != old_slo_manifest_etag):
            self.app.logger.debug(
                'Previous object %s was a different SLO, deleting parts',
                req.path)
            self._delete_slo_parts(req, old_slo_manifest)
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

    def _link_object(self, req):
        _, container, obj = req.headers['Oio-Copy-From'].split('/', 2)

        from_account = req.headers.get('X-Copy-From-Account',
                                       self.account_name)
        self.app.logger.info("Creating link from %s/%s/%s to %s/%s/%s",
                             # Existing
                             from_account, container, obj,
                             # New
                             self.account_name, self.container_name,
                             self.object_name)
        storage = self.app.storage

        if req.headers.get('Range'):
            raise Exception("Fast Copy with Range is unsupported")

            ranges = ranges_from_http_header(req.headers.get('Range'))
            if len(ranges) != 1:
                raise HTTPInternalServerError(
                    request=req, body="mutiple ranges unsupported")
            ranges = ranges[0]
        else:
            ranges = None

        headers = self._prepare_headers(req)
        metadata = self.load_object_metadata(headers)
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('oio.perfdata')
        # FIXME(FVE): use object_show, cache in req.environ
        version = req.environ.get('oio.query', {}).get('version')
        props = storage.object_get_properties(from_account, container, obj,
                                              headers=oio_headers,
                                              version=version,
                                              cache=oio_cache,
                                              perfdata=perfdata)
        if props['properties'].get(SLO, None):
            raise Exception("Fast Copy with SLO is unsupported")
        else:
            if ranges:
                raise HTTPInternalServerError(
                    request=req, body="no range supported with single object")

        try:
            # TODO check return code (values ?)
            link_meta = storage.object_link(
                from_account, container, obj,
                self.account_name, self.container_name, self.object_name,
                headers=oio_headers, properties=metadata,
                properties_directive='REPLACE', target_version=version,
                cache=oio_cache, perfdata=perfdata)
        # TODO(FVE): this exception catching block has to be refactored
        # TODO check which ones are ok or make non sense
        except exceptions.Conflict:
            raise HTTPConflict(request=req)
        except exceptions.PreconditionFailed:
            raise HTTPPreconditionFailed(request=req)
        except exceptions.EtagMismatch:
            return HTTPUnprocessableEntity(request=req)
        except (exceptions.ServiceBusy, exceptions.OioTimeout,
                exceptions.DeadlineReached):
            raise
        except (exceptions.NoSuchContainer, exceptions.NotFound):
            raise HTTPNotFound(request=req)
        except exceptions.ClientException as err:
            # 481 = CODE_POLICY_NOT_SATISFIABLE
            if err.status == 481:
                raise exceptions.ServiceBusy()
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)
        except Exception:
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)

        resp = HTTPCreated(request=req, etag=link_meta['hash'])
        return resp

    def _get_footers(self, req):
        """
        Get extra metadata that may be generated during upload by some
        middlewares (e.g. checksum of cyphered data).
        """
        footers = HeaderKeyDict()
        footer_callback = req.environ.get(
            'swift.callback.update_footers', lambda _footer: None)
        footer_callback(footers)
        return footers

    def _object_create(self, account, container, **kwargs):
        storage = self.app.storage
        if hasattr(storage, 'object_create_ext'):
            return storage.object_create_ext(account, container, **kwargs)

        _chunks, _size, checksum = storage.object_create(account, container,
                                                         **kwargs)
        return _chunks, _size, checksum, {}

    def _store_object(self, req, data_source, headers):
        content_type = req.headers.get('content-type', 'octet/stream')
        policy = None
        if 'X-Oio-Storage-Policy' in req.headers:
            policy = req.headers.get('X-Oio-Storage-Policy')
            if not self.app.POLICIES.get_by_name(policy):
                raise HTTPBadRequest(
                    "invalid policy '%s', must be in %s" %
                    (policy, self.app.POLICIES.by_name.keys()))
        else:
            container_info = self.container_info(self.account_name,
                                                 self.container_name, req)
            try:
                policy_index = int(
                    req.headers.get('X-Backend-Storage-Policy-Index',
                                    container_info['storage_policy']))
            except TypeError:
                policy_index = 0
            if policy_index != 0:
                policy = self.app.POLICIES.get_by_index(policy_index).name
            else:
                policy = self.use_bucket_storage_policy(req)
            if policy is None:
                content_length = int(req.headers.get('content-length', 0))
                policy = self._get_auto_policy_from_size(content_length)

        ct_props = {'properties': {}, 'system': {}}
        metadata = self.load_object_metadata(headers)
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('oio.perfdata')
        # only send headers if needed
        if SUPPORT_VERSIONING and headers.get(FORCEVERSIONING_HEADER):
            oio_headers[FORCEVERSIONING_HEADER] = \
                headers.get(FORCEVERSIONING_HEADER)
        # In case a shard is being created, save the name of the S3 bucket
        # in a container property. This will be used when aggregating
        # container statistics to make bucket statistics.
        if BUCKET_NAME_HEADER in headers:
            bname = headers[BUCKET_NAME_HEADER]
            # FIXME(FVE): the segments container is not part of another bucket!
            # We should not have to strip this here.
            if bname and bname.endswith(MULTIUPLOAD_SUFFIX):
                bname = bname[:-len(MULTIUPLOAD_SUFFIX)]
            ct_props['system'][BUCKET_NAME_PROP] = bname
        try:
            _chunks, _size, checksum, _meta = self._object_create(
                self.account_name, self.container_name,
                obj_name=self.object_name, file_or_path=data_source,
                mime_type=content_type, policy=policy, headers=oio_headers,
                etag=req.headers.get('etag', '').strip('"'),
                properties=metadata, container_properties=ct_props,
                cache=oio_cache, perfdata=perfdata)
            # TODO(FVE): when oio-sds supports it, do that in a callback
            # passed to object_create (or whatever upload method supports it)
            footer_md = self.load_object_metadata(self._get_footers(req))
            if footer_md:
                self.app.storage.object_set_properties(
                    self.account_name, self.container_name, self.object_name,
                    version=_meta.get('version', None), properties=footer_md,
                    headers=oio_headers, cache=oio_cache, perfdata=perfdata)
        except exceptions.Conflict:
            raise HTTPConflict(request=req)
        except exceptions.PreconditionFailed:
            raise HTTPPreconditionFailed(request=req)
        except SourceReadTimeout as err:
            self.app.logger.warning(
                _('ERROR Client read timeout (%s)'), err)
            self.app.logger.increment('client_timeouts')
            raise HTTPRequestTimeout(request=req)
        except exceptions.SourceReadError as err:
            req.client_disconnect = True
            self.app.logger.warning(
                _('Client disconnected without sending last chunk') + (
                    ': %s' % str(err)))
            self.app.logger.increment('client_disconnects')
            raise HTTPClientDisconnect(request=req)
        except exceptions.EtagMismatch:
            return HTTPUnprocessableEntity(request=req)
        except (exceptions.ServiceBusy, exceptions.OioTimeout,
                exceptions.DeadlineReached):
            raise
        except exceptions.NoSuchContainer:
            raise HTTPNotFound(request=req)
        except exceptions.ClientException as err:
            # 481 = CODE_POLICY_NOT_SATISFIABLE
            if err.status == 481:
                raise exceptions.ServiceBusy()
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)
        except Exception:
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)

        last_modified = int(_meta.get('mtime', math.ceil(time.time())))

        resp = HTTPCreated(
           request=req, etag=checksum,
           last_modified=last_modified,
           headers={'x-object-sysmeta-version-id': _meta.get('version', None)})
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

    @public
    @cors_validation
    @delay_denial
    @handle_not_allowed
    @handle_oio_timeout
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

        self.enforce_versioning(req)

        return self._delete_object(req)

    def _delete_object(self, req):
        storage = self.app.storage
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('oio.perfdata')
        # only send headers if needed
        if SUPPORT_VERSIONING and req.headers.get(FORCEVERSIONING_HEADER):
            oio_headers[FORCEVERSIONING_HEADER] = \
                req.headers.get(FORCEVERSIONING_HEADER)
        try:
            storage.object_delete(
                self.account_name, self.container_name, self.object_name,
                version=req.environ.get('oio.query', {}).get('version'),
                headers=oio_headers, cache=oio_cache, perfdata=perfdata)
        except exceptions.NoSuchContainer:
            return HTTPNotFound(request=req)
        except exceptions.NoSuchObject:
            # Swift doesn't consider this case as an error
            pass
        resp = HTTPNoContent(request=req)
        return resp
