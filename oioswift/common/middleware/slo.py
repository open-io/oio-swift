# Copyright (c) 2010-2012 OpenStack Foundation
# Copyright (c) 2020 OpenIO SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Please check original doc from swift/common/middleware/slo.py
"""

import base64
from cgi import parse_header
from collections import defaultdict
from datetime import datetime
from hashlib import md5
import mimetypes
import six
from six.moves.urllib.parse import urlencode
import time

from oio.common.json import json

from swift.common.exceptions import ListingIterError, SegmentError
from swift.common.middleware.bulk import ACCEPTABLE_FORMATS, get_response_body
from swift.common.middleware.listing_formats import \
    MAX_CONTAINER_LISTING_CONTENT_LENGTH
from swift.common.middleware.slo import DEFAULT_MAX_MANIFEST_SEGMENTS, \
    DEFAULT_MAX_MANIFEST_SIZE, DEFAULT_YIELD_FREQUENCY, \
    parse_and_validate_input, StaticLargeObject, SYSMETA_SLO_ETAG, \
    SYSMETA_SLO_SIZE, SloGetContext
from swift.common.middleware.versioned_writes import DELETE_MARKER_CONTENT_TYPE
from swift.common.swob import Request, HTTPBadRequest, HTTPMethodNotAllowed, \
    HTTPRequestEntityTooLarge, HTTPLengthRequired, HTTPOk, HTTPConflict, \
    HTTPUnprocessableEntity, HTTPException, RESPONSE_REASONS, Response
from swift.common.utils import close_if_possible, closing_if_possible, \
    config_true_value, get_valid_utf8_str, override_bytes_from_content_type, \
    quote, register_swift_info, RateLimitedIterator
from swift.common.request_helpers import SegmentedIterable, \
    update_etag_is_at_header, resolve_etag_is_at_header
from swift.common.wsgi import make_subrequest


class OioSloGetContext(SloGetContext):

    def __init__(self, slo):
        super(OioSloGetContext, self).__init__(slo)

    def handle_slo_get_or_head(self, req, start_response):
        """
        Takes a request and a start_response callable and does the normal WSGI
        thing with them. Returns an iterator suitable for sending up the WSGI
        chain.

        :param req: :class:`~swift.common.swob.Request` object; is a ``GET`` or
                    ``HEAD`` request aimed at what may (or may not) be a static
                    large object manifest.
        :param start_response: WSGI start_response callable
        """
        if req.params.get('multipart-manifest') != 'get':
            # If this object is an SLO manifest, we may have saved off the
            # large object etag during the original PUT. Send an
            # X-Backend-Etag-Is-At header so that, if the SLO etag *was*
            # saved, we can trust the object-server to respond appropriately
            # to If-Match/If-None-Match requests.
            update_etag_is_at_header(req, SYSMETA_SLO_ETAG)
        resp_iter = self._app_call(req.environ)

        # make sure this response is for a static large object manifest
        slo_marker = slo_etag = slo_size = None
        for header, value in self._response_headers:
            header = header.lower()
            if header == SYSMETA_SLO_ETAG:
                slo_etag = value
            elif header == SYSMETA_SLO_SIZE:
                slo_size = value
            elif (header == 'x-static-large-object' and
                  config_true_value(value)):
                slo_marker = value

            if slo_marker and slo_etag and slo_size:
                break

        if not slo_marker:
            # Not a static large object manifest. Just pass it through.
            start_response(self._response_status,
                           self._response_headers,
                           self._response_exc_info)
            return resp_iter

        # Handle pass-through request for the manifest itself
        if req.params.get('multipart-manifest') == 'get':
            if req.params.get('format') == 'raw':
                resp_iter = self.convert_segment_listing(
                    self._response_headers, resp_iter)
            else:
                new_headers = []
                for header, value in self._response_headers:
                    if header.lower() == 'content-type':
                        new_headers.append(('Content-Type',
                                            'application/json; charset=utf-8'))
                    else:
                        new_headers.append((header, value))
                self._response_headers = new_headers
            start_response(self._response_status,
                           self._response_headers,
                           self._response_exc_info)
            return resp_iter

        is_conditional = self._response_status.startswith(('304', '412')) and (
            req.if_match or req.if_none_match)
        if slo_etag and slo_size and (
                req.method == 'HEAD' or is_conditional):
            # Since we have length and etag, we can respond immediately
            resp = Response(
                status=self._response_status,
                headers=self._response_headers,
                app_iter=resp_iter,
                request=req,
                conditional_etag=resolve_etag_is_at_header(
                    req, self._response_headers),
                conditional_response=True)
            resp.headers.update({
                'Etag': '"%s"' % slo_etag,
                'Content-Length': slo_size,
            })
            return resp(req.environ, start_response)

        if self._need_to_refetch_manifest(req):
            req.environ['swift.non_client_disconnect'] = True
            close_if_possible(resp_iter)
            del req.environ['swift.non_client_disconnect']

            get_req = make_subrequest(
                req.environ, method='GET',
                headers={'x-auth-token': req.headers.get('x-auth-token')},
                agent='%(orig)s SLO MultipartGET', swift_source='SLO')
            resp_iter = self._app_call(get_req.environ)

        # Any Content-Range from a manifest is almost certainly wrong for the
        # full large object.
        resp_headers = [(h, v) for h, v in self._response_headers
                        if not h.lower() == 'content-range']

        response = self.get_or_head_response(
            req, resp_headers, resp_iter)
        return response(req.environ, start_response)

    def get_or_head_response(self, req, resp_headers, resp_iter):
        segments = self._get_manifest_read(resp_iter)
        slo_etag = None
        content_length = None
        response_headers = []
        for header, value in resp_headers:
            lheader = header.lower()
            if lheader not in ('etag', 'content-length'):
                response_headers.append((header, value))

            if lheader == SYSMETA_SLO_ETAG:
                slo_etag = value
            elif lheader == SYSMETA_SLO_SIZE:
                # it's from sysmeta, so we don't worry about non-integer
                # values here
                content_length = int(value)

        # Prep to calculate content_length & etag if necessary
        if slo_etag is None:
            calculated_etag = md5()
        if content_length is None:
            calculated_content_length = 0

        for seg_dict in segments:
            # Decode any inlined data; it's important that we do this *before*
            # calculating the segment length and etag
            if 'data' in seg_dict:
                seg_dict['raw_data'] = base64.b64decode(seg_dict.pop('data'))

            if slo_etag is None:
                if 'raw_data' in seg_dict:
                    calculated_etag.update(
                        md5(seg_dict['raw_data']).hexdigest())
                elif seg_dict.get('range'):
                    calculated_etag.update(
                        '%s:%s;' % (seg_dict['hash'], seg_dict['range']))
                else:
                    calculated_etag.update(seg_dict['hash'])

            if content_length is None:
                if config_true_value(seg_dict.get('sub_slo')):
                    override_bytes_from_content_type(
                        seg_dict, logger=self.slo.logger)
                calculated_content_length += self._segment_length(seg_dict)

        if slo_etag is None:
            slo_etag = calculated_etag.hexdigest()
        if content_length is None:
            content_length = calculated_content_length

        response_headers.append(('Content-Length', str(content_length)))
        response_headers.append(('Etag', '"%s"' % slo_etag))

        if req.method == 'HEAD':
            return self._manifest_head_response(req, response_headers)
        else:
            return self._manifest_get_response(
                req, content_length, response_headers, segments)

    def _manifest_head_response(self, req, response_headers):
        conditional_etag = resolve_etag_is_at_header(req, response_headers)
        return HTTPOk(request=req, headers=response_headers, body='',
                      conditional_etag=conditional_etag,
                      conditional_response=True)

    def _manifest_get_response(self, req, content_length, response_headers,
                               segments):
        if req.range:
            byteranges = [
                # For some reason, swob.Range.ranges_for_length adds 1 to the
                # last byte's position.
                (start, end - 1) for start, end
                in req.range.ranges_for_length(content_length)]
        else:
            byteranges = []

        ver, account, _junk = req.split_path(3, 3, rest_with_last=True)
        plain_listing_iter = self._segment_listing_iterator(
            req, ver, account, segments, byteranges)

        def ratelimit_predicate(seg_dict):
            if 'raw_data' in seg_dict:
                return False  # it's already in memory anyway
            start = seg_dict.get('start_byte') or 0
            end = seg_dict.get('end_byte')
            if end is None:
                end = int(seg_dict['bytes']) - 1
            is_small = (end - start + 1) < self.slo.rate_limit_under_size
            return is_small

        ratelimited_listing_iter = RateLimitedIterator(
            plain_listing_iter,
            self.slo.rate_limit_segments_per_sec,
            limit_after=self.slo.rate_limit_after_segment,
            ratelimit_if=ratelimit_predicate)

        # data segments are already in the correct format, but object-backed
        # segments need a path key added
        segment_listing_iter = (
            seg_dict if 'raw_data' in seg_dict else
            dict(seg_dict, path=self._segment_path(ver, account, seg_dict))
            for seg_dict in ratelimited_listing_iter)

        segmented_iter = SegmentedIterable(
            req, self.slo.app, segment_listing_iter,
            name=req.path, logger=self.slo.logger,
            ua_suffix="SLO MultipartGET",
            swift_source="SLO",
            max_get_time=self.slo.max_get_time)

        try:
            segmented_iter.validate_first_segment()
        except (ListingIterError, SegmentError):
            # Copy from the SLO explanation in top of this file.
            # If any of the segments from the manifest are not found or
            # their Etag/Content Length no longer match the connection
            # will drop. In this case a 409 Conflict will be logged in
            # the proxy logs and the user will receive incomplete results.
            return HTTPConflict(request=req)

        conditional_etag = resolve_etag_is_at_header(req, response_headers)
        response = Response(request=req, content_length=content_length,
                            headers=response_headers,
                            conditional_response=True,
                            conditional_etag=conditional_etag,
                            app_iter=segmented_iter)
        return response


class OioStaticLargeObject(StaticLargeObject):

    def __init__(self, app, conf, **kwargs):
        super(OioStaticLargeObject, self).__init__(app, conf, **kwargs)
        self.logger.warning("oioswift.slo in use")

    def handle_multipart_get_or_head(self, req, start_response):
        """
        Handles the GET or HEAD of a SLO manifest.

        The response body (only on GET, of course) will consist of the
        concatenation of the segments.

        :param req: a :class:`~swift.common.swob.Request` with a path
                    referencing an object
        :param start_response: WSGI start_response callable
        :raises HttpException: on errors
        """
        return OioSloGetContext(self).handle_slo_get_or_head(
            req, start_response)

    def handle_multipart_put(self, req, start_response):
        """
        Will handle the PUT of a SLO manifest.
        List every object in manifest to check if is valid and if so will
        save a manifest generated from the user input. Uses WSGIContext to
        call self and start_response and returns a WSGI iterator.

        :param req: a :class:`~swift.common.swob.Request` with an obj in path
        :param start_response: WSGI start_response callable
        :raises HttpException: on errors
        """
        vrs, account, container, obj = req.split_path(4, rest_with_last=True)
        if req.content_length > self.max_manifest_size:
            raise HTTPRequestEntityTooLarge(
                "Manifest File > %d bytes" % self.max_manifest_size)
        if req.headers.get('X-Copy-From'):
            raise HTTPMethodNotAllowed(
                'Multipart Manifest PUTs cannot be COPY requests')
        if req.content_length is None and \
                req.headers.get('transfer-encoding', '').lower() != 'chunked':
            raise HTTPLengthRequired(request=req)
        parsed_data = parse_and_validate_input(
            req.body_file.read(self.max_manifest_size),
            req.path)
        problem_segments = []

        object_segments = [seg for seg in parsed_data if 'path' in seg]
        if len(object_segments) > self.max_manifest_segments:
            raise HTTPRequestEntityTooLarge(
                'Number of object-backed segments must be <= %d' %
                self.max_manifest_segments)
        try:
            out_content_type = req.accept.best_match(ACCEPTABLE_FORMATS)
        except ValueError:
            out_content_type = 'text/plain'  # Ignore invalid header
        if not out_content_type:
            out_content_type = 'text/plain'
        data_for_storage = [None] * len(parsed_data)
        total_size = 0
        path2indices = defaultdict(list)
        for index, seg_dict in enumerate(parsed_data):
            if 'data' in seg_dict:
                data_for_storage[index] = seg_dict
                total_size += len(base64.b64decode(seg_dict['data']))
            else:
                path2indices[seg_dict['path']].append(index)

        # BEGIN: New OpenIO code
        obj_path = get_valid_utf8_str(object_segments[0]['path']).lstrip('/')
        split_path = obj_path.split('/')
        segments_container = split_path[0]
        seg_prefix = '/'.join(split_path[1:-1])
        segments_container_path = '/'.join(
            ['', vrs, account, segments_container])
        # END: New OpenIO code

        # BEGIN: Adapt for OpenIO code
        def validate_seg_dict(seg_dict, seg_resp, allow_empty_segment):
            obj_name = seg_dict['path']

            segment_length = seg_resp['bytes']
            if seg_dict.get('range'):
                # Since we now know the length, we can normalize the
                # range. We know that there is exactly one range
                # requested since we checked that earlier in
                # parse_and_validate_input().
                ranges = seg_dict['range'].ranges_for_length(
                    seg_resp['bytes'])

                if not ranges:
                    problem_segments.append([quote(obj_name),
                                             'Unsatisfiable Range'])
                elif ranges == [(0, seg_resp['bytes'])]:
                    # Just one range, and it exactly matches the object.
                    # Why'd we do this again?
                    del seg_dict['range']
                    segment_length = seg_resp['bytes']
                else:
                    rng = ranges[0]
                    seg_dict['range'] = '%d-%d' % (rng[0], rng[1] - 1)
                    segment_length = rng[1] - rng[0]

            if segment_length < 1 and not allow_empty_segment:
                problem_segments.append(
                    [quote(obj_name),
                     'Too small; each segment must be at least 1 byte.'])

            _size_bytes = seg_dict.get('size_bytes')
            size_mismatch = (
                _size_bytes is not None and
                _size_bytes != seg_resp['bytes']
            )
            if size_mismatch:
                problem_segments.append([quote(obj_name), 'Size Mismatch'])

            _etag = seg_dict.get('etag')
            etag_mismatch = (
                _etag is not None and
                _etag != seg_resp['hash']
            )
            if etag_mismatch:
                problem_segments.append([quote(obj_name), 'Etag Mismatch'])

            last_modified_formatted = seg_resp.get('last_modified')
            if not last_modified_formatted:
                # shouldn't happen
                last_modified_formatted = datetime.now().strftime(
                    '%Y-%m-%dT%H:%M:%S.%f'
                )
            seg_data = {
                'name': '/' + seg_dict['path'].lstrip('/'),
                'bytes': seg_resp['bytes'],
                'hash': seg_resp['hash'],
                'content_type': seg_resp['content_type'],
                'last_modified': last_modified_formatted
            }
            if seg_dict.get('range'):
                seg_data['range'] = seg_dict['range']
            if config_true_value(seg_resp['slo']):
                seg_data['sub_slo'] = True

            return segment_length, seg_data
        # END: Adapt for OpenIO code

        heartbeat = config_true_value(req.params.get('heartbeat'))
        separator = ''
        if heartbeat:
            # Apparently some ways of deploying require that this to happens
            # *before* the return? Not sure why.
            req.environ['eventlet.minimum_write_chunk_size'] = 0
            start_response('202 Accepted', [  # NB: not 201 !
                ('Content-Type', out_content_type),
            ])
            separator = '\r\n\r\n'

        def resp_iter(total_size=total_size):
            # wsgi won't propagate start_response calls until some data has
            # been yielded so make sure first heartbeat is sent immediately
            if heartbeat:
                yield ' '
            last_yield_time = time.time()

            # BEGIN: New OpenIO code
            params = {
                'format': 'json',
                'prefix': seg_prefix,
                'limit': self.max_manifest_segments
            }
            sub_req = make_subrequest(
                req.environ,
                path='%s?%s' % (segments_container_path, urlencode(params)),
                method='GET',
                headers={'x-auth-token': req.headers.get('x-auth-token')},
                agent='%(orig)s SLO MultipartPUT', swift_source='SLO')
            sub_req.environ.setdefault('oio.query', {})
            # All meta2 databases may not be synchronized
            sub_req.environ['oio.query']['force_master'] = True
            sub_req.environ['oio.query']['slo'] = True
            list_seg_resp = sub_req.get_response(self)

            with closing_if_possible(list_seg_resp.app_iter):
                segments_resp = json.loads(list_seg_resp.body)

            seg_resp_dict = dict()
            for seg_resp in segments_resp:
                obj_name = '/'.join(('', segments_container, seg_resp['name']))
                seg_resp_dict[obj_name] = seg_resp

            for obj_name in path2indices:
                now = time.time()
                if heartbeat and (now - last_yield_time >
                                  self.yield_frequency):
                    # Make sure we've called start_response before
                    # sending data
                    yield ' '
                    last_yield_time = now

                for i in path2indices[obj_name]:
                    if not list_seg_resp.is_success:
                        problem_segments.append([quote(obj_name),
                                                list_seg_resp.status])
                        segment_length = 0
                        seg_data = None
                    else:
                        seg_resp = seg_resp_dict.get(obj_name)
                        if seg_resp:
                            segment_length, seg_data = validate_seg_dict(
                                parsed_data[i], seg_resp,
                                (i == len(parsed_data) - 1))
                        else:
                            problem_segments.append([quote(obj_name), 404])
                            segment_length = 0
                            seg_data = None
                    data_for_storage[i] = seg_data
                    total_size += segment_length
            # END: New OpenIO code

            if problem_segments:
                err = HTTPBadRequest(content_type=out_content_type)
                resp_dict = {}
                if heartbeat:
                    resp_dict['Response Status'] = err.status
                    resp_dict['Response Body'] = err.body or '\n'.join(
                        RESPONSE_REASONS.get(err.status_int, ['']))
                else:
                    start_response(err.status,
                                   [(h, v) for h, v in err.headers.items()
                                    if h.lower() != 'content-length'])
                yield separator + get_response_body(
                    out_content_type, resp_dict, problem_segments, 'upload')
                return

            slo_etag = md5()
            for seg_data in data_for_storage:
                if 'data' in seg_data:
                    raw_data = base64.b64decode(seg_data['data'])
                    slo_etag.update(md5(raw_data).hexdigest())
                elif seg_data.get('range'):
                    slo_etag.update('%s:%s;' % (seg_data['hash'],
                                                seg_data['range']))
                else:
                    slo_etag.update(seg_data['hash'])

            slo_etag = slo_etag.hexdigest()
            client_etag = req.headers.get('Etag')
            if client_etag and client_etag.strip('"') != slo_etag:
                err = HTTPUnprocessableEntity(request=req)
                if heartbeat:
                    yield separator + get_response_body(out_content_type, {
                        'Response Status': err.status,
                        'Response Body': err.body or '\n'.join(
                            RESPONSE_REASONS.get(err.status_int, [''])),
                    }, problem_segments, 'upload')
                else:
                    for chunk in err(req.environ, start_response):
                        yield chunk
                return

            json_data = json.dumps(data_for_storage)
            if six.PY3:
                json_data = json_data.encode('utf-8')
            req.body = json_data
            req.headers.update({
                SYSMETA_SLO_ETAG: slo_etag,
                SYSMETA_SLO_SIZE: total_size,
                'X-Static-Large-Object': 'True',
                'Etag': md5(json_data).hexdigest(),
            })

            # Ensure container listings have both etags. However, if any
            # middleware to the left of us touched the base value, trust them.
            override_header = 'X-Object-Sysmeta-Container-Update-Override-Etag'
            val, sep, params = req.headers.get(
                override_header, '').partition(';')
            req.headers[override_header] = '%s; slo_etag=%s' % (
                (val or req.headers['Etag']) + sep + params, slo_etag)

            env = req.environ
            if not env.get('CONTENT_TYPE'):
                guessed_type, _junk = mimetypes.guess_type(req.path_info)
                env['CONTENT_TYPE'] = (guessed_type or
                                       'application/octet-stream')
            env['swift.content_type_overridden'] = True
            env['CONTENT_TYPE'] += ";swift_bytes=%d" % total_size

            resp = req.get_response(self.app)
            resp_dict = {'Response Status': resp.status}
            if resp.is_success:
                resp.etag = slo_etag
                resp_dict['Etag'] = resp.headers['Etag']
                resp_dict['Last Modified'] = resp.headers['Last-Modified']

            if heartbeat:
                resp_dict['Response Body'] = resp.body
                yield separator + get_response_body(
                    out_content_type, resp_dict, [], 'upload')
            else:
                for chunk in resp(req.environ, start_response):
                    yield chunk

        return resp_iter()

    def handle_container_listing(self, req, start_response):
        resp = req.get_response(self.app)
        if not resp.is_success or resp.content_type != 'application/json':
            return resp(req.environ, start_response)
        if resp.content_length is None:
            return resp(req.environ, start_response)
        if resp.content_length > MAX_CONTAINER_LISTING_CONTENT_LENGTH:
            self.logger.warn(
                'The content length (%d) of the listing is too long (max=%d)',
                resp.content_length, MAX_CONTAINER_LISTING_CONTENT_LENGTH)
            return resp(req.environ, start_response)
        try:
            listing = json.loads(resp.body)
        except ValueError:
            return resp(req.environ, start_response)

        for item in listing:
            if 'subdir' in item \
                    or item.get('content_type') == DELETE_MARKER_CONTENT_TYPE:
                continue
            etag, params = parse_header(item['hash'])
            if 'slo_etag' in params:
                item['slo_etag'] = '"%s"' % params.pop('slo_etag')
                item['hash'] = etag + ''.join(
                    '; %s=%s' % kv for kv in params.items())

        resp.body = json.dumps(listing)
        return resp(req.environ, start_response)

    def __call__(self, env, start_response):
        """
        WSGI entry point
        """
        if env.get('swift.slo_override'):
            return self.app(env, start_response)

        req = Request(env)
        try:
            vrs, account, container, obj = req.split_path(3, 4, True)
        except ValueError:
            return self.app(env, start_response)

        if not obj:
            if req.method == 'GET':
                return self.handle_container_listing(req, start_response)
            return self.app(env, start_response)

        try:
            if req.method == 'PUT' and \
                    req.params.get('multipart-manifest') == 'put':
                return self.handle_multipart_put(req, start_response)
            if req.method == 'DELETE' and \
                    req.params.get('multipart-manifest') == 'delete':
                return self.handle_multipart_delete(req)(env, start_response)
            if req.method == 'GET' or req.method == 'HEAD':
                return self.handle_multipart_get_or_head(req, start_response)
            if 'X-Static-Large-Object' in req.headers:
                raise HTTPBadRequest(
                    request=req,
                    body='X-Static-Large-Object is a reserved header. '
                    'To create a static large object add query param '
                    'multipart-manifest=put.')
        except HTTPException as err_resp:
            return err_resp(env, start_response)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    max_manifest_segments = int(conf.get('max_manifest_segments',
                                         DEFAULT_MAX_MANIFEST_SEGMENTS))
    max_manifest_size = int(conf.get('max_manifest_size',
                                     DEFAULT_MAX_MANIFEST_SIZE))
    yield_frequency = int(conf.get('yield_frequency',
                                   DEFAULT_YIELD_FREQUENCY))

    register_swift_info('slo',
                        max_manifest_segments=max_manifest_segments,
                        max_manifest_size=max_manifest_size,
                        yield_frequency=yield_frequency,
                        # this used to be configurable; report it as 1 for
                        # clients that might still care
                        min_segment_size=1)

    def slo_filter(app):
        return OioStaticLargeObject(
            app, conf,
            max_manifest_segments=max_manifest_segments,
            max_manifest_size=max_manifest_size,
            yield_frequency=yield_frequency)
    return slo_filter
