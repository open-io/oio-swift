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
import time

from oio.common.json import json

from swift.common.middleware.bulk import ACCEPTABLE_FORMATS, get_response_body
from swift.common.middleware.listing_formats import \
    MAX_CONTAINER_LISTING_CONTENT_LENGTH
from swift.common.middleware.slo import DEFAULT_MAX_MANIFEST_SEGMENTS, \
    DEFAULT_MAX_MANIFEST_SIZE, DEFAULT_YIELD_FREQUENCY, \
    parse_and_validate_input, StaticLargeObject, SYSMETA_SLO_ETAG, \
    SYSMETA_SLO_SIZE
from swift.common.swob import Request, HTTPBadRequest, HTTPMethodNotAllowed, \
    HTTPRequestEntityTooLarge, HTTPLengthRequired, HTTPUnprocessableEntity, \
    HTTPException, RESPONSE_REASONS
from swift.common.utils import closing_if_possible, config_true_value, \
    get_valid_utf8_str, quote, register_swift_info
from swift.common.wsgi import make_subrequest


class OioStaticLargeObject(StaticLargeObject):

    def __init__(self, app, conf, **kwargs):
        super(OioStaticLargeObject, self).__init__(app, conf, **kwargs)
        self.logger.warning("oioswift.slo in use")

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
            sub_req = make_subrequest(
                req.environ,
                path='%s?format=json&prefix=%s&limit=%d' %
                     (segments_container_path, seg_prefix,
                      self.max_manifest_segments),
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
            if 'subdir' in item:
                continue
            etag, params = parse_header(item['hash'])
            if 'slo_etag' in params:
                item['slo_etag'] = '"%s"' % params.pop('slo_etag')
                item['hash'] = etag + ''.join(
                    '; %s=%s' % kv for kv in params.items())

        resp.body = json.dumps(listing).encode('ascii')
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
