"""
Please check original doc from swift/common/middleware/copy.py
"""

# from oio.common.http import ranges_from_http_header

import os
from six.moves.configparser import ConfigParser, NoSectionError, NoOptionError
from six.moves.urllib.parse import quote, unquote

from swift.common import utils
from swift.common.utils import get_logger, \
    config_true_value, FileLikeIter, read_conf_dir, close_if_possible
from swift.common.swob import Request, HTTPPreconditionFailed, \
    HTTPRequestEntityTooLarge, HTTPBadRequest, HTTPException
from swift.common.http import HTTP_MULTIPLE_CHOICES, HTTP_CREATED, \
    is_success, HTTP_OK
from swift.common.constraints import check_account_format, MAX_FILE_SIZE
from swift.common.request_helpers import copy_header_subset, remove_items, \
    is_sys_meta, is_sys_or_user_meta, is_object_transient_sysmeta
from swift.common.wsgi import WSGIContext, make_subrequest


def _check_path_header(req, name, length, error_msg):
    """
    Validate that the value of path-like header is
    well formatted. We assume the caller ensures that
    specific header is present in req.headers.

    :param req: HTTP request object
    :param name: header name
    :param length: length of path segment check
    :param error_msg: error message for client
    :returns: A tuple with path parts according to length
    :raise HTTPPreconditionFailed: if header value
            is not well formatted.
    """
    src_header = unquote(req.headers.get(name))
    if not src_header.startswith('/'):
        src_header = '/' + src_header
    try:
        return utils.split_path(src_header, length, length, True)
    except ValueError:
        raise HTTPPreconditionFailed(
            request=req,
            body=error_msg)


def _check_copy_from_header(req):
    """
    Validate that the value from x-copy-from header is
    well formatted. We assume the caller ensures that
    x-copy-from header is present in req.headers.

    :param req: HTTP request object
    :returns: A tuple with container name and object name
    :raise HTTPPreconditionFailed: if x-copy-from value
            is not well formatted.
    """
    return _check_path_header(req, 'X-Copy-From', 2,
                              'X-Copy-From header must be of the form '
                              '<container name>/<object name>')


def _check_destination_header(req):
    """
    Validate that the value from destination header is
    well formatted. We assume the caller ensures that
    destination header is present in req.headers.

    :param req: HTTP request object
    :returns: A tuple with container name and object name
    :raise HTTPPreconditionFailed: if destination value
            is not well formatted.
    """
    return _check_path_header(req, 'Destination', 2,
                              'Destination header must be of the form '
                              '<container name>/<object name>')


def _copy_headers(src, dest):
    """
    Will copy desired headers from src to dest.

    :params src: an instance of collections.Mapping
    :params dest: an instance of collections.Mapping
    """
    for k, v in src.items():
        if (is_sys_or_user_meta('object', k) or
                is_object_transient_sysmeta(k) or
                k.lower() == 'x-delete-at'):
            dest[k] = v


class ServerSideCopyWebContext(WSGIContext):

    def __init__(self, app, logger):
        super(ServerSideCopyWebContext, self).__init__(app)
        self.app = app
        self.logger = logger

    def get_source_resp(self, req):
        sub_req = make_subrequest(
            req.environ, path=req.path_info, headers=req.headers,
            swift_source='SSC')
        return sub_req.get_response(self.app)

    def send_put_req(self, req, additional_resp_headers, start_response):
        app_resp = self._app_call(req.environ)
        self._adjust_put_response(req, additional_resp_headers)
        start_response(self._response_status,
                       self._response_headers,
                       self._response_exc_info)
        return app_resp

    def _adjust_put_response(self, req, additional_resp_headers):
        if 'swift.post_as_copy' in req.environ:
            # Older editions returned 202 Accepted on object POSTs, so we'll
            # convert any 201 Created responses to that for compatibility with
            # picky clients.
            if self._get_status_int() == HTTP_CREATED:
                self._response_status = '202 Accepted'
        elif is_success(self._get_status_int()):
            for header, value in additional_resp_headers.items():
                self._response_headers.append((header, value))

    def handle_OPTIONS_request(self, req, start_response):
        app_resp = self._app_call(req.environ)
        if is_success(self._get_status_int()):
            for i, (header, value) in enumerate(self._response_headers):
                if header.lower() == 'allow' and 'COPY' not in value:
                    self._response_headers[i] = ('Allow', value + ', COPY')
                if header.lower() == 'access-control-allow-methods' and \
                        'COPY' not in value:
                    self._response_headers[i] = \
                        ('Access-Control-Allow-Methods', value + ', COPY')
        start_response(self._response_status,
                       self._response_headers,
                       self._response_exc_info)
        return app_resp


class ServerSideCopyMiddleware(object):

    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf, log_route="copy")
        # Read the old object_post_as_copy option from Proxy app just in case
        # someone has set it to false (non default). This wouldn't cause
        # problems during upgrade.
        self._load_object_post_as_copy_conf(conf)
        self.object_post_as_copy = \
            config_true_value(conf.get('object_post_as_copy', 'false'))
        if self.object_post_as_copy:
            msg = ('object_post_as_copy=true is deprecated; remove all '
                   'references to it from %s to disable this warning. This '
                   'option will be ignored in a future release' % conf.get(
                       '__file__', 'proxy-server.conf'))
            self.logger.warning(msg)
        self.logger.warning("oioswift.copy in use")

    def _load_object_post_as_copy_conf(self, conf):
        if ('object_post_as_copy' in conf or '__file__' not in conf):
            # Option is explicitly set in middleware conf. In that case,
            # we assume operator knows what he's doing.
            # This takes preference over the one set in proxy app
            return

        cp = ConfigParser()
        if os.path.isdir(conf['__file__']):
            read_conf_dir(cp, conf['__file__'])
        else:
            cp.read(conf['__file__'])

        try:
            pipe = cp.get("pipeline:main", "pipeline")
        except (NoSectionError, NoOptionError):
            return

        proxy_name = pipe.rsplit(None, 1)[-1]
        proxy_section = "app:" + proxy_name

        try:
            conf['object_post_as_copy'] = cp.get(proxy_section,
                                                 'object_post_as_copy')
        except (NoSectionError, NoOptionError):
            pass

    def __call__(self, env, start_response):
        req = Request(env)
        try:
            (version, account, container, obj) = req.split_path(4, 4, True)
        except ValueError:
            # If obj component is not present in req, do not proceed further.
            return self.app(env, start_response)

        self.account_name = account
        self.container_name = container
        self.object_name = obj

        # Check if fastcopy is possible
        # (only plain object at this time)
        if req.headers.get('X-Copy-From') and not (
                req.headers.get('Range') or
                req.headers.get('X-Amz-Copy-Source-Range')):
            # TODO: it could be also a copy from MPU to full object
            # but I pretty sure that this case is explained on AWS doc
            req.headers['Oio-Copy-From'] = req.headers.get('X-Copy-From')
            del req.headers['X-Copy-From']
            return self.app(env, start_response)
        """ TODO (how access proxy/obj.py instance to checking SLO ?)
            # compare range and segments

            ranges = ranges_from_http_header(req.headers.get('Range'))
            if len(ranges) == 1:
                ranges = ranges[0]

                # check that ORG object is SLO
                container, obj = req.headers['X-Copy-From'].split('/', 1)
                storage = self.app.storage
                props = storage.object_get_properties(
                    self.account_name, container, obj)
                if props['properties'].get(SLO, None):
                    manifest = json.loads("".join(data))
                offset = 0
                # identify segment to copy
                for entry in manifest:
                    if ranges[0] == offset and \
                            ranges[1] + 1 == offset + entry['bytes']:
                        _, container, obj = entry['name'].split('/', 2)
                        checksum = entry['hash']
                        self.app.logger.info(
                            "LINK SLO (%s,%s,%s) TO (%s,%s,%s)",
                            self.account_name, self.container_name,
                            self.object_name,
                            self.account_name, container, obj)
                        return self.app(env, start_response)
                        break
                    offset += entry['bytes']
                else:
                    print("NO SEGMENT FOUND, FALLACK")
        """
        try:
            # In some cases, save off original request method since it gets
            # mutated into PUT during handling. This way logging can display
            # the method the client actually sent.
            if req.method == 'PUT' and req.headers.get('X-Copy-From'):
                return self.handle_PUT(req, start_response)
            elif req.method == 'COPY':
                req.environ['swift.orig_req_method'] = req.method
                return self.handle_COPY(req, start_response)
            elif req.method == 'POST' and self.object_post_as_copy:
                req.environ['swift.orig_req_method'] = req.method
                return self.handle_object_post_as_copy(req, start_response)
            elif req.method == 'OPTIONS':
                # Does not interfere with OPTIONS response from
                # (account,container) servers and /info response.
                return self.handle_OPTIONS(req, start_response)

        except HTTPException as e:
            return e(req.environ, start_response)

        return self.app(env, start_response)

    def handle_object_post_as_copy(self, req, start_response):
        req.method = 'PUT'
        req.path_info = '/v1/%s/%s/%s' % (
            self.account_name, self.container_name, self.object_name)
        req.headers['Content-Length'] = 0
        req.headers.pop('Range', None)
        req.headers['X-Copy-From'] = quote('/%s/%s' % (self.container_name,
                                           self.object_name))
        req.environ['swift.post_as_copy'] = True
        params = req.params
        # for post-as-copy always copy the manifest itself if source is *LO
        params['multipart-manifest'] = 'get'
        req.params = params
        return self.handle_PUT(req, start_response)

    def handle_COPY(self, req, start_response):
        if not req.headers.get('Destination'):
            return HTTPPreconditionFailed(request=req,
                                          body='Destination header required'
                                          )(req.environ, start_response)
        dest_account = self.account_name
        if 'Destination-Account' in req.headers:
            dest_account = req.headers.get('Destination-Account')
            dest_account = check_account_format(req, dest_account)
            req.headers['X-Copy-From-Account'] = self.account_name
            self.account_name = dest_account
            del req.headers['Destination-Account']
        dest_container, dest_object = _check_destination_header(req)
        source = '/%s/%s' % (self.container_name, self.object_name)
        self.container_name = dest_container
        self.object_name = dest_object
        # re-write the existing request as a PUT instead of creating a new one
        req.method = 'PUT'
        # As this the path info is updated with destination container,
        # the proxy server app will use the right object controller
        # implementation corresponding to the container's policy type.
        ver, _junk = req.split_path(1, 2, rest_with_last=True)
        req.path_info = '/%s/%s/%s/%s' % \
                        (ver, dest_account, dest_container, dest_object)
        req.headers['Content-Length'] = 0
        req.headers['X-Copy-From'] = quote(source)
        del req.headers['Destination']
        return self.handle_PUT(req, start_response)

    def _get_source_object(self, ssc_ctx, source_path, req):
        source_req = req.copy_get()

        # make sure the source request uses it's container_info
        source_req.headers.pop('X-Backend-Storage-Policy-Index', None)
        source_req.path_info = quote(source_path)
        source_req.headers['X-Newest'] = 'true'
        if 'swift.post_as_copy' in req.environ:
            # We're COPYing one object over itself because of a POST; rely on
            # the PUT for write authorization, don't require read authorization
            source_req.environ['swift.authorize'] = lambda req: None
            source_req.environ['swift.authorize_override'] = True

        # in case we are copying an SLO manifest, set format=raw parameter
        params = source_req.params
        if params.get('multipart-manifest') == 'get':
            params['format'] = 'raw'
            source_req.params = params

        source_resp = ssc_ctx.get_source_resp(source_req)

        if source_resp.content_length is None:
            # This indicates a transfer-encoding: chunked source object,
            # which currently only happens because there are more than
            # CONTAINER_LISTING_LIMIT segments in a segmented object. In
            # this case, we're going to refuse to do the server-side copy.
            close_if_possible(source_resp.app_iter)
            return HTTPRequestEntityTooLarge(request=req)

        if source_resp.content_length > MAX_FILE_SIZE:
            close_if_possible(source_resp.app_iter)
            return HTTPRequestEntityTooLarge(request=req)

        return source_resp

    def _create_response_headers(self, source_path, source_resp, sink_req):
        resp_headers = dict()
        acct, path = source_path.split('/', 3)[2:4]
        resp_headers['X-Copied-From-Account'] = quote(acct)
        resp_headers['X-Copied-From'] = quote(path)
        if 'last-modified' in source_resp.headers:
            resp_headers['X-Copied-From-Last-Modified'] = \
                source_resp.headers['last-modified']
        # Existing sys and user meta of source object is added to response
        # headers in addition to the new ones.
        _copy_headers(sink_req.headers, resp_headers)
        return resp_headers

    def handle_PUT(self, req, start_response):
        if req.content_length:
            return HTTPBadRequest(body='Copy requests require a zero byte '
                                  'body', request=req,
                                  content_type='text/plain')(req.environ,
                                                             start_response)

        # Form the path of source object to be fetched
        ver, acct, _rest = req.split_path(2, 3, True)
        src_account_name = req.headers.get('X-Copy-From-Account')
        if src_account_name:
            src_account_name = check_account_format(req, src_account_name)
        else:
            src_account_name = acct
        src_container_name, src_obj_name = _check_copy_from_header(req)
        source_path = '/%s/%s/%s/%s' % (ver, src_account_name,
                                        src_container_name, src_obj_name)

        if req.environ.get('swift.orig_req_method', req.method) != 'POST':
            self.logger.info("Copying object from %s to %s" %
                             (source_path, req.path))

        # GET the source object, bail out on error
        ssc_ctx = ServerSideCopyWebContext(self.app, self.logger)
        source_resp = self._get_source_object(ssc_ctx, source_path, req)
        if source_resp.status_int >= HTTP_MULTIPLE_CHOICES:
            return source_resp(source_resp.environ, start_response)

        # Create a new Request object based on the original request instance.
        # This will preserve original request environ including headers.
        sink_req = Request.blank(req.path_info, environ=req.environ)

        def is_object_sysmeta(k):
            return is_sys_meta('object', k)

        if 'swift.post_as_copy' in sink_req.environ:
            # Post-as-copy: ignore new sysmeta, copy existing sysmeta
            remove_items(sink_req.headers, is_object_sysmeta)
            copy_header_subset(source_resp, sink_req, is_object_sysmeta)
        elif config_true_value(req.headers.get('x-fresh-metadata', 'false')):
            # x-fresh-metadata only applies to copy, not post-as-copy: ignore
            # existing user metadata, update existing sysmeta with new
            copy_header_subset(source_resp, sink_req, is_object_sysmeta)
            copy_header_subset(req, sink_req, is_object_sysmeta)
        else:
            # First copy existing sysmeta, user meta and other headers from the
            # source to the sink, apart from headers that are conditionally
            # copied below and timestamps.
            exclude_headers = ('x-static-large-object', 'x-object-manifest',
                               'etag', 'content-type', 'x-timestamp',
                               'x-backend-timestamp')
            copy_header_subset(source_resp, sink_req,
                               lambda k: k.lower() not in exclude_headers)
            # now update with original req headers
            sink_req.headers.update(req.headers)

        params = sink_req.params
        if params.get('multipart-manifest') == 'get':
            if 'X-Static-Large-Object' in source_resp.headers:
                params['multipart-manifest'] = 'put'
            if 'X-Object-Manifest' in source_resp.headers:
                del params['multipart-manifest']
                if 'swift.post_as_copy' not in sink_req.environ:
                    sink_req.headers['X-Object-Manifest'] = \
                        source_resp.headers['X-Object-Manifest']
            sink_req.params = params

        # Set swift.source, data source, content length and etag
        # for the PUT request
        sink_req.environ['swift.source'] = 'SSC'
        sink_req.environ['wsgi.input'] = FileLikeIter(source_resp.app_iter)
        sink_req.content_length = source_resp.content_length
        if (source_resp.status_int == HTTP_OK and
                'X-Static-Large-Object' not in source_resp.headers and
                ('X-Object-Manifest' not in source_resp.headers or
                 req.params.get('multipart-manifest') == 'get')):
            # copy source etag so that copied content is verified, unless:
            #  - not a 200 OK response: source etag may not match the actual
            #    content, for example with a 206 Partial Content response to a
            #    ranged request
            #  - SLO manifest: etag cannot be specified in manifest PUT; SLO
            #    generates its own etag value which may differ from source
            #  - SLO: etag in SLO response is not hash of actual content
            #  - DLO: etag in DLO response is not hash of actual content
            sink_req.headers['Etag'] = source_resp.etag
        else:
            # since we're not copying the source etag, make sure that any
            # container update override values are not copied.
            remove_items(sink_req.headers, lambda k: k.startswith(
                'X-Object-Sysmeta-Container-Update-Override-'))

        # We no longer need these headers
        sink_req.headers.pop('X-Copy-From', None)
        sink_req.headers.pop('X-Copy-From-Account', None)

        # If the copy request does not explicitly override content-type,
        # use the one present in the source object.
        if not req.headers.get('content-type'):
            sink_req.headers['Content-Type'] = \
                source_resp.headers['Content-Type']

        # Create response headers for PUT response
        resp_headers = self._create_response_headers(source_path,
                                                     source_resp, sink_req)

        put_resp = ssc_ctx.send_put_req(sink_req, resp_headers, start_response)
        close_if_possible(source_resp.app_iter)
        return put_resp

    def handle_OPTIONS(self, req, start_response):
        return ServerSideCopyWebContext(self.app, self.logger).\
            handle_OPTIONS_request(req, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def copy_filter(app):
        return ServerSideCopyMiddleware(app, conf)

    return copy_filter
