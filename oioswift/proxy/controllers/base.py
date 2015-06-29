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

import time
import functools
import inspect
from urllib import quote

import os
from swift.common.wsgi import make_pre_authed_env
from swift.common.utils import public, split_path, list_from_csv, Timestamp
from swift.common.http import is_success, HTTP_OK, HTTP_NOT_FOUND, \
    HTTP_UNAUTHORIZED
from swift.common.swob import Request, Response, HeaderKeyDict
from swift.common.request_helpers import strip_sys_meta_prefix, \
    strip_user_meta_prefix, is_user_meta, is_sys_meta, is_sys_or_user_meta
from oiopy import exceptions


def update_headers(response, headers):
    """
    Helper function to update headers in the response.

    :param response: swob.Response object
    :param headers: dictionary headers
    """
    if hasattr(headers, 'items'):
        headers = headers.items()
    for name, value in headers:
        if name == 'etag':
            response.headers[name] = value.replace('"', '')
        elif name not in ('date', 'content-length', 'content-type',
                          'connection', 'x-put-timestamp', 'x-delete-after'):
            response.headers[name] = value


def source_key(resp):
    """
    Provide the timestamp of the swift http response as a floating
    point value.  Used as a sort key.

    :param resp: bufferedhttp response object
    """
    return float(resp.getheader('x-put-timestamp') or
                 resp.getheader('x-timestamp') or 0)


def delay_denial(func):
    """
    Decorator to declare which methods should have any swift.authorize call
    delayed. This is so the method can load the Request object up with
    additional information that may be needed by the authorization system.

    :param func: function for which authorization will be delayed
    """
    func.delay_denial = True

    @functools.wraps(func)
    def wrapped(*a, **kw):
        return func(*a, **kw)

    return wrapped


def get_account_memcache_key(account):
    cache_key, env_key = _get_cache_key(account, None)
    return cache_key


def get_container_memcache_key(account, container):
    if not container:
        raise ValueError("container not provided")
    cache_key, env_key = _get_cache_key(account, container)
    return cache_key


def _prep_headers_to_info(headers, server_type):
    """
    Helper method that iterates once over a dict of headers,
    converting all keys to lower case and separating
    into subsets containing user metadata, system metadata
    and other headers.
    """
    meta = {}
    sysmeta = {}
    other = {}
    for key, val in dict(headers).iteritems():
        lkey = key.lower()
        if is_user_meta(server_type, lkey):
            meta[strip_user_meta_prefix(server_type, lkey)] = val
        elif is_sys_meta(server_type, lkey):
            sysmeta[strip_sys_meta_prefix(server_type, lkey)] = val
        else:
            other[lkey] = val
    return other, meta, sysmeta


def headers_to_account_info(headers, status_int=HTTP_OK):
    """
    Construct a cacheable dict of account info based on response headers.
    """
    headers, meta, sysmeta = _prep_headers_to_info(headers, 'account')
    return {
        'status': status_int,
        # 'container_count' anomaly:
        # Previous code sometimes expects an int sometimes a string
        # Current code aligns to str and None, yet translates to int in
        # deprecated functions as needed
        'container_count': headers.get('x-account-container-count'),
        'total_object_count': headers.get('x-account-object-count'),
        'bytes': headers.get('x-account-bytes-used'),
        'meta': meta,
        'sysmeta': sysmeta
    }


def headers_to_container_info(headers, status_int=HTTP_OK):
    """
    Construct a cacheable dict of container info based on response headers.
    """
    headers, meta, sysmeta = _prep_headers_to_info(headers, 'container')
    return {
        'status': status_int,
        'read_acl': headers.get('x-container-read'),
        'write_acl': headers.get('x-container-write'),
        'sync_key': headers.get('x-container-sync-key'),
        'object_count': headers.get('x-container-object-count'),
        'bytes': headers.get('x-container-bytes-used'),
        'versions': headers.get('x-versions-location'),
        'storage_policy': headers.get('X-Backend-Storage-Policy-Index'.lower(),
                                      '0'),
        'cors': {
            'allow_origin': meta.get('access-control-allow-origin'),
            'expose_headers': meta.get('access-control-expose-headers'),
            'max_age': meta.get('access-control-max-age')
        },
        'meta': meta,
        'sysmeta': sysmeta
    }


def headers_to_object_info(headers, status_int=HTTP_OK):
    """
    Construct a cacheable dict of object info based on response headers.
    """
    headers, meta, sysmeta = _prep_headers_to_info(headers, 'object')
    info = {'status': status_int,
            'length': headers.get('content-length'),
            'type': headers.get('content-type'),
            'etag': headers.get('etag'),
            'meta': meta
    }
    return info


def cors_validation(func):
    """
    Decorator to check if the request is a CORS request and if so, if it's
    valid.

    :param func: function to check
    """

    @functools.wraps(func)
    def wrapped(*a, **kw):
        controller = a[0]
        req = a[1]

        # The logic here was interpreted from
        # http://www.w3.org/TR/cors/#resource-requests

        # Is this a CORS request?
        req_origin = req.headers.get('Origin', None)
        if req_origin:
            # Yes, this is a CORS request so test if the origin is allowed
            container_info = \
                controller.container_info(controller.account_name,
                                          controller.container_name, req)
            cors_info = container_info.get('cors', {})

            # Call through to the decorated method
            resp = func(*a, **kw)

            if controller.app.strict_cors_mode and \
                    not controller.is_origin_allowed(cors_info, req_origin):
                return resp

            # Expose,
            #  - simple response headers,
            #    http://www.w3.org/TR/cors/#simple-response-header
            #  - swift specific: etag, x-timestamp, x-trans-id
            #  - user metadata headers
            #  - headers provided by the user in
            #    x-container-meta-access-control-expose-headers
            if 'Access-Control-Expose-Headers' not in resp.headers:
                expose_headers = [
                    'cache-control', 'content-language', 'content-type',
                    'expires', 'last-modified', 'pragma', 'etag',
                    'x-timestamp', 'x-trans-id']
                for header in resp.headers:
                    if header.startswith('X-Container-Meta') or \
                            header.startswith('X-Object-Meta'):
                        expose_headers.append(header.lower())
                if cors_info.get('expose_headers'):
                    expose_headers.extend(
                        [header_line.strip()
                         for header_line in
                         cors_info['expose_headers'].split(' ')
                         if header_line.strip()])
                resp.headers['Access-Control-Expose-Headers'] = \
                    ', '.join(expose_headers)

            # The user agent won't process the response if the Allow-Origin
            # header isn't included
            if 'Access-Control-Allow-Origin' not in resp.headers:
                if cors_info['allow_origin'] and \
                                cors_info['allow_origin'].strip() == '*':
                    resp.headers['Access-Control-Allow-Origin'] = '*'
                else:
                    resp.headers['Access-Control-Allow-Origin'] = req_origin

            return resp
        else:
            # Not a CORS request so make the call as normal
            return func(*a, **kw)

    return wrapped


def get_object_info(env, app, path=None, swift_source=None):
    """
    Get the info structure for an object, based on env and app.
    This is useful to middlewares.

    .. note::

        This call bypasses auth. Success does not imply that the request has
        authorization to the object.
    """
    (version, account, container, obj) = \
        split_path(path or env['PATH_INFO'], 4, 4, True)
    info = _get_object_info(app, env, account, container, obj,
                            swift_source=swift_source)
    if not info:
        info = headers_to_object_info({}, 0)
    return info


def get_container_info(env, app, swift_source=None):
    """
    Get the info structure for a container, based on env and app.
    This is useful to middlewares.

    .. note::

        This call bypasses auth. Success does not imply that the request has
        authorization to the container.
    """
    (version, account, container, unused) = \
        split_path(env['PATH_INFO'], 3, 4, True)
    info = get_info(app, env, account, container, ret_not_found=True,
                    swift_source=swift_source)
    if not info:
        info = headers_to_container_info({}, 0)
    info.setdefault('storage_policy', '0')
    return info


def get_account_info(env, app, swift_source=None):
    """
    Get the info structure for an account, based on env and app.
    This is useful to middlewares.

    .. note::

        This call bypasses auth. Success does not imply that the request has
        authorization to the account.
    """
    (version, account, _junk, _junk) = \
        split_path(env['PATH_INFO'], 2, 4, True)
    info = get_info(app, env, account, ret_not_found=True,
                    swift_source=swift_source)
    if not info:
        info = headers_to_account_info({}, 0)
    if info.get('container_count') is None:
        info['container_count'] = 0
    else:
        info['container_count'] = int(info['container_count'])
    return info


def _get_cache_key(account, container):
    """
    Get the keys for both memcache (cache_key) and env (env_key)
    where info about accounts and containers is cached
    :param   account: The name of the account
    :param container: The name of the container (or None if account)
    :returns a tuple of (cache_key, env_key)
    """

    if container:
        cache_key = 'container/%s/%s' % (account, container)
    else:
        cache_key = 'account/%s' % account
    # Use a unique environment cache key per account and one container.
    # This allows caching both account and container and ensures that when we
    # copy this env to form a new request, it won't accidentally reuse the
    # old container or account info
    env_key = 'swift.%s' % cache_key
    return cache_key, env_key


def get_object_env_key(account, container, obj):
    """
    Get the keys for env (env_key) where info about object is cached
    :param   account: The name of the account
    :param container: The name of the container
    :param obj: The name of the object
    :returns a string env_key
    """
    env_key = 'swift.object/%s/%s/%s' % (account,
                                         container, obj)
    return env_key


def _set_info_cache(app, env, account, container, resp):
    """
    Cache info in both memcache and env.

    Caching is used to avoid unnecessary calls to account & container servers.
    This is a private function that is being called by GETorHEAD_base and
    by clear_info_cache.
    Any attempt to GET or HEAD from the container/account server should use
    the GETorHEAD_base interface which would than set the cache.

    :param  app: the application object
    :param  account: the unquoted account name
    :param  container: the unquoted container name or None
    :param resp: the response received or None if info cache should be cleared
    """

    if container:
        cache_time = app.recheck_container_existence
    else:
        cache_time = app.recheck_account_existence
    cache_key, env_key = _get_cache_key(account, container)

    if resp:
        if resp.status_int == HTTP_NOT_FOUND:
            cache_time *= 0.1
        elif not is_success(resp.status_int):
            cache_time = None
    else:
        cache_time = None

    # Next actually set both memcache and the env cache
    memcache = getattr(app, 'memcache', None) or env.get('swift.cache')
    if not cache_time:
        env.pop(env_key, None)
        if memcache:
            memcache.delete(cache_key)
        return

    if container:
        info = headers_to_container_info(resp.headers, resp.status_int)
    else:
        info = headers_to_account_info(resp.headers, resp.status_int)
    if memcache:
        memcache.set(cache_key, info, time=cache_time)
    env[env_key] = info


def _set_object_info_cache(app, env, account, container, obj, resp):
    """
    Cache object info env. Do not cache object informations in
    memcache. This is an intentional omission as it would lead
    to cache pressure. This is a per-request cache.

    Caching is used to avoid unnecessary calls to object servers.
    This is a private function that is being called by GETorHEAD_base.
    Any attempt to GET or HEAD from the object server should use
    the GETorHEAD_base interface which would then set the cache.

    :param  app: the application object
    :param  account: the unquoted account name
    :param  container: the unquoted container name or None
    :param  object: the unquoted object name or None
    :param resp: the response received or None if info cache should be cleared
    """

    env_key = get_object_env_key(account, container, obj)

    if not resp:
        env.pop(env_key, None)
        return

    info = headers_to_object_info(resp.headers, resp.status_int)
    env[env_key] = info


def clear_info_cache(app, env, account, container=None):
    """
    Clear the cached info in both memcache and env

    :param  app: the application object
    :param  account: the account name
    :param  container: the containr name or None if setting info for containers
    """
    _set_info_cache(app, env, account, container, None)


def _get_info_cache(app, env, account, container=None):
    """
    Get the cached info from env or memcache (if used) in that order
    Used for both account and container info
    A private function used by get_info

    :param  app: the application object
    :param  env: the environment used by the current request
    :returns the cached info or None if not cached
    """

    cache_key, env_key = _get_cache_key(account, container)
    if env_key in env:
        return env[env_key]
    memcache = getattr(app, 'memcache', None) or env.get('swift.cache')
    if memcache:
        info = memcache.get(cache_key)
        if info:
            for key in info:
                if isinstance(info[key], unicode):
                    info[key] = info[key].encode("utf-8")
            env[env_key] = info
        return info
    return None


def _prepare_pre_auth_info_request(env, path, swift_source):
    """
    Prepares a pre authed request to obtain info using a HEAD.

    :param env: the environment used by the current request
    :param path: The unquoted request path
    :param swift_source: value for swift.source in WSGI environment
    :returns: the pre authed request
    """
    # Set the env for the pre_authed call without a query string
    newenv = make_pre_authed_env(env, 'HEAD', path, agent='Swift',
                                 query_string='', swift_source=swift_source)
    # This is a sub request for container metadata- drop the Origin header from
    # the request so the it is not treated as a CORS request.
    newenv.pop('HTTP_ORIGIN', None)
    # Note that Request.blank expects quoted path
    return Request.blank(quote(path), environ=newenv)


def get_info(app, env, account, container=None, ret_not_found=False,
             swift_source=None):
    """
    Get the info about accounts or containers

    Note: This call bypasses auth. Success does not imply that the
          request has authorization to the info.

    :param app: the application object
    :param env: the environment used by the current request
    :param account: The unquoted name of the account
    :param container: The unquoted name of the container (or None if account)
    :returns: the cached info or None if cannot be retrieved
    """
    info = _get_info_cache(app, env, account, container)
    if info:
        if ret_not_found or is_success(info['status']):
            return info
        return None
    # Not in cache, let's try the account servers
    path = '/v1/%s' % account
    if container:
        # Stop and check if we have an account?
        if not get_info(app, env, account) and not account.startswith(
                getattr(app, 'auto_create_account_prefix', '.')):
            return None
        path += '/' + container

    req = _prepare_pre_auth_info_request(
        env, path, (swift_source or 'GET_INFO'))
    # Whenever we do a GET/HEAD, the GETorHEAD_base will set the info in
    # the environment under environ[env_key] and in memcache. We will
    # pick the one from environ[env_key] and use it to set the caller env
    resp = req.get_response(app)
    cache_key, env_key = _get_cache_key(account, container)
    try:
        info = resp.environ[env_key]
        env[env_key] = info
        if ret_not_found or is_success(info['status']):
            return info
    except (KeyError, AttributeError):
        pass
    return None


def _get_object_info(app, env, account, container, obj, swift_source=None):
    """
    Get the info about object

    Note: This call bypasses auth. Success does not imply that the
          request has authorization to the info.

    :param app: the application object
    :param env: the environment used by the current request
    :param account: The unquoted name of the account
    :param container: The unquoted name of the container
    :param obj: The unquoted name of the object
    :returns: the cached info or None if cannot be retrieved
    """
    env_key = get_object_env_key(account, container, obj)
    info = env.get(env_key)
    if info:
        return info
    # Not in cached, let's try the object servers
    path = '/v1/%s/%s/%s' % (account, container, obj)
    req = _prepare_pre_auth_info_request(env, path, swift_source)
    # Whenever we do a GET/HEAD, the GETorHEAD_base will set the info in
    # the environment under environ[env_key]. We will
    # pick the one from environ[env_key] and use it to set the caller env
    resp = req.get_response(app)
    try:
        info = resp.environ[env_key]
        env[env_key] = info
        return info
    except (KeyError, AttributeError):
        pass
    return None


class Controller(object):
    """Base WSGI controller class for the proxy"""
    server_type = 'Base'

    # Ensure these are all lowercase
    pass_through_headers = []

    def __init__(self, app):
        """
        Creates a controller attached to an application instance

        :param app: the application instance
        """
        self.account_name = None
        self.app = app
        self.trans_id = '-'
        self._allowed_methods = None

    @property
    def allowed_methods(self):
        if self._allowed_methods is None:
            self._allowed_methods = set()
            all_methods = inspect.getmembers(self, predicate=inspect.ismethod)
            for name, m in all_methods:
                if getattr(m, 'publicly_accessible', False):
                    self._allowed_methods.add(name)
        return self._allowed_methods

    def _x_remove_headers(self):
        """
        Returns a list of headers that must not be sent to the backend

        :returns: a list of header
        """
        return []

    def transfer_headers(self, src_headers, dst_headers):
        """
        Transfer legal headers from an original client request to dictionary
        that will be used as headers by the backend request

        :param src_headers: A dictionary of the original client request headers
        :param dst_headers: A dictionary of the backend request headers
        """
        st = self.server_type.lower()

        x_remove = 'x-remove-%s-meta-' % st
        dst_headers.update((k.lower().replace('-remove', '', 1), '')
                           for k in src_headers
                           if k.lower().startswith(x_remove) or
                           k.lower() in self._x_remove_headers())

        dst_headers.update((k.lower(), v)
                           for k, v in src_headers.iteritems()
                           if k.lower() in self.pass_through_headers or
                           is_sys_or_user_meta(st, k))

    def generate_request_headers(self, orig_req=None, additional=None,
                                 transfer=False):
        """
        Create a list of headers to be used in backend requets
        :param orig_req: the original request sent by the client to the proxy
        :param additional: additional headers to send to the backend
        :param transfer: If True, transfer headers from original client request
        :returns: a dictionary of headers
        """
        # Use the additional headers first so they don't overwrite the headers
        # we require.
        headers = HeaderKeyDict(additional) if additional else HeaderKeyDict()
        if transfer:
            self.transfer_headers(orig_req.headers, headers)
        headers.setdefault('x-timestamp', Timestamp(time.time()).internal)
        if orig_req:
            referer = orig_req.as_referer()
        else:
            referer = ''
        headers['x-trans-id'] = self.trans_id
        headers['connection'] = 'close'
        headers['user-agent'] = 'proxy-server %s' % os.getpid()
        headers['referer'] = referer
        return headers

    def account_info(self, account, req=None):
        """
        Get account information, and also verify that the account exists.

        :param account: name of the account to get the info for
        :param req: caller's HTTP request context object (optional)
        :returns: container_count or None if it does not exist
        """
        if req:
            env = getattr(req, 'environ', {})
        else:
            env = {}
        info = get_info(self.app, env, account)
        if not info:
            return None
        if info.get('container_count') is None:
            container_count = 0
        else:
            container_count = int(info['container_count'])
        return container_count

    def container_info(self, account, container, req=None):
        """
        Get container information and thusly verify container existence.
        This will also verify account existence.

        :param account: account name for the container
        :param container: container name to look up
        :param req: caller's HTTP request context object (optional)
        :returns: dict containing at least container read
                  acl ('read_acl'), container write acl ('write_acl'),
                  and container sync key ('sync_key').
                  Values are set to None if the container does not exist.
        """
        if req:
            env = getattr(req, 'environ', {})
        else:
            env = {}
        info = get_info(self.app, env, account, container)
        if not info:
            info = headers_to_container_info({}, 0)
        else:
            info.setdefault('storage_policy', '0')
        return info

    def is_origin_allowed(self, cors_info, origin):
        """
        Is the given Origin allowed to make requests to this resource

        :param cors_info: the resource's CORS related metadata headers
        :param origin: the origin making the request
        :return: True or False
        """
        allowed_origins = set()
        if cors_info.get('allow_origin'):
            allowed_origins.update(
                [a.strip()
                 for a in cors_info['allow_origin'].split(' ')
                 if a.strip()])
        if self.app.cors_allow_origin:
            allowed_origins.update(self.app.cors_allow_origin)
        return origin in allowed_origins or '*' in allowed_origins

    @public
    def GET(self, req):
        """
        Handler for HTTP GET requests.
        :param req: The client request
        :returns: the response to the client
        """
        return self.GETorHEAD(req)

    @public
    def HEAD(self, req):
        """
        Handler for HTTP HEAD requests.
        :param req: The client request
        :returns: the response to the client
        """
        return self.GETorHEAD(req)

    def autocreate_account(self, req, account):
        try:
            self.app.storage.account_create(account)
            self.app.logger.info('autocreate account %r' % account)
            clear_info_cache(self.app, req.environ, account)
        except exceptions.OioException:
            self.app.logger.warning('Could not autocreate account %r' % account)

    @public
    def OPTIONS(self, req):
        """
        Base handler for OPTIONS requests

        :param req: swob.Request object
        :returns: swob.Response object
        """
        # Prepare the default response
        headers = {'Allow': ', '.join(self.allowed_methods)}
        resp = Response(status=200, request=req, headers=headers)

        # If this isn't a CORS pre-flight request then return now
        req_origin_value = req.headers.get('Origin', None)
        if not req_origin_value:
            return resp

        # This is a CORS preflight request so check it's allowed
        try:
            container_info = \
                self.container_info(self.account_name,
                                    self.container_name, req)
        except AttributeError:
            # This should only happen for requests to the Account. A future
            # change could allow CORS requests to the Account level as well.
            return resp

        cors = container_info.get('cors', {})

        # If the CORS origin isn't allowed return a 401
        if not self.is_origin_allowed(cors, req_origin_value) or (
                    req.headers.get('Access-Control-Request-Method') not in
                    self.allowed_methods):
            resp.status = HTTP_UNAUTHORIZED
            return resp

        # Allow all headers requested in the request. The CORS
        # specification does leave the door open for this, as mentioned in
        # http://www.w3.org/TR/cors/#resource-preflight-requests
        # Note: Since the list of headers can be unbounded
        # simply returning headers can be enough.
        allow_headers = set()
        if req.headers.get('Access-Control-Request-Headers'):
            allow_headers.update(
                list_from_csv(req.headers['Access-Control-Request-Headers']))

        # Populate the response with the CORS preflight headers
        if cors.get('allow_origin', '').strip() == '*':
            headers['access-control-allow-origin'] = '*'
        else:
            headers['access-control-allow-origin'] = req_origin_value
        if cors.get('max_age') is not None:
            headers['access-control-max-age'] = cors.get('max_age')
        headers['access-control-allow-methods'] = \
            ', '.join(self.allowed_methods)
        if allow_headers:
            headers['access-control-allow-headers'] = ', '.join(allow_headers)
        resp.headers = headers

        return resp
