# Copyright (C) 2018 OpenIO SAS
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
import importlib
from paste.deploy import loadwsgi
from six.moves.urllib.parse import parse_qs, quote_plus
from swift.common.swob import Request
from swift.common.utils import config_true_value, \
    closing_if_possible, get_logger
from swift.common.wsgi import make_subrequest, loadcontext, PipelineWrapper
from oioswift.common.middleware.autocontainerbase import AutoContainerBase
from oio.common.exceptions import ConfigurationException

LOG = None
MIDDLEWARE_NAME = 'container_sharding'
DEFAULT_LIMIT = 10000

OBJ = 'obj'  # redis key represent a real empty object that ends with /
CNT = 'cnt'  # redis key show a redirection to a container


class RedisDb(object):
    def __init__(self, redis_host=None,
                 sentinel_hosts=None, sentinel_name=None):
        self.__redis_mod = importlib.import_module('redis')
        self.__redis_sentinel_mod = importlib.import_module('redis.sentinel')
        self._sentinel_hosts = None
        self._sentinel = None
        self._conn = None

        if redis_host:
            self._redis_host, self._redis_port = redis_host.rsplit(':', 1)
            self._redis_port = int(self._redis_port)
            return

        if not sentinel_name:
            raise ValueError("missing parameter 'sentinel_name'")

        if isinstance(sentinel_hosts, basestring):
            sentinel_hosts = sentinel_hosts.split(',')
        self._sentinel_hosts = [(h, int(p)) for h, p, in (hp.split(':', 2)
                                for hp in sentinel_hosts.split(','))]
        self._master_name = sentinel_name

        self._sentinel = self.__redis_sentinel_mod.Sentinel(
            self._sentinel_hosts)

    @property
    def conn(self):
        if self._sentinel:
            return self._sentinel.master_for(self._master_name)
        if not self._conn:
            self._conn = self.__redis_mod.StrictRedis(host=self._redis_host,
                                                      port=self._redis_port)
        return self._conn

    def set(self, key, val):
        return self.conn.set(key, val)

    def delete(self, key):
        return self.conn.delete(key)

    def keys(self, pattern):
        return self.conn.scan_iter(pattern)


class FakeRedis(object):
    """Fake Redis stubb for unit test"""
    def __init__(self):
        LOG.warn("**FakeRedis stub in use **")
        self._keys = {}

    def set(self, key, val):
        self._keys[key] = val

    def delete(self, key):
        self._keys.pop(key, None)

    def keys(self, pattern):
        raise NotImplemented()


class ContainerShardingMiddleware(AutoContainerBase):
    """
    Middleware that will spawn a container for each level of object path.
    """

    DELIMITER = '/'
    ENCODED_DELIMITER = '%2F'
    SWIFT_SOURCE = 'SHARD'
    PREFIX = 'CS:'

    def __init__(self, app, conf, acct, **kwargs):
        redis_host = kwargs.pop('redis_host', None)
        sentinel_hosts = kwargs.pop('sentinel_hosts', None)
        sentinel_name = kwargs.pop('sentinel_name', None)

        super(ContainerShardingMiddleware, self).__init__(
            app, acct, **kwargs)
        LOG.debug(self.SWIFT_SOURCE)
        self.check_pipeline(conf)

        if redis_host or sentinel_hosts:
            self.conn = RedisDb(
                redis_host=redis_host,
                sentinel_hosts=sentinel_hosts,
                sentinel_name=sentinel_name)
        else:
            self.conn = FakeRedis()

    def check_pipeline(self, conf):
        """
        Check that proxy-server.conf has an appropriate pipeline
        for container_sharding
        """
        if conf.get('__file__', None) is None:
            return

        ctx = loadcontext(loadwsgi.APP, conf['__file__'])
        pipeline = str(PipelineWrapper(ctx)).split(' ')

        if 'swift3' in pipeline and not all((self.account_first,
                                             self.strip_v1,
                                             self.swift3_compat)):
            LOG.warn('account_first, strip_v1 and swift3_compat options '
                     'must be enabled when using %s along with swift3',
                     MIDDLEWARE_NAME)

        auth_index = -1
        if 'tempauth' in pipeline:
            LOG.debug('Use tempauth middleware.')
            auth_index = pipeline.index('tempauth')
        elif 'keystoneauth' in pipeline:
            LOG.debug('Use keystone middleware.')
            auth_index = pipeline.index('keystoneauth')
        if pipeline.index(MIDDLEWARE_NAME) < auth_index:
            raise ValueError(
                'Invalid pipeline %r: %s must be placed after authentication'
                % (pipeline, MIDDLEWARE_NAME))

        if ('slo' in pipeline and
                pipeline.index(MIDDLEWARE_NAME) < pipeline.index('slo')):
            raise ValueError(
                'Invalid pipeline %r: %s must be placed after SLO'
                % (pipeline, MIDDLEWARE_NAME))

    def key(self, account, container, mode, path=None):
        """returns Redis key"""
        ret = self.PREFIX + account + ":" + container + ":"
        if mode:
            ret += mode + ":"
            if path:
                ret += path
        return ret

    def _create_key(self, req, account, container, mode, path):
        key = self.key(account, container, mode, path)
        LOG.debug("%s: create key %s", self.SWIFT_SOURCE, key)
        # TODO: should we increase number of objects ?
        # but we should manage in this case all error case
        # to avoid false counter
        res = self.conn.set(key, "1")
        if not res:
            LOG.warn("%s: failed to create key %s", self.SWIFT_SOURCE, key)

    def _remove_key(self, req, account, container, mode, path):
        key = self.key(account, container, mode, path)
        if mode == CNT:
            # remove container key only if empty
            empty = not any(self._list_objects(
                            req.environ.copy(),
                            account,
                            [container] + path.split('/')[:-1],
                            None,
                            limit=1))

            if not empty:
                return

        LOG.debug("%s: remove key %s (key %s)", self.SWIFT_SOURCE, path, key)
        res = self.conn.delete(key)
        if not res:
            LOG.warn("%s: failed to remove key %s", self.SWIFT_SOURCE, key)

    def _build_object_listing(self, start_response, env,
                              account, container, prefix,
                              limit=None,
                              recursive=False, marker=None):

        LOG.debug("%s: listing with %s %s %s %s %s %s",
                  self.SWIFT_SOURCE, account, container, prefix, limit,
                  recursive, marker)

        def header_cb(header_dict):
            oheaders.update(header_dict)

        oheaders = dict()
        all_objs = []

        prefix = prefix[0]

        # have we to parse root container ?
        # / must be absent from prefix AND marker
        parse_root = self.DELIMITER not in prefix and \
            (not marker or self.DELIMITER not in marker)
        LOG.debug("%s: parse root container ? %s",
                  self.SWIFT_SOURCE, parse_root)

        prefix_key = self.key(account, container, "")
        key = self.key(account, container, '*', prefix) + '*'
        matches = [k[len(prefix_key):].split(':', 2)
                   for k in self.conn.keys(key)]

        LOG.debug("SHARD: prefix %s / matches: %s", prefix_key, matches)

        if parse_root:
            matches.append((CNT, ""))

        # if prefix is something like dir1/dir2/dir3/ob
        if not prefix.endswith(self.DELIMITER) and self.DELIMITER in prefix:
            pfx = prefix[:prefix.rindex(self.DELIMITER)+1]
            key = self.key(account, container, CNT, pfx)
            if self.conn.exists(key):
                # then we must append dir1/dir2/dir3/ to be able to retrieve
                # object1 and object2 from this container
                matches.append(key[len(prefix_key):])

        # we should ignore all keys that are before marker to
        # avoid useless lookup or false listing
        if marker:
            m = matches
            marker_ = marker[:marker.rindex('/')] + '/'
            LOG.debug("%s: convert marker %s to %s",
                      self.SWIFT_SOURCE, marker, marker_)
            matches = []
            for mode, entry in m:
                if entry < marker_:
                    LOG.debug("%s: marker ignore %s: before)",
                              self.SWIFT_SOURCE, entry)
                    continue
                if entry == marker_ and not recursive:
                    # marker is something like d1/ but we d1/d2/d3/ key
                    LOG.debug("%s: marker ignore %s: not recursive",
                              self.SWIFT_SOURCE, entry)
                    continue
                if mode == OBJ and entry == marker_:
                    LOG.debug("%s: marker ignore %s: skip object",
                              self.SWIFT_SOURCE, entry, marker_)
                    continue
                matches.append((mode, entry))
        matches.sort()

        already_done = set()

        len_pfx = len(prefix)
        cnt_delimiter = len(prefix.split('/'))

        for mode, entry in matches:
            if self.DELIMITER in entry[len_pfx:] and not recursive:
                # append subdir entry, no difference between CNT and OBJ
                subdir = '/'.join(entry.split("/")[:cnt_delimiter]) + '/'
                if subdir in already_done:
                    continue

                already_done.add(subdir)
                all_objs.append({
                        'subdir': subdir
                })
            else:
                _prefix = ''
                if len(entry) < len(prefix):
                    _prefix = prefix[len(entry):]

                # transmit marker only to exact container
                # otherwise we will have incorrect listings
                _marker = None
                if marker and entry.rstrip('/') == marker[:marker.rindex('/')]:
                    _marker = marker[marker.rindex('/'):].lstrip('/')
                    LOG.debug("%s: convert marker %s to %s",
                              self.SWIFT_SOURCE, marker, _marker)

                if mode == "obj":
                    ret = [{'name': entry,
                            'bytes': 0,
                            'hash': '"d41d8cd98f00b204e9800998ecf8427e"',
                            'last_modified': '1970-01-01T00:00:00.000000'}]

                elif entry:
                    ret = self._list_objects(
                        env, account,
                        [container] + entry.strip('/').split('/'), header_cb,
                        _prefix, limit=DEFAULT_LIMIT, marker=_marker)
                else:
                    # manage root container
                    # TODO: rewrite condition
                    ret = self._list_objects(
                        env, account,
                        [container], header_cb, _prefix, limit=DEFAULT_LIMIT,
                        marker=_marker)
                for x in ret:
                    all_objs.append(x)

            # it suppose to have proper order but it will help a lot !
            # quick test with page-size 2 to list 10 directories with 10 objets
            # with break: 2.1s vs without break 3.8s
            if len(all_objs) > limit:
                break

        LOG.debug("%s: got %d items / limit was %d", self.SWIFT_SOURCE,
                  len(all_objs), limit)
        all_objs = sorted(all_objs,
                          key=lambda entry: entry.get('name',
                                                      entry.get('subdir')))
        body = json.dumps(all_objs)

        oheaders['Content-Length'] = len(body)
        start_response("200 OK", oheaders.items())

        return [body]

    def _fake_container_and_obj(self, container, obj_parts, is_listing=False):
        """
        Aggregate object parts (except the last) into the container name.

        :returns: container name and object name
        """
        if len(obj_parts) > 1 and not obj_parts[-1] and not is_listing:
            container = self.ENCODED_DELIMITER.join(
                [container] + obj_parts[:-2])
            obj = obj_parts[-2] + self.DELIMITER
        else:
            container = self.ENCODED_DELIMITER.join(
                [container] + obj_parts[:-1])
            obj = obj_parts[-1] if obj_parts else ''
        return container, obj

    def _list_objects(self, env, account, ct_parts, header_cb,
                      prefix='', limit=DEFAULT_LIMIT,
                      marker=None):
        """
        returns items
        """
        sub_path = quote_plus(self.DELIMITER.join(
            ('', 'v1', account, self.ENCODED_DELIMITER.join(ct_parts))))
        LOG.debug("%s: listing objects from '%s' "
                  "(limit=%d, prefix=%s, marker=%s)",
                  self.SWIFT_SOURCE, sub_path, limit, prefix, marker)
        sub_req = make_subrequest(env.copy(), method='GET', path=sub_path,
                                  body='',
                                  swift_source=self.SWIFT_SOURCE)
        params = sub_req.params
        params['delimiter'] = self.DELIMITER
        params['limit'] = str(limit)  # FIXME: why is it str?
        params['prefix'] = prefix
        params['format'] = 'json'
        if marker:
            params['marker'] = marker
        sub_req.params = params
        resp = sub_req.get_response(self.app)
        obj_prefix = ''
        if len(ct_parts) > 1:
            obj_prefix = self.DELIMITER.join(ct_parts[1:] + ['', ])

        if not resp.is_success or resp.content_length == 0:
            LOG.warn("%s: Failed to list %s",
                     self.SWIFT_SOURCE, sub_path)
            return
        with closing_if_possible(resp.app_iter):
            items = json.loads(resp.body)
        if header_cb:
            header_cb(resp.headers)

        for obj in items:
            if 'name' in obj:
                obj['name'] = obj_prefix + obj['name']
                yield obj

    def should_bypass(self, env):
        # Pre authentication from swift3
        return (env.get('REQUEST_METHOD') == 'TEST' or
                super(ContainerShardingMiddleware, self).should_bypass(env))

    def __call__(self, env, start_response):
        if self.should_bypass(env):
            return self.app(env, start_response)

        req = Request(env)

        account, container, obj = self._extract_path(req.path_info)
        # allow global listing on account
        if container is None:
            return self.app(env, start_response)

        env2 = env.copy()
        qs = parse_qs(req.query_string or '')
        prefix = qs.get('prefix')  # returns a list or None
        if not prefix:
            prefix = ['']
        marker = qs.get('marker')
        limit = qs.get('limit')
        LOG.debug("%s: Got %s request for container=%s, "
                  "obj=%s, prefix=%s marker=%s",
                  self.SWIFT_SOURCE, req.method, container, obj, prefix,
                  marker)
        must_recurse = False

        if 'Oio-Copy-From' in req.headers and req.method == 'PUT':
            _, c_container, c_obj = req.headers['Oio-Copy-From'].split('/', 2)
            c_container, c_obj = \
                self._fake_container_and_obj(c_container, c_obj.split('/'))
            # update Headers
            req.headers['Oio-Copy-From'] = '/' + c_container + '/' + c_obj
            env2['HTTP_OIO_COPY_FROM'] = '/' + c_container + '/' + c_obj

        if obj is None:
            LOG.debug("%s: -> is a listing request", self.SWIFT_SOURCE)
            must_recurse = req.method == 'GET' and 'delimiter' not in qs
            if not marker:
                marker = None
            else:
                marker = marker[0]
            if not limit:
                limit = DEFAULT_LIMIT
            else:
                limit = int(limit[0])
            container2 = container
            obj2 = obj
        else:
            LOG.debug("%s: -> is NOT listing request", self.SWIFT_SOURCE)
            obj_parts = obj.split(self.DELIMITER)
            if len(obj_parts) > 1:
                path = self.DELIMITER.join(obj_parts[:-1]) + self.DELIMITER
                is_dir = obj.endswith('/')
                # TODO (MBO) we should accept create key d1/d2/ only
                # for empty object
                if req.method == 'PUT':
                    LOG.error("SHARD: CREATE MARKER FOR %s => is_dir %s",
                              obj, obj.endswith('/'))
                    self._create_key(req, account, container,
                                     OBJ if is_dir else CNT, path)
                    if is_dir:
                        oheaders = {'Content-Length': 0,
                                    'Etag': 'd41d8cd98f00b204e9800998ecf8427e'}
                        start_response("201 Created", oheaders.items())
                        return ['']

                elif req.method == 'DELETE' and is_dir:
                    self._remove_key(req, account, container, OBJ, path)
                    oheaders = {'Content-Length': 0,
                                'Etag': 'd41d8cd98f00b204e9800998ecf8427e'}
                    start_response("204 No Content", oheaders.items())
                    return ['']

            container2, obj2 = self._fake_container_and_obj(container,
                                                            obj_parts)

        LOG.debug("%s: Converted to container=%s, obj=%s, qs=%s",
                  self.SWIFT_SOURCE, container2, obj2, qs)
        if must_recurse:
            res = self._build_object_listing(start_response, env,
                                             account, container2, prefix,
                                             limit=limit, recursive=True,
                                             marker=marker)
        elif qs.get('prefix') or qs.get('delimiter'):
            res = self._build_object_listing(start_response, env,
                                             account, container2, prefix,
                                             limit=limit,
                                             recursive=False, marker=marker)
        else:
            # should be other operation that listing
            if obj:
                env2['PATH_INFO'] = "/v1/%s/%s/%s" % (account, container2,
                                                      obj2)
            else:
                env2['PATH_INFO'] = "/v1/%s/%s" % (account, container2)
            res = self.app(env2, start_response)

            if req.method == 'DELETE' and res == '':
                # only remove marker if everything is ok
                self._remove_marker(req, account, container, CNT, path)
        return res


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)
    global LOG
    LOG = get_logger(conf)
    LOG.warn('%s middleware is proof-of-concept '
             'and not suitable for production use!',
             MIDDLEWARE_NAME)

    acct = conf.get('sds_default_account')

    if acct is None:
        raise ConfigurationException('No OIO-SDS account configured')

    account_first = config_true_value(local_config.get('account_first'))
    swift3_compat = config_true_value(local_config.get('swift3_compat'))
    strip_v1 = config_true_value(local_config.get('strip_v1'))
    redis_host = local_config.get('redis_host')
    sentinel_hosts = local_config.get('sentinel_hosts')
    sentinel_name = local_config.get('sentinel_name')

    def factory(app):
        return ContainerShardingMiddleware(
            app, global_conf, acct,
            strip_v1=strip_v1,
            account_first=account_first,
            swift3_compat=swift3_compat,
            redis_host=redis_host,
            sentinel_hosts=sentinel_hosts,
            sentinel_name=sentinel_name)
    return factory
