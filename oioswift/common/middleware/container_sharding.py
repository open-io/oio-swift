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
from six.moves.urllib.parse import parse_qs, quote_plus, urlencode
from swift.common.swob import Request
from swift.common.http import HTTP_PRECONDITION_FAILED
from swift.common.utils import config_true_value, close_if_possible, \
    closing_if_possible, get_logger
from swift.common.wsgi import make_subrequest, loadcontext, PipelineWrapper
from oioswift.common.middleware.autocontainerbase import AutoContainerBase
from oio.common.exceptions import ConfigurationException

LOG = None
MIDDLEWARE_NAME = 'container_sharding'
DEFAULT_LIMIT = 10000


class ContainerShardingMiddleware(AutoContainerBase):
    """
    Middleware that will spawn a container for each level of object path.
    """

    DELIMITER = '/'
    ENCODED_DELIMITER = '%2F'
    SWIFT_SOURCE = 'SHARD'

    def __init__(self, app, conf, acct, **kwargs):
        super(ContainerShardingMiddleware, self).__init__(
            app, acct, **kwargs)
        LOG.debug(self.SWIFT_SOURCE)
        self.check_pipeline(conf)

        #
        self.__redis_mod = importlib.import_module('redis')
        self.__redis_sentinel_mod = importlib.import_module('redis.sentinel')

        host = "127.0.0.1:6379"
        prefix = "swiftsharding:"
        self._redis_host, self._redis_port = host.rsplit(':', 1)
        self._redis_port = int(self._redis_port)
        self._prefix = prefix
        sentinel_hosts = None
        master_name = ""
        if isinstance(sentinel_hosts, basestring):
            self._sentinel_hosts = [(h, int(p)) for h, p, in (hp.split(':', 2)
                                    for hp in sentinel_hosts.split(','))]
        else:
            self._sentinel_hosts = sentinel_hosts
        if self._sentinel_hosts and not master_name:
            raise ValueError("missing parameter 'master_name'")
        self._master_name = master_name

        self._conn = None
        self._sentinel = None

        if self._sentinel_hosts:
            self._sentinel = self.__redis_sentinel_mod.Sentinel(
                self._sentinel_hosts)

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

    @property
    def conn(self):
        if self._sentinel:
            return self._sentinel.master_for(self._master_name)
        if not self._conn:
            self._conn = self.__redis_mod.StrictRedis(host=self._redis_host,
                                                      port=self._redis_port)
        return self._conn

    def key(self, account, container, path):
        return self._prefix + account + ":" + container + ":" + path

    def _create_dir_marker(self, req, account, container, path):
        key = self.key(account, container, path)
        LOG.debug("%s: create key %s", self.SWIFT_SOURCE, key)
        # should we increase number of objects ?
        # but we should manage in this case all error case
        # to avoid false counter
        res = self.conn.set(key, "1")
        assert res
        return res

    def _remove_dir_marker(self, req, account, container, path):
        # and decrease it here ?
        key = self.key(account, container, path)
        LOG.debug("%s: should remove path %s (key %s)",
            self.SWIFT_SOURCE, path, key)
        # key = self.key(account, container, path)
        # res = self.conn.delete(key)
        empty = not any(self._list_objects(
                        req.environ.copy(),
                        account,
                        [container] + path.split('/')[:-1],
                        None,
                        limit=1))


        print("SHARD is empty ?", empty)
        if empty:
            key = self.key(account, container, path)
            res = self.conn.delete(key)

    def _can_delete_dir_marker(self, req, account, container, obj):
        """
        Check if an entry redis can be deleted:
        the sub-container must be empty.
        """

        container2 = container + self.ENCODED_DELIMITER + obj[:-1]
        LOG.debug("%s: checking if '%s' is empty",
                  self.SWIFT_SOURCE, container2)
        # Check if there is any object (or placeholder) before
        # accepting deletion.
        empty = not any(self._list_objects(
                        req.environ.copy(),
                        account,
                        tuple(container2.split(self.ENCODED_DELIMITER)),
                        None,
                        limit=1))
        return empty

    def _build_empty_response(self, start_response, status='200 OK'):
        """Build a response with no body and the specified status."""
        oheaders = {'Content-Length': 0}
        start_response(status, oheaders.items())
        return []  # empty body

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
        LOG.warn("%s: prefix=> '%s'", self.SWIFT_SOURCE, prefix)
        LOG.warn("%s: marker=> '%s'", self.SWIFT_SOURCE, marker)
        parse_root = self.DELIMITER not in prefix and (not marker or self.DELIMITER not in marker)
        print(self.SWIFT_SOURCE, "should we parse root container ?", parse_root)

        prefix_key = self.key(account, container, '')
        key = self.key(account, container, prefix) + '*'
        print("key => ", key)
        matches = [k[len(prefix_key):] for k in self.conn.keys(key)]

        if parse_root:
            matches.append("")

        # if prefix is something like dir1/dir2/dir3/ob
        if not prefix.endswith(self.DELIMITER) and self.DELIMITER in prefix:
            pfx = prefix[:prefix.rindex(self.DELIMITER)+1]
            key = self.key(account, container, pfx)
            if self.conn.exists(key):
                # then we must append dir1/dir2/dir3/
                # to be able to retrieve object1 and object2 from this container
                matches.append(key[len(prefix_key):])

        # =>
        if marker:
            # we should ignore all keys that are before marker to
            # avoid useles lookup
            m = matches
            # not sure if it is necessary
            marker_ = marker[:marker.rindex('/')] + '/'
            LOG.warn("%s: marker %s to %s", self.SWIFT_SOURCE, marker, marker_)
            matches = []
            for entry in m:
                if entry < marker_:
                    LOG.warn("%s: ignore %s (before marker %s)", self.SWIFT_SOURCE, entry, marker_)
                    continue
                if entry == marker_ and not recursive:
                    continue
                matches.append(entry)

        already_done = set()

        len_pfx = len(prefix)
        cnt_delimiter = len(prefix.split('/'))
        print(self.SWIFT_SOURCE, "cnt_delimiter", cnt_delimiter)
        print(self.SWIFT_SOURCE, "we should parse", ' '.join(matches))

        for entry in matches:
            # print(self.SWIFT_SOURCE, "Checking", entry)
            if self.DELIMITER in entry[len_pfx:] and not recursive:
                # append subdir entry
                # all_objs.append(
                subdir = '/'.join(entry.split("/")[:cnt_delimiter]) + '/'
                # print(self.SWIFT_SOURCE, "generate subdir for", entry, ":", subdir)
                if subdir in already_done:
                    continue

                already_done.add(subdir)
                all_objs.append(
                    {
                        'subdir': subdir
                    }
                )
            else:
                # FIXME: adapt marker
                _prefix = ''
                if len(entry) < len(prefix):
                    _prefix = prefix[len(entry):]
                _marker = None

                if marker:
                    LOG.warn("%s: marker %s vs prefix %s", self.SWIFT_SOURCE,
                             marker, entry)
                    LOG.warn("%s ===> %s vs %s",
                        self.SWIFT_SOURCE, marker[:marker.rindex('/')], entry.rstrip('/'))

                if marker and entry.rstrip('/') == marker[:marker.rindex('/')]:#prefix.startswith(marker):
                    _marker = marker[marker.rindex('/'):].lstrip('/')
                    LOG.warn("%s: use marker: %s from %s",
                        self.SWIFT_SOURCE, _marker, marker)

                if entry:
                    ret = self._list_objects(env, account,
                                             [container] + entry.strip('/').split('/'), header_cb,
                                             _prefix, limit=DEFAULT_LIMIT, marker=_marker)
                else:
                    ret = self._list_objects(env, account,
                                             [container], header_cb, _prefix, limit=DEFAULT_LIMIT, marker=_marker)
                for x in ret:
                    all_objs.append(x)

        all_objs = sorted(all_objs,
                          key=lambda entry: entry.get('name',
                                                      entry.get('subdir')))
        body = json.dumps(all_objs)

        oheaders['Content-Length'] = len(body)
        start_response("200 OK", oheaders.items())

        return [body]
        """
        oheaders = dict()


        def header_cb(header_dict):
            oheaders.update(header_dict)

        all_objs = [x for x in self._list_objects(
                    env, account,
                    tuple(container.split(self.ENCODED_DELIMITER)),
                    header_cb, prefix=obj or '', marker=marker,
                    limit=limit, recursive=recursive)]
        # results must be sorted or paginated listing are broken
        all_objs = sorted(all_objs,
                          key=lambda entry: entry.get('name',
                                                      entry.get('subdir')))
        body = json.dumps(all_objs)
        oheaders['X-Container-Object-Count'] = len(all_objs)
        # FIXME: aggregate X-Container-Bytes-Used
        # FIXME: aggregate X-Container-Object-Count
        # FIXME: send main bucket X-Timestamp
        oheaders['Content-Length'] = len(body)
        start_response("200 OK", oheaders.items())
        return [body]
        """

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
        '''
        LOG.debug("%s: listing objects from '%s' "
                  "(limit=%d, prefix=%s, marker=%s)",
                  self.SWIFT_SOURCE, sub_path, limit, prefix, marker)
        '''
        print(self.SWIFT_SOURCE, "===>", sub_path)
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
        LOG.warn("%s: XXX marker before getting response %s", self.SWIFT_SOURCE, marker)
        resp = sub_req.get_response(self.app)
        obj_prefix = ''
        if len(ct_parts) > 1:
            # print(self.SWIFT_SOURCE, "real listing", ct_parts)
            obj_prefix = self.DELIMITER.join(ct_parts[1:] + ['',])

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

        if container == "org":
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

        # TODO Oio-Copy-From to use correct source (container, obj)
        if 'Oio-Copy-From' in req.headers and req.method == 'PUT':
            _, c_container, c_obj = req.headers['Oio-Copy-From'].split('/', 2)
            c_container, c_obj = \
                self._fake_container_and_obj(c_container, c_obj.split('/'))
            # update Headers
            req.headers['Oio-Copy-From'] = '/' + c_container + '/' + c_obj
            env2['HTTP_OIO_COPY_FROM'] = '/' + c_container + '/' + c_obj

        if obj is None:
            # TODO/FIXME
            LOG.debug("%s: -> is a listing request", self.SWIFT_SOURCE)
            must_recurse = req.method == 'GET' and 'delimiter' not in qs
            if not marker:
                marker = None
            else:
                # FIXME: it is broken
                marker = marker[0] #.strip('/').split(self.DELIMITER)[-1]
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
                # ct = self.ENCODED_DELIMITER.join([container] + obj_parts[:-2])
                # obj = obj_parts[-2] + self.DELIMITER
                path = self.DELIMITER.join(obj_parts[:-1]) + self.DELIMITER
                if req.method == 'PUT':
                    self._create_dir_marker(req, account, container, path)
                elif req.method == 'DELETE': #and not obj_parts[-1]:
                    # there is two cases to manage:
                    # - case for DEL d1/d2/d3/ (it should not be necessary anymore)
                    # (and in fact should fake response when creating empty object with final /)
                    # - case DEL s1/s2/s3/o where O is the last object inside s1/s2/s3/
                    # we have to remove s1/s2/s3/ from
                    # self._remove_dir_marker(req, account, container, path)
                    """
                    if not self._can_delete_dir_marker(req, account, ct, obj):
                        return self._build_empty_response(
                            start_response, '204 No content')
                    """
                    pass
            container2, obj2 = self._fake_container_and_obj(container, obj_parts)

        LOG.debug("%s: Converted to container=%s, obj=%s, qs=%s",
                  self.SWIFT_SOURCE, container2, obj2, qs)
        if must_recurse:
            print("SHARD => RECURSE LISTING MODE")
            res = self._build_object_listing(start_response, env,
                                             account, container2, prefix,
                                             limit=limit, recursive=True,
                                             marker=marker)
        elif qs.get('prefix') or qs.get('delimiter'):
            print("SHARD => SIMPLE LISTING MODE")
            res = self._build_object_listing(start_response, env,
                                             account, container2, prefix,
                                             limit=limit,
                                             recursive=False, marker=marker)
        else:
            # should be other operation that listing
            if obj:
                env2['PATH_INFO'] = "/v1/%s/%s/%s" % (account, container2, obj2)
            else:
                env2['PATH_INFO'] = "/v1/%s/%s" % (account, container2)
            res = self.app(env2, start_response)

            if req.method == 'DELETE' and res == '':
                # only remove marker if everything is ok
               self._remove_dir_marker(req, account, container, path)
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
    """
    create_dir_placeholders = config_true_value(
        local_config.get('create_dir_placeholders'))
    recursive_placeholders = config_true_value(
        local_config.get('recursive_placeholders'))
    """

    def factory(app):
        return ContainerShardingMiddleware(
            app, global_conf, acct,
            strip_v1=strip_v1,
            account_first=account_first,
            swift3_compat=swift3_compat)
    return factory
