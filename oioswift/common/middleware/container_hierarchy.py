# Copyright (C) 2018-2019 OpenIO SAS
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

import base64
import json
import importlib
from paste.deploy import loadwsgi
from six.moves.urllib.parse import parse_qs, quote
from swift.common.swob import Request, HTTPInternalServerError
from swift.common.utils import config_true_value, \
    closing_if_possible, get_logger, MD5_OF_EMPTY_STRING
from swift.common.wsgi import make_subrequest, loadcontext, PipelineWrapper
from oioswift.common.middleware.autocontainerbase import AutoContainerBase
from oio.common.exceptions import ConfigurationException
from distutils.version import LooseVersion

LOG = None
MIDDLEWARE_NAME = 'container_hierarchy'
DEFAULT_LIMIT = 10000
REDIS_KEYS_FORMAT_V1 = 'v1'
REDIS_KEYS_FORMAT_V2 = 'v2'
REDIS_KEYS_FORMAT_V3 = 'v3'

# The Redis key represents a real empty object whose name ends with /.
OBJ = 'obj'
# The Redis key represents a redirection to a container, a "common prefix"
# in the sense of S3 object listing.
CNT = 'cnt'

FAKE_ACL = '''{"Owner":"internal:internal",
               "Grant":[{"Grantee":"AllUsers","Permission":"READ"},
                        {"Grantee":"AllUsers","Permission":"WRITE"}]}'''


class RedisDb(object):
    lua_script_utilities = """
        local get_index = function(key, start, delimiter)
            -- Get index of the first delimiter of the key
            local index = string.find(key, delimiter, start, true)
            if index  == nil then
                return #key
            end
            return index
        end
        local get_first_level = function(key, start, delimiter)
            -- Get the hierarchy first level
            -- start = start looking at this index
            -- delimiter = used for separating level
            -- key = prefix .. delimiter .. first_level ...
            -- Examples get_first_level("aaa/bbb/ccc/", 4, '/') = "aaa/bbb/"
            -- get_first_level("aaa/bbb/ccc/", 8, '/') = "aaa/bbb/ccc/"

            local index = get_index(key, start, delimiter)
            -- if prefix is like "start" we should return "start/"
            -- but if prefix is like "start/" we should return "start/*"
            if index == start then
                start = index + 1
                index = get_index(key, start, delimiter)
            end
            local rv = string.sub(key, 0, index)
            return rv
        end

        local bucket = KEYS[1]
        local prefix = KEYS[2]
        local delimiter = KEYS[3]
        local marker = KEYS[4]
        local recursive = tonumber(KEYS[5])
        local limit = tonumber(KEYS[6])
        local prefix_len = string.len(prefix)
        local set = {}
        -- There is no set on lua this is a hack using the table keys to hold
        -- data and assure uniqueness
    """

    lua_script_zkeys = lua_script_utilities + """
        local keys = {}
        --rank is the redis term for zset index https://redis.io/commands/zrank
        local rank = 0
        local finish = false

        if marker == "" then
            marker = "-"
            if prefix ~= "" then
                marker = "[" .. prefix
            end
        else
            marker = "[" .. marker
        end
        -- We are using the variable `count` to count the element of `set`
        -- `len` and `#` are only possible for continuous numeric indexes
        -- https://stackoverflow.com/questions/2705793/
        -- how-to-get-number-of-entries-in-a-lua-table
        local count = 0
        while count < limit + 2 and not finish do
            keys = redis.call('ZRANGEBYLEX', bucket, marker, '+', 'LIMIT',
                               0, limit)
            for i=1, #keys do
                local elem = keys[i]
                if recursive == 0 then
                    elem = get_first_level(keys[i], prefix_len + 1, delimiter)
                    -- if we found a prefix, skip remaining stuff ?
                    -- but we should check keys array instead
                    -- instead triggering a new zrangebylex
                end
                if prefix ~= "" then
                    local index = string.find(elem, prefix, 1, true)
                    if index == nil or index > 1 then
                        finish = true
                        break
                    end
                end

                if set[elem] == nil then
                    count = count + 1
                    set[elem] = true
                end
            end


            if #keys <= 1 then
                finish = true
            else
                if prefix ~= "" then
                    -- if key doesn't match prefix, stop looping
                    if string.find(keys[#keys], prefix, 1, true) == nil then
                        finish = true
                    end
                end
                marker = "[" .. keys[#keys]
            end
        end

        local lst  = {}
        for k,_ in pairs(set) do
            table.insert(lst, k)
        end
        return lst
    """

    def __init__(self, redis_host=None,
                 sentinel_hosts=None, sentinel_name=None):
        self.__redis_mod = importlib.import_module('redis')
        self.__redis_sentinel_mod = importlib.import_module('redis.sentinel')
        self._sentinel_hosts = None
        self._sentinel = None
        self._conn = None
        self._conn_slave = None
        self._script_zkeys = None

        if LooseVersion(self.__redis_mod.__version__) < LooseVersion("3.0.0"):
            self.zset = self.zset_legacy
        else:
            self.zset = self.zset3

        if redis_host:
            self._redis_host, self._redis_port = redis_host.rsplit(':', 1)
            self._redis_port = int(self._redis_port)
            return

        if not sentinel_name:
            raise ValueError("missing parameter 'sentinel_name'")

        if isinstance(sentinel_hosts, basestring):
            sentinel_hosts = sentinel_hosts.split(',')
        self._sentinel_hosts = [(h, int(p)) for h, p, in (hp.rsplit(':', 1)
                                for hp in sentinel_hosts)]
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

    @property
    def conn_slave(self):
        if self._sentinel:
            return self._sentinel.slave_for(self._master_name)

        if not self._conn:
            self._conn = self.__redis_mod.StrictRedis(host=self._redis_host,
                                                      port=self._redis_port)
        return self._conn

    def set(self, key, val):
        return self.conn.set(key, val)

    def setnx(self, key, val):
        return self.conn.setnx(key, val)

    def hset(self, key, path, val):
        return self.conn.hset(key, path, val)

    def hsetnx(self, key, path, val):
        return self.conn.hsetnx(key, path, val)

    def zset3(self, key, path):
        return self.conn.zadd(key, {path: 1}, nx=True)

    def zset_legacy(self, key, path):
        return self.conn.zadd(key, 1, path)

    def delete(self, key):
        return self.conn.delete(key)

    def hdel(self, key, hkey):
        return self.conn.hdel(key, hkey)

    def zdel(self, key, zkey):
        return self.conn.zrem(key, zkey)

    def keys(self, pattern, count=DEFAULT_LIMIT):
        return self.conn_slave.scan_iter(pattern, count=count)

    def hkeys(self, key, match=None, count=DEFAULT_LIMIT):
        return [k[0] for k in
                self.conn_slave.hscan_iter(key, match=match, count=count)]

    def zkeys(self, key, prefix, delimiter, marker=None, recursive=False,
              limit=DEFAULT_LIMIT):
        """
        Return a range of elements from a sorted set (wraps ZRANGEBYLEX).
        """
        if not self._script_zkeys:
            self._script_zkeys = self.conn_slave.register_script(
                self.lua_script_zkeys)
        if marker:
            pos = marker.rfind(delimiter)
            marker = marker[: pos if pos == -1 else pos + 1]

        return self._script_zkeys([key, prefix, delimiter, marker or "",
                                   1 if recursive else 0, limit])

    def exists(self, key):
        return self.conn_slave.exists(key)

    def hexists(self, key, hkey):
        return self.conn_slave.hexists(key, hkey)

    def zexists(self, key, zkey):
        # zrank returns `None` if missing
        # `0` is a valid value
        return True if self.conn_slave.zrank(key, zkey) is not None else False


class FakeRedis(object):
    """Fake Redis stubb for unit test"""
    def __init__(self):
        LOG.warn("**FakeRedis stub in use **")
        self._keys = {}

    def set(self, key, val):
        self._keys[key] = val

    def setnx(self, key, val):
        self.set(key, val)

    def hset(self, key, path, val):
        self._keys.setdefault(key, {})[path] = val

    def hsetnx(self, key, path, val):
        self.hset(key, path, val)

    def delete(self, key):
        self._keys.pop(key, None)

    def hdel(self, key, hkey):
        if not self._keys.get(key, None):
            return
        self._keys[key].pop(hkey, None)

    def zdel(self, key, zkey):
        if not self._keys.get(key, None):
            return
        self._keys[key].pop(zkey, None)

    def hkeys(self, key, match=None):
        if not self._keys.get(key, None):
            return []
        return self._keys[key].iterkeys()

    def zkeys(self, key, prefix, delimiter, marker=None, recursive=False,
              limit=DEFAULT_LIMIT):
        if not self._keys.get(key, None):
            return []
        return self._keys[key].iterkeys()

    def keys(self, pattern):
        return self._keys.iterkeys()

    def exists(self, key):
        return key in self._keys

    def hexists(self, key, hkey):
        return key+hkey in self._keys

    def zexists(self, key, zkey):
        return key+zkey in self._keys


class ContainerHierarchyMiddleware(AutoContainerBase):
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
        self.redis_keys_format = kwargs.pop('redis_keys_format',
                                            REDIS_KEYS_FORMAT_V1)
        self.support_listing_versioning = \
            kwargs.pop('support_listing_versioning')
        if self.redis_keys_format not in [REDIS_KEYS_FORMAT_V1,
                                          REDIS_KEYS_FORMAT_V2,
                                          REDIS_KEYS_FORMAT_V3]:
            raise ValueError(
                '"redis_keys_format" value not accepted: %s',
                self.redis_keys_format)

        super(ContainerHierarchyMiddleware, self).__init__(
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
        for container_hierarchy
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

        ch_index = pipeline.index(MIDDLEWARE_NAME)
        if 'slo' in pipeline and ch_index < pipeline.index('slo'):
            raise ValueError(
                'Invalid pipeline %r: %s must be placed after SLO'
                % (pipeline, MIDDLEWARE_NAME))

        if ('versioned_writes' in pipeline and
                ch_index < pipeline.index('versioned_writes')):
            raise ValueError(
                'Invalid pipeline %r: '
                '%s must be placed after versioned_writes'
                % (pipeline, MIDDLEWARE_NAME))

    def key(self, account, container, mode, path=None):
        """
        Build the name of a key that will be used to store
        container or dummy object placeholders.
        """
        ret = self.PREFIX + account + ":" + container + ":"
        if mode:
            if self.redis_keys_format == REDIS_KEYS_FORMAT_V1:
                ret += mode + ":"
                if path:
                    ret += path
            else:
                ret += mode
        return ret

    def _create_placeholder(self, req, account, container, mode, path):
        """
        Create a "placeholder" telling that a container has been created
        to hold objects sharing a common prefix.

        :param mode: OBJ or CNT.
        """
        key = self.key(account, container, mode, path)
        LOG.debug("%s: create key %s", self.SWIFT_SOURCE, key)
        # TODO: should we increase number of objects ?
        # but we should manage in this case all error case
        # to avoid false counter
        try:
            if self.redis_keys_format == REDIS_KEYS_FORMAT_V1:
                self.conn.setnx(key, "1")
            elif self.redis_keys_format == REDIS_KEYS_FORMAT_V2:
                self.conn.hsetnx(key, path, "1")
            else:
                self.conn.zset(key, path)
        except Exception as e:
            LOG.error("%s: failed to create key %s (%s)", self.SWIFT_SOURCE,
                      ':'.join([key, path]), str(e))
            raise HTTPInternalServerError()

    def _remove_placeholder(self, req, account, container, mode, path):
        if self.redis_keys_format == REDIS_KEYS_FORMAT_V1:
            key = self.key(account, container, mode, path) + '/'
        else:
            key = self.key(account, container, mode)

        if mode == CNT:
            # remove container key only if empty
            empty = not any(self._list_objects(
                            req.environ.copy(),
                            account,
                            [container] + path.split('/'),
                            None,
                            limit=1,
                            force_master=True,
                            versions=True))
            if not empty:
                return

        LOG.debug("%s: remove key %s (key %s)", self.SWIFT_SOURCE, path, key)
        if self.redis_keys_format == REDIS_KEYS_FORMAT_V1:
            res = self.conn.delete(key)
            if not res:
                LOG.warn("%s: failed to remove key %s", self.SWIFT_SOURCE, key)
        else:
            path += "/"
            if self.redis_keys_format == REDIS_KEYS_FORMAT_V2:
                res = self.conn.hdel(key, path)
            else:
                res = self.conn.zdel(key, path)
            if not res:
                LOG.warn("%s: failed to remove path %s key %s",
                         self.SWIFT_SOURCE, path, key)

    def _build_object_listing_mpu(self, start_response, env,
                                  account, container, prefix,
                                  limit=DEFAULT_LIMIT,
                                  recursive=False, marker=None):
        """Implement specific listing for MPU"""

        LOG.debug("%s: MPU listing with %s %s %s %s %s %s",
                  self.SWIFT_SOURCE, account, container, prefix, limit,
                  recursive, marker)

        # FIXME(mb): should use marker for big MPU
        # but it doesn't seems to manage truncated MPU listing in swift3
        prefix = prefix[0] if prefix else ''
        obj_parts = prefix.rstrip(self.DELIMITER).split(self.DELIMITER)

        is_mpu = False
        if len(obj_parts) > 0:
            pfx = obj_parts[-1]
            # is it list-multipart-uploads or list-parts requests ?
            # docker registry use temporary name like {aaaa}-{bbbb}-{ddddddddd}
            # and base64.b64decode ignore '-' character
            if len(pfx) > 32 and '-' not in pfx:
                try:
                    base64.b64decode(pfx)
                    is_mpu = True
                except TypeError:
                    pass

        path, _ = self._container_suffix(obj_parts, is_mpu)
        mpu_prefix = prefix[len(path):].lstrip('/')

        def header_cb(header_dict):
            oheaders.update(header_dict)

        oheaders = dict()
        ct_parts = [container]
        if path:
            ct_parts += path.split(self.DELIMITER)
        ret = self._list_objects(env, account, ct_parts, header_cb,
                                 mpu_prefix, limit=limit,
                                 marker=marker)

        all_objs = list(ret)
        all_objs.sort(key=lambda entry: entry.get('name', entry.get('subdir')))
        body = json.dumps(all_objs)

        oheaders['Content-Length'] = len(body)
        start_response("200 OK", oheaders.items())
        return [body]

    def _build_object_listing(self, start_response, env,
                              account, container, prefix,
                              limit=DEFAULT_LIMIT,
                              recursive=False, marker=None, is_mpu=False):

        if is_mpu:
            return self._build_object_listing_mpu(start_response, env, account,
                                                  container, prefix, limit,
                                                  recursive, marker)

        LOG.debug("%s: listing with %s %s %s %s %s %s",
                  self.SWIFT_SOURCE, account, container, prefix, limit,
                  recursive, marker)

        def header_cb(header_dict):
            oheaders.update(header_dict)

        oheaders = dict()
        all_objs = []

        # always respect versioning listing to avoid
        # issues in versioned_writes (since we used to
        # use CH before versioned_writes in pipeline)
        versions = env.get('oio.query', {}).get('versions')

        prefix = prefix[0] if prefix else ''
        # have we to parse root container ?
        # / must be absent from prefix or if marker is set
        parse_root = self.DELIMITER not in prefix or marker
        # (not marker or self.DELIMITER not in marker)
        LOG.debug("%s: parse root container ? %s",
                  self.SWIFT_SOURCE, parse_root)
        key = ""
        matches = []
        prefix_key = self.key(account, container, "")
        if self.redis_keys_format == REDIS_KEYS_FORMAT_V1:
            key = self.key(account, container, '*', prefix) + '*'
            matches = [k[len(prefix_key):].split(':', 1)
                       for k in self.conn.keys(key)]
        else:
            matches = list()
            for mode in (CNT, OBJ):
                key = self.key(account, container, mode)
                # empty if key does not exist
                key_list = None
                if self.redis_keys_format == REDIS_KEYS_FORMAT_V3:
                    key_list = self.conn.zkeys(key, prefix,
                                               self.DELIMITER,
                                               marker, recursive, limit)
                else:
                    key_list = self.conn.hkeys(key, match=prefix + "*")
                    # empty if key does not exist
                for entry in key_list:
                    matches.append((mode, entry))
        LOG.debug("SHARD: prefix %s / matches: %d", prefix_key, len(matches))

        if parse_root:
            matches.append((CNT, ""))
        # if prefix is something like dir1/dir2/dir3/ob
        if not prefix.endswith(self.DELIMITER) and self.DELIMITER in prefix:
            pfx = prefix[:prefix.rindex(self.DELIMITER)+1]
            # then we must append dir1/dir2/dir3/ to be able to retrieve
            # object1 and object2 from this container
            if self.redis_keys_format == REDIS_KEYS_FORMAT_V1:
                key = self.key(account, container, CNT, pfx)
                if self.conn.exists(key):
                    matches.append((CNT, key[len(prefix_key) + 4:]))
            else:
                key = self.key(account, container, CNT)
                exists = self.conn.hexists
                if self.redis_keys_format == REDIS_KEYS_FORMAT_V3:
                    exists = self.conn.zexists
                if exists(key, pfx):
                    matches.append((CNT, pfx))

        # we should ignore all keys that are before marker to
        # avoid useless lookup or false listing
        marker_root = False
        if marker:
            m = matches
            if '/' in marker:
                marker_ = marker[:marker.rindex('/')]
                # marker_root = False
            else:
                marker_ = marker
                marker_root = True
            LOG.debug("%s: convert marker %s to %s",
                      self.SWIFT_SOURCE, marker, marker_)
            matches = []
            for mode, entry in m:
                if entry == "":
                    matches.append((mode, entry))
                    continue
                if entry < marker_:
                    continue
                # when a listing is done without recursive mode, ignore marker
                # for container entry
                if mode == CNT and entry == marker and not recursive:
                    LOG.debug(
                        "%s: marker ignore %s: skip container (not recursive)",
                        self.SWIFT_SOURCE, entry)
                    continue
                if mode == OBJ and entry == marker_ + '/':
                    LOG.debug("%s: marker ignore %s: skip object",
                              self.SWIFT_SOURCE, entry)
                    continue
                matches.append((mode, entry))
        matches.sort()

        already_done = set()
        last_obj = None
        len_pfx = len(prefix)
        cnt_delimiter = len(prefix.split('/'))
        for mode, entry in matches:
            if self.DELIMITER in entry[len_pfx:] and not recursive:
                # append subdir entry, no difference between CNT and OBJ
                subdir = '/'.join(entry.split("/")[:cnt_delimiter]) + '/'
                if subdir in already_done:
                    continue
                empty = False
                # check is prefix contains only DeleteMarker as latest version
                # TODO(mbo) avoid this listing if versioning was never enabled
                # on root container/bucket
                if self.support_listing_versioning and not versions:
                    empty = not any(self._list_objects(
                                    env,
                                    account,
                                    [container] + entry.strip(self.DELIMITER)
                                                       .split(self.DELIMITER),
                                    None,
                                    limit=1,
                                    versions=False))

                if not empty:
                    if last_obj and \
                       subdir.decode('utf-8') > all_objs[last_obj - 1]['name']\
                       and len(all_objs) > limit:
                        break
                    already_done.add(subdir)
                    all_objs.append({
                        'subdir': subdir.decode('utf-8')
                    })

            else:
                _prefix = ''
                if len(entry) < len(prefix):
                    _prefix = prefix[len(entry):]

                # transmit marker only to exact container
                # otherwise we will have incorrect listings
                _marker = None
                if marker:
                    if entry == "":
                        _marker = marker if '/' not in marker \
                                         else marker[:marker.index('/')]
                    elif not marker_root \
                            and entry.rstrip('/') == \
                            marker[:marker.rindex('/')]:
                        _marker = marker[marker.rindex('/'):].lstrip('/')
                    LOG.debug("%s: convert marker %s to %s",
                              self.SWIFT_SOURCE, marker, _marker)

                if mode == "obj":
                    ret = [{'name': entry.decode('utf-8'),
                            'bytes': 0,
                            'hash': MD5_OF_EMPTY_STRING,
                            'last_modified': '1970-01-01T00:00:00.000000'}]

                elif entry:
                    if entry[-1] == self.DELIMITER:
                        entry = entry[:-1]
                    ret = self._list_objects(
                        env, account,
                        [container] + entry.split(self.DELIMITER), header_cb,
                        _prefix, limit=limit, marker=_marker,
                        versions=versions)
                else:
                    # manage root container
                    # TODO: rewrite condition
                    ret = self._list_objects(
                        env, account,
                        [container], header_cb, _prefix, limit=limit,
                        marker=_marker, versions=versions)
                for x in ret:
                    all_objs.append(x)
                # root container is the first one listed
                if last_obj is None:
                    last_obj = len(all_objs)
                if len(all_objs) > last_obj + limit:
                    break

            # it suppose to have proper order but it will help a lot !
            # quick test with page-size 2 to list 10 directories with 10 objets
            # with break: 2.1s vs without break 3.8s
            if len(all_objs) > 2 * limit:
                break

        LOG.debug("%s: got %d items / limit was %d", self.SWIFT_SOURCE,
                  len(all_objs), limit)
        all_objs = sorted(all_objs,
                          key=lambda entry: entry.get('name',
                                                      entry.get('subdir')))
        body = json.dumps(all_objs[:limit])

        oheaders['Content-Length'] = len(body)
        start_response("200 OK", oheaders.items())
        return [body]

    def _container_suffix(self, obj_parts, is_mpu, sep=None):
        """
        Build a suffix for the name of the container, by aggregating object
        parts (except the last).

        :returns: the suffix and the index of the first part that should
            be kept in the object name.
        """
        if not sep:
            sep = self.DELIMITER

        # FIXME(mbo): a proper HEADER should be added in swift3 controller
        # to help recognize manifest / part
        if is_mpu:
            for i, item in reversed(list(enumerate(obj_parts))):
                if len(item) > 32:
                    try:
                        base64.b64decode(item)
                        # CloudBerry: mitigate number of container created
                        if i >= 3:
                            if obj_parts[i-3] == obj_parts[i-1] + ':':
                                return sep.join(obj_parts[:i-3]), i-3
                        return sep.join(obj_parts[:i-1]), i-1
                    except TypeError:
                        pass
            LOG.error("MPU fails to detect UploadId")

        # CloudBerry: mitigate number of container created
        if len(obj_parts) >= 3:
            if obj_parts[-1] + ':' == obj_parts[-3]:
                return sep.join(obj_parts[:-3]), -3

        return sep.join(obj_parts[:-1]), len(obj_parts)-1

    def _fake_container_and_obj(self, container, obj_parts, is_listing=False,
                                is_mpu=False):
        """
        Aggregate object parts (except the last) into the container name.

        :returns: container name and object name
        """
        if len(obj_parts) > 1 and not obj_parts[-1] and not is_listing:
            container = self.ENCODED_DELIMITER.join(
                [container] + obj_parts[:-2])
            obj = obj_parts[-2] + self.DELIMITER
        else:
            cnt, idx = self._container_suffix(
                obj_parts, is_mpu, sep=self.ENCODED_DELIMITER)
            if cnt:
                container += self.ENCODED_DELIMITER + cnt
            obj = obj_parts[idx:] if obj_parts else ''
            obj = '/'.join(obj)
        return container, obj

    def _list_objects(self, env, account, ct_parts, header_cb,
                      prefix='', limit=DEFAULT_LIMIT,
                      marker=None, force_master=False, versions=False):
        """
        returns items
        """
        sub_path = quote(self.DELIMITER.join(
            ('', 'v1', account, self.ENCODED_DELIMITER.join(ct_parts))))

        LOG.debug("%s: listing objects from '%s' "
                  "(limit=%d, prefix=%s, marker=%s)",
                  self.SWIFT_SOURCE, sub_path, limit, prefix, marker)
        sub_req = make_subrequest(env.copy(), method='GET', path=sub_path,
                                  body='',
                                  swift_source=self.SWIFT_SOURCE)
        params = sub_req.params
        params.pop('delimiter', None)  # allow list-multipart-uploads
        params['limit'] = str(limit)  # FIXME: why is it str?
        params['prefix'] = prefix
        params['format'] = 'json'
        if marker:
            params['marker'] = marker
        else:
            params.pop('marker', None)
        if force_master:
            # this is used to check if container is empty after a delete
            # but we want to ensure listing is done on master
            sub_req.environ.setdefault('oio.query', {})
            sub_req.environ['oio.query']['force_master'] = True
        if versions:
            # this is used to check if container is really empty after a delete
            # or when a versioned listing is done
            sub_req.environ.setdefault('oio.query', {})
            sub_req.environ['oio.query']['versions'] = True

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
                obj['name'] = obj_prefix.decode('utf-8') + obj['name']
                yield obj

    def should_bypass(self, env):
        # Pre authentication from swift3
        return (env.get('REQUEST_METHOD') == 'TEST' or
                super(ContainerHierarchyMiddleware, self).should_bypass(env))

    def update_copy_headers(self, req, env2):
        if 'Oio-Copy-From' in req.headers and req.method == 'PUT':
            # TODO(mb): check if MPU is used here (with upload-part-copy)
            _, c_container, c_obj = req.headers['Oio-Copy-From'].split('/', 2)
            c_container, c_obj = \
                self._fake_container_and_obj(c_container, c_obj.split('/'))
            # update Headers
            req.headers['Oio-Copy-From'] = '/' + c_container + '/' + c_obj
            env2['HTTP_OIO_COPY_FROM'] = '/' + c_container + '/' + c_obj

    def _handle_dir_object(self, req, start_response, account, container,
                           path):
        if req.method in ('GET', 'HEAD'):
            key = self.key(account, container, OBJ, path)
            if self.redis_keys_format == REDIS_KEYS_FORMAT_V1:
                is_available = self.conn.exists(key + "/")
            elif self.redis_keys_format == REDIS_KEYS_FORMAT_V2:
                is_available = self.conn.hexists(key, path + "/")
            else:
                is_available = self.conn.zexists(key, path + "/")

            if is_available:
                # add a fake AllUsers permissions, otherwise it will
                # be dropped by ACL checks in S3 Layer
                oheaders = {
                    'Content-Length': 0,
                    'Etag': MD5_OF_EMPTY_STRING,
                    'x-object-sysmeta-swift3-acl': FAKE_ACL}
                start_response("200 OK", oheaders.items())
            else:
                start_response("404 Not Found", [])
            return ['']

        if req.method == 'PUT':
            # TODO (MBO) we should accept create key d1/d2/ only
            # for empty object
            key = self.key(account, container, OBJ, path)
            self._create_placeholder(req, account, container,
                                     OBJ, path + '/')
            oheaders = {'Content-Length': 0,
                        'Etag': MD5_OF_EMPTY_STRING}
            start_response("201 Created", oheaders.items())
            return ['']

        if req.method == 'DELETE':
            self._remove_placeholder(req, account, container, OBJ, path)
            oheaders = {'Content-Length': 0,
                        'Etag': MD5_OF_EMPTY_STRING}
            start_response("204 No Content", oheaders.items())
            return ['']

    def __call__(self, env, start_response):
        self._save_bucket_name(env)
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
        marker = qs.get('marker')
        limit = qs.get('limit')

        # if obj and prefix are None with container+segments, we want the
        # normal listing because it is the list-multipart-uploads operation
        is_mpu = container.endswith("+segments") and (obj is not None
                                                      or prefix is not None)
        LOG.debug("%s: Got %s request for container=%s, "
                  "obj=%s, prefix=%s marker=%s is_mpu=%d",
                  self.SWIFT_SOURCE, req.method, container, obj,
                  prefix, marker, is_mpu)
        must_recurse = False
        obj_parts = ()

        self.update_copy_headers(req, env2)

        if obj is None:
            LOG.debug("%s: -> is a listing request", self.SWIFT_SOURCE)
            must_recurse = req.method == 'GET' and 'delimiter' not in qs
            if marker:
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
                path, _ = self._container_suffix(obj_parts, is_mpu)
                # When Hadoop S3A detects a prefix (dir1/dir2/) for
                # objet dir1/dir2/object1, two HEAD requests will be done:
                # HEAD dir1/dir2/
                #   this case is managed by checking if Redis Key OBJ exists
                if obj.endswith(self.DELIMITER):
                    return self._handle_dir_object(req, start_response,
                                                   account, container, path)

                # HEAD dir1/dir2 : this case is partially managed by checking
                # is # Redis Key CNT exists for dir1, if key if not present, we
                # can reply 404 because there is no objects in dir1/ container
                if not is_mpu and req.method in ('GET', 'HEAD'):
                    key = self.key(account, container, CNT, path)
                    if self.redis_keys_format == REDIS_KEYS_FORMAT_V1:
                        check = self.conn.exists(key + '/')
                    elif self.redis_keys_format == REDIS_KEYS_FORMAT_V2:
                        check = self.conn.hexists(key, path + "/")
                    else:
                        check = self.conn.zexists(key, path + "/")
                    if not check:
                        start_response("404 Not Found", [])
                        return ['']

                # manage real objects
                if req.method == 'PUT':
                    self._create_placeholder(req, account, container,
                                             CNT, path + '/')

            container2, obj2 = self._fake_container_and_obj(container,
                                                            obj_parts,
                                                            is_mpu=is_mpu)

        LOG.debug("%s: Converted to container=%s, obj=%s, qs=%s",
                  self.SWIFT_SOURCE, container2, obj2, qs)
        if must_recurse or prefix or qs.get('delimiter'):
            res = self._build_object_listing(start_response, env,
                                             account, container2, prefix,
                                             limit=limit, marker=marker,
                                             recursive=must_recurse,
                                             is_mpu=is_mpu)
        else:
            # should be other operation that listing
            if obj:
                env2['PATH_INFO'] = "/v1/%s/%s/%s" % (account, container2,
                                                      obj2)
            else:
                env2['PATH_INFO'] = "/v1/%s/%s" % (account, container2)
            res = self.app(env2, start_response)

            if req.method == 'DELETE' and not is_mpu and len(obj_parts) > 1:
                # only remove marker
                self._remove_placeholder(req, account, container, CNT, path)
        return res


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)
    global LOG
    LOG = get_logger(conf)

    acct = conf.get('sds_default_account')

    if acct is None:
        raise ConfigurationException('No OIO-SDS account configured')

    account_first = config_true_value(local_config.get('account_first'))
    swift3_compat = config_true_value(local_config.get('swift3_compat'))
    strip_v1 = config_true_value(local_config.get('strip_v1'))
    redis_keys_format = local_config.get('redis_keys_format',
                                         REDIS_KEYS_FORMAT_V1)
    redis_host = local_config.get('redis_host')
    sentinel_hosts = local_config.get('sentinel_hosts')
    sentinel_name = local_config.get('sentinel_name')
    support_listing_versioning = config_true_value(
                local_config.get('support_listing_versioning'))

    def factory(app):
        return ContainerHierarchyMiddleware(
            app, global_conf, acct,
            strip_v1=strip_v1,
            account_first=account_first,
            swift3_compat=swift3_compat,
            redis_keys_format=redis_keys_format,
            redis_host=redis_host,
            sentinel_hosts=sentinel_hosts,
            sentinel_name=sentinel_name,
            support_listing_versioning=support_listing_versioning)
    return factory
