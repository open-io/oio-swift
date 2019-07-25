# Copyright (c) 2017 OpenStack Foundation.
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

import time
import importlib
from swift.common.utils import config_true_value


class DummyBucketDb(object):
    """
    Keep a list of buckets with their associated account.
    Dummy in-memory implementation.
    """

    def __init__(self, *args, **kwargs):
        self._bucket_db = dict()

    def get_owner(self, bucket):
        """
        Get the owner of a bucket.
        """
        owner, deadline = self._bucket_db.get(bucket, (None, None))
        if deadline is not None and deadline < time.time():
            del self._bucket_db[bucket]
            return None
        return owner

    def reserve(self, bucket, owner, timeout=30):
        """
        Reserve a bucket. The bucket entry must not already
        exist in the database.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param timeout: a timeout in seconds, for the reservation to expire.
        :returns: True if the bucket has been reserved, False otherwise
        """
        if self.get_owner(bucket):
            return False
        deadline = time.time() + timeout
        self._bucket_db[bucket] = (owner, deadline)
        return True

    def set_owner(self, bucket, owner):
        """
        Set the owner of a bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the ownership has been set
        """
        self._bucket_db[bucket] = (owner, None)
        return True

    def release(self, bucket):
        """
        Remove the bucket from the database.
        """
        self._bucket_db.pop(bucket, None)


class RedisBucketDb(object):
    """
    Keep a list of buckets with their associated account.
    Dummy in-memory implementation.
    """

    def __init__(self, host="127.0.0.1:6379",
                 sentinel_hosts=None, master_name=None,
                 prefix="s3bucket:", **kwargs):
        self.__redis_mod = importlib.import_module('redis')
        self.__redis_sentinel_mod = importlib.import_module('redis.sentinel')

        self._redis_host, self._redis_port = host.rsplit(':', 1)
        self._redis_port = int(self._redis_port)
        self._prefix = prefix

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

    @property
    def conn(self):
        if self._sentinel:
            return self._sentinel.master_for(self._master_name)
        if not self._conn:
            self._conn = self.__redis_mod.StrictRedis(host=self._redis_host,
                                                      port=self._redis_port)
        return self._conn

    def _key(self, bucket):
        return self._prefix + bucket

    def get_owner(self, bucket):
        """
        Get the owner of a bucket.

        :returns: the name of the account owning the bucket or None
        """
        owner = self.conn.get(self._key(bucket))
        return owner

    def set_owner(self, bucket, owner):
        """
        Set the owner of a bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the ownership has been set
        """
        res = self.conn.set(self._key(bucket), owner)
        return res is True

    def reserve(self, bucket, owner, timeout=30):
        """
        Reserve a bucket. The bucket entry must not already
        exist in the database.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param timeout: a timeout in seconds, for the reservation to expire.
        :returns: True if the bucket has been reserved, False otherwise
        """
        res = self.conn.set(self._key(bucket), owner,
                            ex=int(timeout), nx=True)
        return res is True

    def release(self, bucket):
        """
        Remove the bucket from the database.
        """
        self.conn.delete(self._key(bucket))


def get_bucket_db(conf):
    """
    If `bucket_db_enabled` is set in `conf`, get the bucket database,
    otherwise return `None`.

    If `bucket_db_host` or `bucket_db_sentinel_hosts` are also set in `conf`,
    return an instance of `RedisBucketDb`, otherwise return an instance of
    `DummyBucketDb`.
    """
    db_kwargs = {k[10:]: v for k, v in conf.items()
                 if k.startswith('bucket_db_')}
    if config_true_value(db_kwargs.get('enabled', 'false')):
        if 'host' in db_kwargs or 'sentinel_hosts' in db_kwargs:
            return RedisBucketDb(**db_kwargs)
        else:
            return DummyBucketDb(**db_kwargs)

    return None
