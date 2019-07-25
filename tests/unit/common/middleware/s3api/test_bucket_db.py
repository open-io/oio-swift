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

from swift.common import swob
from swift.common.swob import Request
from swift.common.utils import json
from oioswift.common.middleware.s3api.cfg import CONF
from oioswift.common.middleware.s3api.etree import fromstring
from tests.unit.common.middleware.s3api import S3TestCase


class TestS3BucketDb(S3TestCase):

    def __init__(self, name):
        super(TestS3BucketDb, self).__init__(name)

    def setUp(self):
        # Trick to load dummy bucket DB
        CONF.bucket_db_enabled = True

        super(TestS3BucketDb, self).setUp()
        self.swift.register('PUT', '/v1/AUTH_test2/bucket',
                            swob.HTTPCreated, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/bucket-server-error',
                            swob.HTTPServerError, {}, None)
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
            {'X-Container-Object-Count': 0}, None)
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?format=json&marker=',
            swob.HTTPNotFound, {}, None)

    @property
    def db(self):
        return self.s3api.bucket_db

    def _bucket_op(self, op, bucket='bucket', account='test'):
        req = Request.blank(
            '/%s' % bucket,
            environ={'REQUEST_METHOD': op},
            headers={'Authorization': 'AWS %s:tester:hmac' % account,
                     'Date': self.get_date_header()})
        return self.call_s3api(req)

    def _bucket_put(self, *args, **kwargs):
        return self._bucket_op('PUT', *args, **kwargs)

    def _bucket_get(self, *args, **kwargs):
        return self._bucket_op('GET', *args, **kwargs)

    def _bucket_delete(self, *args, **kwargs):
        return self._bucket_op('DELETE', *args, **kwargs)

    def test_bucket_PUT(self):
        self.assertIsNone(self.db.get_owner('bucket'))
        status, headers, body = self._bucket_put()
        self.assertEqual(body, '')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Location'], '/bucket')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

    def test_bucket_PUT_twice(self):
        self.assertIsNone(self.db.get_owner('bucket'))
        status, headers, body = self._bucket_put()
        self.assertEqual(body, '')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Location'], '/bucket')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        status, headers, body = self._bucket_put()
        self.assertEqual(status.split()[0], '409')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

    def test_bucket_PUT_other_account(self):
        self.assertIsNone(self.db.get_owner('bucket'))
        status, headers, body = self._bucket_put()
        self.assertEqual(body, '')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Location'], '/bucket')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        status, headers, body = self._bucket_put(account='test2')
        self.assertEqual(status.split()[0], '409')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

    def test_bucket_PUT_fail(self):
        self.assertIsNone(self.db.get_owner('bucket-server-error'))
        status, _, _ = self._bucket_put('bucket-server-error')
        self.assertEqual(status.split()[0], '500')
        self.assertIsNone(self.db.get_owner('bucket-server-error'))

    def test_bucket_DELETE(self):
        self.assertIsNone(self.db.get_owner('bucket'))
        status, _, _ = self._bucket_put()
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        status, _, _ = self._bucket_delete()
        self.assertEqual(status.split()[0], '204')
        self.assertIsNone(self.db.get_owner('bucket'))

    def test_bucket_DELETE_fail(self):
        self.assertIsNone(self.db.get_owner('bucket'))
        status, _, _ = self._bucket_put()
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        self.swift.register('DELETE', '/v1/AUTH_test/bucket',
                            swob.HTTPServerError, {}, None)
        status, _, _ = self._bucket_delete()
        self.assertEqual(status.split()[0], '500')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

    def test_bucket_PUT_after_DELETE(self):
        self.assertIsNone(self.db.get_owner('bucket'))
        status, _, _ = self._bucket_put()
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        status, _, _ = self._bucket_delete()
        self.assertEqual(status.split()[0], '204')
        self.assertIsNone(self.db.get_owner('bucket'))

        status, _, _ = self._bucket_put(account='test2')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test2')

    def test_bucket_GET_other_account(self):
        self.assertIsNone(self.db.get_owner('bucket'))
        status, _, _ = self._bucket_put()
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        # Register request with account 'test'.
        expected_body = json.dumps(
            [{"name": "expected",
              "last_modified": "2017-04-21T16:30:34.133034",
              "hash": "0000",
              "bytes": 0}])
        self.swift.register('GET',
                            '/v1/AUTH_test/bucket?format=json&limit=1001',
                            swob.HTTPOk, {}, expected_body)
        # Then do a call with 'test2' account, that should be changed
        # to 'test' by the middleware (because the bucket 'bucket' belongs
        # to account 'test').
        status, _, body = self._bucket_get('bucket', account='test2')
        elem = fromstring(body, "ListBucketResult")
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(elem.find('Contents').find('Key').text, "expected")
