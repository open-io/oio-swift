# Copyright (c) 2018 OpenStack Foundation
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

from oioswift.common.middleware.s3api.etree import fromstring, tostring, \
    Element, SubElement
from oioswift.common.middleware.s3api.controllers import tagging
from tests.unit.common.middleware.s3api import S3TestCase


class TestS3Tagging(S3TestCase):

    TAGGING_BODY = """
        <Tagging>
          <TagSet>
            <Tag>
              <Key>organization</Key>
              <Value>marketing</Value>
            </Tag>
          </TagSet>
        </Tagging>
    """

    TAGGING_BODY_NO_KEY = """
        <Tagging>
          <TagSet>
            <Tag>
              <Value>marketing</Value>
            </Tag>
          </TagSet>
        </Tagging>
    """

    TAGGING_BODY_NO_VALUE = """
        <Tagging>
          <TagSet>
            <Tag>
              <Key>organization</Key>
            </Tag>
          </TagSet>
        </Tagging>
    """

    def setUp(self):
        super(TestS3Tagging, self).setUp()
        self.swift.register('HEAD', '/v1/AUTH_test/missingbucket',
                            swob.HTTPNotFound, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/missingobject',
                            swob.HTTPNotFound, {}, None)
        self.swift.register('POST', '/v1/AUTH_test/bucket/missingobject',
                            swob.HTTPNotFound, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent,
                            {tagging.BUCKET_TAGGING_HEADER:
                             self.__class__.TAGGING_BODY},
                            None)
        self.swift.register('POST', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk,
                            {tagging.VERSION_ID_HEADER: '1538495586123456',
                             tagging.OBJECT_TAGGING_HEADER:
                                 self.__class__.TAGGING_BODY},
                            None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object_no_tagging',
                            swob.HTTPOk,
                            {tagging.VERSION_ID_HEADER: '1538495586123456'},
                            None)
        self.swift.register('POST', '/v1/AUTH_test/bucket/object',
                            swob.HTTPAccepted, {}, None)

    def _assert_error(self, req, expected_status, expected_errcode):
        status, _headers, body = self.call_s3api(req)
        self.assertEqual(expected_status, status)
        self.assertEqual(expected_errcode, self._get_error_code(body))

    def _build_tagging_body(self, n_tags=1):
        elem = Element('Tagging')
        sub = SubElement(elem, 'TagSet')
        for num in range(n_tags):
            tag = SubElement(sub, 'Tag')
            SubElement(tag, 'Key').text = 'key' * 41 + '%05d' % num
            SubElement(tag, 'Value').text = 'value' * 50 + '%06d' % num
        return tostring(elem)

    def _validate_tagset(self, body, empty=False):
        root = fromstring(body, 'Tagging')
        tagset = root.find('./TagSet')
        self.assertIsNotNone(tagset)
        tag = tagset.find('./Tag')
        if empty:
            self.assertIsNone(tag)
        else:
            self.assertIsNotNone(tag)
            key = tag.find('./Key')
            value = tag.find('./Value')
            self.assertIsNotNone(key)
            self.assertIsNotNone(value)
            self.assertEqual('organization', key.text)
            self.assertEqual('marketing', value.text)

    # --- Bucket tagging ------------------------------
    def test_bucket_tagging_GET_missing_bucket(self):
        req = Request.blank('/missingbucket?tagging',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        self._assert_error(req, '404 Not Found', 'NoSuchBucket')

    def test_bucket_tagging_PUT_missing_bucket(self):
        req = Request.blank('/missingbucket?tagging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=self.__class__.TAGGING_BODY)
        self._assert_error(req, '404 Not Found', 'NoSuchBucket')

    def test_bucket_tagging_DELETE_missing_bucket(self):
        req = Request.blank('/missingbucket?tagging',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        self._assert_error(req, '404 Not Found', 'NoSuchBucket')

    def test_bucket_tagging_GET(self):
        req = Request.blank('/bucket?tagging',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, _headers, body = self.call_s3api(req)
        self.assertEqual('200 OK', status)
        self._validate_tagset(body)

    def test_bucket_tagging_PUT(self):
        req = Request.blank('/bucket?tagging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=self.__class__.TAGGING_BODY)
        status, _headers, body = self.call_s3api(req)
        self.assertEqual('204 No Content', status)
        self.assertFalse(body)  # False -> empty
        calls = self.swift.calls_with_headers
        self.assertEqual(2, len(calls))
        post = calls[1]
        self.assertEqual('POST', post[0])
        self.assertEqual('/v1/AUTH_test/bucket', post[1])
        self.assertIn(tagging.BUCKET_TAGGING_HEADER, post[2])
        self.assertEqual(self.__class__.TAGGING_BODY,
                         post[2][tagging.BUCKET_TAGGING_HEADER])

    def test_bucket_tagging_PUT_invalid_body(self):
        req = Request.blank('/bucket?tagging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=self.__class__.TAGGING_BODY_NO_VALUE)
        self._assert_error(req, '400 Bad Request', 'MalformedXML')

    def test_bucket_tagging_DELETE(self):
        req = Request.blank('/bucket?tagging',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, _headers, body = self.call_s3api(req)
        self.assertEqual('204 No Content', status)
        self.assertFalse(body)  # False -> empty
        calls = self.swift.calls_with_headers
        self.assertEqual(2, len(calls))
        post = calls[1]
        self.assertEqual('POST', post[0])
        self.assertEqual('/v1/AUTH_test/bucket', post[1])
        self.assertIn(tagging.BUCKET_TAGGING_HEADER, post[2])
        self.assertEqual('', post[2][tagging.BUCKET_TAGGING_HEADER])

    # --- Object tagging ------------------------------
    def test_object_tagging_GET_missing_object(self):
        req = Request.blank('/bucket/missingobject?tagging',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        self._assert_error(req, '404 Not Found', 'NoSuchKey')

    def test_object_tagging_PUT_missing_object(self):
        req = Request.blank('/bucket/missingobject?tagging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=self.__class__.TAGGING_BODY)
        self._assert_error(req, '404 Not Found', 'NoSuchKey')

    def test_object_tagging_PUT_huge_body(self):
        body = self._build_tagging_body(20)
        req = Request.blank('/bucket/object?tagging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=body)
        self._assert_error(req, '400 Bad Request', 'MalformedXML')

    def test_object_tagging_PUT_invalid_body(self):
        req = Request.blank('/bucket/missingobject?tagging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=self.__class__.TAGGING_BODY_NO_KEY)
        self._assert_error(req, '400 Bad Request', 'MalformedXML')

    def test_object_tagging_PUT_too_many_tags(self):
        self.skipTest('No restriction on the number of tags at the moment')

    def test_object_tagging_DELETE_missing_object(self):
        req = Request.blank('/bucket/missingobject?tagging',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        self._assert_error(req, '404 Not Found', 'NoSuchKey')

    def test_object_tagging_GET(self):
        req = Request.blank('/bucket/object?tagging',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, _headers, body = self.call_s3api(req)
        self.assertEqual('200 OK', status)
        self._validate_tagset(body)

    def test_object_tagging_GET_missing_tagging(self):
        req = Request.blank('/bucket/object_no_tagging?tagging',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, _headers, body = self.call_s3api(req)
        self.assertEqual('200 OK', status)
        self._validate_tagset(body, empty=True)

    def test_object_tagging_PUT(self):
        req = Request.blank('/bucket/object?tagging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=self.__class__.TAGGING_BODY)
        status, _headers, body = self.call_s3api(req)
        self.assertEqual('200 OK', status)
        self.assertFalse(body)  # False -> empty
        calls = self.swift.calls_with_headers
        self.assertEqual(2, len(calls))
        post = calls[1]
        self.assertEqual('POST', post[0])
        self.assertEqual('/v1/AUTH_test/bucket/object', post[1])
        self.assertIn(tagging.OBJECT_TAGGING_HEADER, post[2])
        self.assertEqual(self.__class__.TAGGING_BODY,
                         post[2][tagging.OBJECT_TAGGING_HEADER])

    def test_object_tagging_DELETE(self):
        req = Request.blank('/bucket/object?tagging',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, _headers, body = self.call_s3api(req)
        self.assertEqual('204 No Content', status)
        self.assertFalse(body)  # False -> empty
        calls = self.swift.calls_with_headers
        self.assertEqual(2, len(calls))
        post = calls[1]
        self.assertEqual('POST', post[0])
        self.assertEqual('/v1/AUTH_test/bucket/object', post[1])
        self.assertIn(tagging.OBJECT_TAGGING_HEADER, post[2])
        self.assertEqual('', post[2][tagging.OBJECT_TAGGING_HEADER])
