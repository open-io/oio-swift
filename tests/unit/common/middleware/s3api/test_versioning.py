# Copyright (c) 2014 OpenStack Foundation
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

import unittest

from swift.common.swob import Request, HTTPCreated, HTTPNoContent, \
    HTTPNotFound, HTTPOk

from oioswift.common.middleware.s3api.utils import VERSIONING_SUFFIX

from tests.unit.common.middleware.s3api import S3TestCase
from oioswift.common.middleware.s3api.etree import fromstring, tostring, \
    Element, SubElement

VERSIONING_BUCKET = 'bucket%s' % VERSIONING_SUFFIX


class TestS3Versioning(S3TestCase):

    def _versioning_GET(self, path):
        req = Request.blank('%s?versioning' % path,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, headers, body = self.call_s3api(req)
        return status, headers, body

    def _versioning_GET_not_configured(self, path):
        self.swift.register('HEAD', '/v1/AUTH_test/%s' % VERSIONING_BUCKET,
                            HTTPNotFound, {}, None)

        status, headers, body = self._versioning_GET(path)
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'VersioningConfiguration')
        self.assertEqual(elem.getchildren(), [])

    def _versioning_GET_enabled(self, path):
        self.swift.register('HEAD', '/v1/AUTH_test/%s' % VERSIONING_BUCKET,
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket', HTTPNoContent, {
            'X-Container-Sysmeta-Versions-Location': VERSIONING_BUCKET,
            'X-Container-Sysmeta-Versions-Mode': 'history',
        }, None)

        status, headers, body = self._versioning_GET(path)
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'VersioningConfiguration')
        status = elem.find('./Status').text
        self.assertEqual(status, 'Enabled')

    def _versioning_GET_suspended(self, path):
        self.swift.register('HEAD', '/v1/AUTH_test/%s' % VERSIONING_BUCKET,
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket', HTTPNoContent, {},
                            None)

        status, headers, body = self._versioning_GET('/bucket/object')
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'VersioningConfiguration')
        status = elem.find('./Status').text
        self.assertEqual(status, 'Suspended')

    def _versioning_PUT_error(self, path):
        # Root tag is not VersioningConfiguration
        elem = Element('foo')
        SubElement(elem, 'Status').text = 'Enabled'
        xml = tostring(elem)

        req = Request.blank('%s?versioning' % path,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '400')

        # Status is not "Enabled" or "Suspended"
        elem = Element('VersioningConfiguration')
        SubElement(elem, 'Status').text = 'enabled'
        xml = tostring(elem)

        req = Request.blank('%s?versioning' % path,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '400')

    def _versioning_PUT_enabled(self, path):
        elem = Element('VersioningConfiguration')
        SubElement(elem, 'Status').text = 'Enabled'
        xml = tostring(elem)

        self.swift.register('HEAD', '/v1/AUTH_test/%s' % VERSIONING_BUCKET,
                            HTTPNotFound, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/%s' % VERSIONING_BUCKET,
                            HTTPCreated, {}, None)
        self.swift.register('POST', '/v1/AUTH_test/bucket',
                            HTTPNoContent, {}, None)

        req = Request.blank('%s?versioning' % path,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '200')

        calls = self.swift.calls_with_headers
        self.assertEqual(calls[-1][0], 'POST')
        self.assertIn(('X-History-Location', VERSIONING_BUCKET),
                      calls[-1][2].items())

    def _versioning_PUT_suspended(self, path):
        elem = Element('VersioningConfiguration')
        SubElement(elem, 'Status').text = 'Suspended'
        xml = tostring(elem)

        self.swift.register('HEAD', '/v1/AUTH_test/%s' % VERSIONING_BUCKET,
                            HTTPNotFound, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/%s' % VERSIONING_BUCKET,
                            HTTPCreated, {}, None)
        self.swift.register('POST', '/v1/AUTH_test/bucket',
                            HTTPNoContent, {}, None)

        req = Request.blank('%s?versioning' % path,
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '200')

        calls = self.swift.calls_with_headers
        self.assertEqual(calls[-1][0], 'POST')
        self.assertIn(('X-Remove-History-Location', 'true'),
                      calls[-1][2].items())

    def _GET_object_versions(self, path):
        objects = '''[
        {"bytes": 43740,
         "content_type": "application/octet-stream",
         "hash": "029ea7399fb3f89d86e537fd24de027e",
         "last_modified": "2018-11-15T10:26:09.000000",
         "name": "magic"},
        {"subdir": "sub/"}
        ]'''
        objects_versions = '''[
        {"bytes": 113,
         "content_type": "application/octet-stream",
         "hash": "8de4989188593b0419d387099c9e9872",
         "last_modified": "2018-11-15T10:25:59.000000",
         "name": "005magic/1542277559206248",
         "version": 1542277559206248}
        ]'''
        query = 'delimiter=/&format=json&limit=1001'
        query2 = 'delimiter=/&format=json&limit=1001&reverse=true'
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/magic', HTTPOk,
                            {'X-Object-Sysmeta-Version-Id': '1542277569223672',
                             'Content-Length': '43740',
                             'Content-Type': 'application/octet-stream',
                             'Last-Modified': 'Thu, 15 Nov 2018 10:26:09 GMT',
                             'Etag': '029ea7399fb3f89d86e537fd24de027e'},
                            None)
        self.swift.register('GET', '/v1/AUTH_test/bucket?%s' % (query, ),
                            HTTPOk, {}, objects)
        self.swift.register(
            'GET', '/v1/AUTH_test/%s?%s' % (VERSIONING_BUCKET, query2, ),
            HTTPOk, {}, objects_versions)
        req = Request.blank('%s?versions&delimiter=/' % path,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListVersionsResult')
        versions = elem.findall('Version')
        self.assertEqual(len(versions), 2)
        for version in versions:
            key = version.find('Key')
            self.assertEqual(key.text, 'magic')

    def test_object_versioning_GET_not_configured(self):
        self._versioning_GET_not_configured('/bucket/object')

    def test_object_versioning_GET_enabled(self):
        self._versioning_GET_enabled('/bucket/object')

    def test_object_versioning_GET_suspended(self):
        self._versioning_GET_suspended('/bucket/object')

    def test_object_versioning_PUT_error(self):
        self._versioning_PUT_error('/bucket/object')

    def test_object_versioning_PUT_enabled(self):
        self._versioning_PUT_enabled('/bucket/object')

    def test_object_versioning_PUT_suspended(self):
        self._versioning_PUT_suspended('/bucket/object')

    def test_bucket_versioning_GET_not_configured(self):
        self._versioning_GET_not_configured('/bucket')

    def test_bucket_versioning_GET_enabled(self):
        self._versioning_GET_enabled('/bucket')

    def test_bucket_versioning_GET_suspended(self):
        self._versioning_GET_suspended('/bucket')

    def test_bucket_versioning_PUT_error(self):
        self._versioning_PUT_error('/bucket')

    def test_bucket_versioning_PUT_enabled(self):
        self._versioning_PUT_enabled('/bucket')

    def test_bucket_versioning_PUT_suspended(self):
        self._versioning_PUT_suspended('/bucket')

    def test_bucket_versioning_GET_object_versions(self):
        self._GET_object_versions('/bucket')


if __name__ == '__main__':
    unittest.main()
