# Copyright (c) 2018 OpenStack Foundation.
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
from xml.etree import ElementTree as ET

from swift.common.swob import Request, HTTPNoContent

from tests.unit.common.middleware.s3api import S3TestCase
from oioswift.common.middleware.s3api.controllers.cors import \
    BUCKET_CORS_HEADER

RULE = {
    "AllowedOrigin": "http://www.example.com",
    "AllowedHeader": ["hdr-1", "hdr-2"],
    "AllowedMethod": ["PUT", "POST", "DELETE"],
    "MaxAgeSeconds": 3000,
    "ExposeHeader": ["x-amz-server-side-encryption"]
}


def build_xml(rules):
    """Convert dict to xml"""
    def tuple_to_xml(val, node, key):
        if isinstance(val[key], str):
            val[key] = [val[key]]
        for v in val[key]:
            ET.SubElement(node, key).text = v
    root = ET.Element(
        'CORSConfiguration',
        attrib={'xmlns': 'http://s3.amazonaws.com/doc/2006-03-01/'})
    if isinstance(rules, dict):
        rules = [rules]

    for item in rules:
        rule = ET.SubElement(root, 'CORSRule')
        ET.SubElement(rule, "AllowedOrigin").text = item['AllowedOrigin']
        tuple_to_xml(item, rule, "AllowedHeader")
        tuple_to_xml(item, rule, "AllowedMethod")
        ET.SubElement(rule, "MaxAgeSeconds").text = str(item["MaxAgeSeconds"])
        tuple_to_xml(item, rule, "ExposeHeader")

    return ET.tostring(root)


class TestS3Cors(S3TestCase):
    def setUp(self):
        super(TestS3Cors, self).setUp()

    def _cors_GET(self, path):
        req = Request.blank('%s?cors' % path,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, headers, body = self.call_s3api(req)
        return status, headers, body

    def _cors_PUT(self, path, cors):
        xml = build_xml(cors)
        req = Request.blank('%s?cors' % path,
                            environ={'REQUEST_METHOD': 'PUT'},
                            body=xml,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, headers, body = self.call_s3api(req)
        return status, headers, body

    def _options(self, path, headers=None):
        hdrs = {'Authorization': 'AWS test:tester:hmac',
                'Date': self.get_date_header()}
        if headers:
            hdrs.update(headers)
        req = Request.blank(path,
                            environ={'REQUEST_METHOD': 'OPTIONS'},
                            headers=hdrs)
        status, headers, body = self.call_s3api(req)
        return status, headers, body

    def test_missing_cors(self):
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {}, None)
        ret = self._cors_GET('/test-cors')
        self.assertEqual(self._get_error_code(ret[2]),
                         'NoSuchCORSConfiguration')

    def test_invalid_AllowedOrigin(self):
        rule = RULE.copy()
        rule['AllowedOrigin'] = 'http://*.example.*'

        ret = self._cors_PUT('/test-cors', cors=rule)
        self.assertEqual(self._get_error_code(ret[2]),
                         'CORSInvalidRequest')
        self.assertIn('AllowedOrigin', ret[2])

    def test_invalid_ExposeHeader(self):
        rule = RULE.copy()
        rule['ExposeHeader'] = 'amz-*'

        ret = self._cors_PUT('/test-cors', cors=rule)
        self.assertEqual(self._get_error_code(ret[2]),
                         'CORSInvalidRequest')
        self.assertIn('ExposeHeader', ret[2])

    def test_invalid_AllowedHeader(self):
        rule = RULE.copy()
        rule['AllowedHeader'] = 'x-ping-*-private-*'

        ret = self._cors_PUT('/test-cors', cors=rule)
        self.assertEqual(self._get_error_code(ret[2]),
                         'CORSInvalidRequest')
        self.assertIn('AllowedHeader', ret[2])

    def test_invalid_AllowedMethod(self):
        rule = RULE.copy()
        rule['AllowedMethod'] = ['PUT', 'PATCH', 'OPTIONS']

        ret = self._cors_PUT('/test-cors', cors=rule)
        self.assertEqual(self._get_error_code(ret[2]),
                         'CORSInvalidRequest')
        self.assertIn('unsupported HTTP method', ret[2])

    def test_put_get(self):
        self.swift.register('POST', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {}, None)

        ret = self._cors_PUT('/test-cors', cors=RULE)
        self.assertEqual(ret[0], '200 OK')

        xml = build_xml(RULE)
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {BUCKET_CORS_HEADER: xml}, None)

        ret = self._cors_GET('/test-cors')
        self.assertEqual(ret[2], xml)

    def test_options_missing_origin(self):
        ret = self._options('/test-cors/obj')
        self.assertEqual(ret[0], '400 Bad Request')
        self.assertIn('CORSOriginMissing', ret[2])

    def test_options_missing_access_control_request(self):
        ret = self._options('/test-cors/obj',
                            {'Origin': 'http://example.com'})
        self.assertEqual(ret[0], '400 Bad Request')
        self.assertIn('CORSInvalidAccessControlRequest', ret[2])

    def test_options_invalid_access_control_request(self):
        ret = self._options('/test-cors/obj',
                            {'Origin': 'http://example.com',
                             'Access-Control-Request-Method': 'PATCH'})
        self.assertEqual(ret[0], '400 Bad Request')
        self.assertIn('CORSInvalidAccessControlRequest', ret[2])

    def test_options_notfound_origin(self):
        xml = build_xml(RULE)
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {BUCKET_CORS_HEADER: xml}, None)
        ret = self._options('/test-cors/obj',
                            {'Origin': 'http://example.com:80',
                             'Access-Control-Request-Method': 'POST'})
        self.assertEqual(ret[0], '403 Forbidden')
        self.assertIn('CORSForbidden', ret[2])

    def test_options_notfound_method(self):
        xml = build_xml(RULE)
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {BUCKET_CORS_HEADER: xml}, None)
        ret = self._options('/test-cors/obj',
                            {'Origin': 'http://www.example.com',
                             'Access-Control-Request-Method': 'GET'})
        self.assertEqual(ret[0], '403 Forbidden')
        self.assertIn('CORSForbidden', ret[2])

    def test_options_invalid_method(self):
        xml = build_xml(RULE)
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {BUCKET_CORS_HEADER: xml}, None)
        ret = self._options('/test-cors/obj',
                            {'Origin': 'http://www.example.com',
                             'Access-Control-Request-Method': 'XXX'})
        self.assertEqual(ret[0], '400 Bad Request')
        self.assertIn('CORSInvalidAccessControlRequest', ret[2])

    def test_options_allowed(self):
        xml = build_xml(RULE)
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {BUCKET_CORS_HEADER: xml}, None)
        ret = self._options('/test-cors/obj',
                            {'Origin': 'http://www.example.com',
                             'Access-Control-Request-Method': 'POST'})
        self.assertEqual(ret[0], '200 OK')
        self.assertEqual(ret[1]['Access-Control-Allow-Origin'],
                         'http://www.example.com')
        self.assertEqual(ret[1]['Access-Control-Allow-Methods'],
                         'PUT, POST, DELETE')
        self.assertEqual(ret[1]['Access-Control-Max-Age'], '3000')
        self.assertEqual(ret[1]['Access-Control-Allow-Credentials'], 'true')
        self.assertEqual(ret[1]['Access-Control-Expose-Headers'],
                         'x-amz-server-side-encryption')

    def test_options_wildcard(self):
        r1 = RULE.copy()
        r1['AllowedOrigin'] = 'https://*.example.com'
        xml = build_xml(r1)
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {BUCKET_CORS_HEADER: xml}, None)
        ret = self._options('/test-cors/obj',
                            {'Origin': 'https://sub.example.com',
                             'Access-Control-Request-Method': 'POST'})
        self.assertEqual(ret[0], '200 OK')

    def test_options_invalid_wildcard(self):
        r1 = RULE.copy()
        r1['AllowedOrigin'] = 'https://*.example.com'
        xml = build_xml(r1)
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {BUCKET_CORS_HEADER: xml}, None)
        ret = self._options('/test-cors/obj',
                            {'Origin': 'https://subexample.com',
                             'Access-Control-Request-Method': 'POST'})
        self.assertEqual(ret[0], '403 Forbidden')

    def test_options_multiple_rules(self):
        r1 = RULE.copy()
        r1['AllowedOrigin'] = 'https://www.ssl.org'
        xml = build_xml([RULE, r1])
        self.swift.register('HEAD', '/v1/AUTH_test/test-cors',
                            HTTPNoContent, {BUCKET_CORS_HEADER: xml}, None)
        ret = self._options('/test-cors/obj',
                            {'Origin': 'https://www.ssl.org',
                             'Access-Control-Request-Method': 'POST'})
        self.assertEqual(ret[0], '200 OK')

if __name__ == '__main__':
    unittest.main()
