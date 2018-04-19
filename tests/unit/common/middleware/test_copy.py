#!/usr/bin/env python
# Copyright (c) 2015 OpenStack Foundation
# Copyright (c) 2018 OpenIO SAS
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

import os.path
import sys

from six.moves import urllib

from swift.common import swob
from swift.common.swob import Request
from oioswift.common.middleware import copy

# noqa: E402
# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__, '../../../../..')))
import test  # noqa: F401
from test.unit.common.middleware.helpers import FakeSwift
from test.unit.common.middleware.test_copy import TestServerSideCopyMiddleware


class TestOioServerSideCopyMiddleware(TestServerSideCopyMiddleware):

    def setUp(self):
        self.app = FakeSwift()
        self.ssc = copy.filter_factory({
            'object_post_as_copy': 'yes',
        })(self.app)
        self.ssc.logger = self.app.logger

    def tearDown(self):
        # get_object_info() does not close response iterator,
        # thus we have to disable the unclosed_requests test.
        pass

    def test_basic_put_with_x_copy_from(self):
        self.app.register('HEAD', '/v1/a/c/o', swob.HTTPOk, {})
        self.app.register('PUT', '/v1/a/c/o2', swob.HTTPCreated, {})
        req = Request.blank('/v1/a/c/o2', environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Content-Length': '0',
                                     'X-Copy-From': 'c/o'})
        status, headers, body = self.call_ssc(req)
        self.assertEqual(status, '201 Created')
        self.assertTrue(('X-Copied-From', 'c/o') in headers)
        self.assertEqual(len(self.authorized), 1)
        self.assertEqual('PUT', self.authorized[0].method)
        self.assertEqual('/v1/a/c/o2', self.authorized[0].path)
        self.assertEqual(self.app.swift_sources[0], 'SSC')
        # For basic test cases, assert orig_req_method behavior
        self.assertNotIn('swift.orig_req_method', req.environ)

    def test_static_large_object_manifest(self):
        self.skipTest('To be fixed')

    def test_static_large_object(self):
        self.app.register('HEAD', '/v1/a/c/o', swob.HTTPOk,
                          {'X-Static-Large-Object': 'True',
                           'Etag': 'should not be sent'})
        self.app.register('PUT', '/v1/a/c/o2',
                          swob.HTTPCreated, {})
        req = Request.blank('/v1/a/c/o2',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Content-Length': '0',
                                     'X-Copy-From': 'c/o'})
        status, headers, body = self.call_ssc(req)
        self.assertEqual(status, '201 Created')
        self.assertTrue(('X-Copied-From', 'c/o') in headers)
        self.assertEqual(self.app.calls, [
            ('HEAD', '/v1/a/c/o'),
            ('PUT', '/v1/a/c/o2')])
        req_headers = self.app.headers[1]
        self.assertNotIn('X-Static-Large-Object', req_headers)
        self.assertNotIn('Etag', req_headers)
        self.assertEqual(len(self.authorized), 1)
        self.assertEqual('PUT', self.authorized[0].method)
        self.assertEqual('/v1/a/c/o2', self.authorized[0].path)

    def test_basic_put_with_x_copy_from_across_container(self):
        self.app.register('HEAD', '/v1/a/c1/o1', swob.HTTPOk, {})
        self.app.register('PUT', '/v1/a/c2/o2', swob.HTTPCreated, {})
        req = Request.blank('/v1/a/c2/o2', environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Content-Length': '0',
                                     'X-Copy-From': 'c1/o1'})
        status, headers, body = self.call_ssc(req)
        self.assertEqual(status, '201 Created')
        self.assertTrue(('X-Copied-From', 'c1/o1') in headers)
        self.assertEqual(len(self.authorized), 1)
        self.assertEqual('PUT', self.authorized[0].method)
        self.assertEqual('/v1/a/c2/o2', self.authorized[0].path)

    def test_basic_put_with_x_copy_from_across_container_and_account(self):
        self.app.register('HEAD', '/v1/a1/c1/o1', swob.HTTPOk, {})
        self.app.register('PUT', '/v1/a2/c2/o2', swob.HTTPCreated, {},
                          'passed')
        req = Request.blank('/v1/a2/c2/o2', environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Content-Length': '0',
                                     'X-Copy-From': 'c1/o1',
                                     'X-Copy-From-Account': 'a1'})
        status, headers, body = self.call_ssc(req)
        self.assertEqual(status, '201 Created')
        self.assertTrue(('X-Copied-From', 'c1/o1') in headers)
        self.assertTrue(('X-Copied-From-Account', 'a1') in headers)
        self.assertEqual(len(self.authorized), 1)
        self.assertEqual('PUT', self.authorized[0].method)
        self.assertEqual('/v1/a2/c2/o2', self.authorized[0].path)

    def test_copy_not_found_reading_source(self):
        self.skipTest('To be fixed')

    def test_copy_not_found_reading_source_and_account(self):
        self.skipTest('To be fixed')

    def test_copy_server_error_reading_source(self):
        self.skipTest('To be fixed')

    def test_copy_server_error_reading_source_and_account(self):
        self.skipTest('To be fixed')

    def test_copy_source_larger_than_max_file_size(self):
        self.skipTest('To be fixed')

    def test_COPY_source_metadata(self):
        self.skipTest('To be fixed')

    def test_copy_with_leading_slash_and_slashes_in_x_copy_from(self):
        self.skipTest('To be fixed')

    def test_copy_with_leading_slash_and_slashes_in_x_copy_from_acct(self):
        self.skipTest('To be fixed')

    def test_copy_with_leading_slash_in_x_copy_from(self):
        self.skipTest('To be fixed')

    def test_copy_with_leading_slash_in_x_copy_from_and_account(self):
        self.skipTest('To be fixed')

    def test_copy_with_object_metadata(self):
        self.skipTest('To be fixed')

    def test_copy_with_object_metadata_and_account(self):
        self.skipTest('To be fixed')

    def test_copy_with_slashes_in_x_copy_from(self):
        self.skipTest('To be fixed')

    def test_copy_with_slashes_in_x_copy_from_and_account(self):
        self.skipTest('To be fixed')

    def test_copy_with_spaces_in_x_copy_from(self):
        self.skipTest('To be fixed')

    def test_copy_with_spaces_in_x_copy_from_and_account(self):
        self.skipTest('To be fixed')
