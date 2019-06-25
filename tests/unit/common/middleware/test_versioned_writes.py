import os.path
import sys
from swift.common import swob
from swift.common.swob import Request
from oioswift.common.middleware import versioned_writes

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__, '../../../../..')))  # noqa: E402 E501
import test  # noqa: E402, F401
from test.unit.common.middleware import test_versioned_writes as test_vw
from test.unit.common.middleware.test_versioned_writes import FakeCache


class OioVersionedWritesTestCase(test_vw.VersionedWritesTestCase):

    def setUp(self):
        test.unit.common.middleware.test_versioned_writes.versioned_writes = \
            versioned_writes
        super(OioVersionedWritesTestCase, self).setUp()

    def test_put_first_object_success(self):
        self.app.register(
            'PUT', '/v1/a/c/o', swob.HTTPOk, {}, 'passed')
        self.app.register(
            'GET', '/v1/a/c/o', swob.HTTPNotFound, {}, None)

        cache = FakeCache({'sysmeta': {'versions-location': 'ver_cont'}})
        req = Request.blank(
            '/v1/a/c/o',
            environ={'REQUEST_METHOD': 'PUT', 'swift.cache': cache,
                     'CONTENT_LENGTH': '100',
                     'swift.trans_id': 'fake_trans_id'})
        status, headers, body = self.call_vw(req)
        self.assertEqual(status, '200 OK')
        self.assertEqual(len(self.authorized), 1)
        self.assertRequestEqual(req, self.authorized[0])
        self.assertEqual(1, self.app.call_count)
        self.assertEqual([None], self.app.swift_sources)
        self.assertEqual({'fake_trans_id'}, set(self.app.txn_ids))

    def test_put_request_is_dlo_manifest_with_container_config_true(self):
        # oio-swift's versioned_writes does not use a version container,
        # but relies on oio-sds versioning features. It does not do a GET
        # request since this will be checked internally by oio-sds.
        self.app.register(
            'PUT', '/v1/a/c/o', swob.HTTPCreated, {}, 'passed')
        self.app.register(
            'GET', '/v1/a/c/o', swob.HTTPOk,
            {'last-modified': 'Thu, 1 Jan 1970 00:01:00 GMT'}, 'old version')
        # self.app.register(
        #     'PUT', '/v1/a/ver_cont/001o/0000000060.00000', swob.HTTPCreated,
        #     {}, '')
        cache = FakeCache({'versions': 'ver_cont'})
        req = Request.blank(
            '/v1/a/c/o',
            headers={'X-Object-Manifest': 'req/manifest'},
            environ={'REQUEST_METHOD': 'PUT', 'swift.cache': cache,
                     'CONTENT_LENGTH': '100'})
        status, headers, body = self.call_vw(req)
        self.assertEqual(status, '201 Created')
        # self.assertEqual(len(self.authorized), 2)
        self.assertEqual(len(self.authorized), 1)
        self.assertRequestEqual(req, self.authorized[0])
        # self.assertRequestEqual(req, self.authorized[1])
        # self.assertEqual(3, self.app.call_count)
        self.assertEqual(1, self.app.call_count)
        self.assertEqual([
            # ('GET', '/v1/a/c/o'),
            # ('PUT', '/v1/a/ver_cont/001o/0000000060.00000'),
            ('PUT', '/v1/a/c/o'),
        ], self.app.calls)
        self.assertIn('x-object-manifest',
                      # self.app.calls_with_headers[2].headers)
                      self.app.calls_with_headers[0].headers)

    def test_put_version_is_dlo_manifest_with_container_config_true(self):
        self.skipTest("Disabled for oio-swift")

    def test_new_version_success(self):
        self.app.register(
            'PUT', '/v1/a/c/o', swob.HTTPCreated, {}, 'passed')
        self.app.register(
            'GET', '/v1/a/c/o', swob.HTTPOk,
            {'last-modified': 'Thu, 1 Jan 1970 00:00:01 GMT'}, 'passed')
        self.app.register(
            'PUT', '/v1/a/ver_cont/001o/0000000001.00000', swob.HTTPCreated,
            {}, None)
        cache = FakeCache({'sysmeta': {'versions-location': 'ver_cont'}})
        req = Request.blank(
            '/v1/a/c/o',
            environ={'REQUEST_METHOD': 'PUT', 'swift.cache': cache,
                     'CONTENT_LENGTH': '100',
                     'swift.trans_id': 'fake_trans_id'})
        status, headers, body = self.call_vw(req)
        self.assertEqual(status, '201 Created')
        # authorized twice now because versioned_writes now makes a check on
        # PUT
        self.assertEqual(len(self.authorized), 1)
        self.assertRequestEqual(req, self.authorized[0])
        self.assertEqual([None], self.app.swift_sources)
        self.assertEqual({'fake_trans_id'}, set(self.app.txn_ids))

    def test_new_version_get_errors(self):
        self.skipTest("Disabled for oio-swift")

    def test_new_version_put_errors(self):
        self.skipTest("Disabled for oio-swift")

    def test_new_version_sysmeta_precedence(self):
        self.skipTest("Disabled for oio-swift")

    def test_delete_no_versions_container_success(self):
        self.skipTest("Disabled for oio-swift")

    def test_delete_first_object_success(self):
        self.app.register(
            'DELETE', '/v1/a/c/o', swob.HTTPOk, {}, 'passed')
        self.app.register(
            'GET',
            '/v1/a/ver_cont?format=json&prefix=001o/&marker=&reverse=on',
            swob.HTTPOk, {}, '[]')

        cache = FakeCache({'sysmeta': {'versions-location': 'ver_cont'}})
        req = Request.blank(
            '/v1/a/c/o',
            environ={'REQUEST_METHOD': 'DELETE', 'swift.cache': cache,
                     'CONTENT_LENGTH': '0'})
        status, headers, body = self.call_vw(req)
        self.assertEqual(status, '200 OK')
        self.assertEqual(len(self.authorized), 1)
        self.assertRequestEqual(req, self.authorized[0])

        self.assertEqual(self.app.calls, [
            ('DELETE', '/v1/a/c/o'),
        ])

    def test_delete_latest_version_no_marker_success(self):
        self.skipTest("Disabled for oio-swift")

    def test_delete_latest_version_restores_marker_success(self):
        self.skipTest("Disabled for oio-swift")

    def test_delete_latest_version_is_marker_success(self):
        self.skipTest("Disabled for oio-swift")

    def test_delete_latest_version_doubled_up_markers_success(self):
        self.skipTest("Disabled for oio-swift")

    def test_history_delete_marker_no_object_success(self):
        self.skipTest("Disabled for oio-swift")

    def test_history_delete_marker_over_object_success(self):
        self.skipTest("Disabled for oio-swift")

    def test_delete_single_version_success(self):
        self.skipTest("Disabled for oio-swift")

    def test_DELETE_on_expired_versioned_object(self):
        self.skipTest("Disabled for oio-swift")

    def test_denied_DELETE_of_versioned_object(self):
        self.skipTest("Disabled for oio-swift")

    def test_list_no_versions_with_delimiter(self):
        self.app.register(
            'GET',
            '/v1/a/c?delimiter=%2F&format=json',
            swob.HTTPOk, {},
            '''[
                {"subdir": "v1/"},
                {"hash": "8de4989188593b0419d387099c9e9872",
                 "name": "magic",
                 "last_modified": "2018-11-14T16:20:43.000000",
                 "bytes": 113,
                 "version": 1542212443748591,
                 "content_type": "text/plain"}
            ]''')
        cache = FakeCache({'sysmeta': {
            'versions-location': 'c' + versioned_writes.VERSIONING_SUFFIX}})
        req = Request.blank(
            '/v1/a/c' + versioned_writes.VERSIONING_SUFFIX + '?delimiter=%2F',
            environ={'REQUEST_METHOD': 'GET', 'swift.cache': cache,
                     'CONTENT_LENGTH': '0'})
        status, _headers, body = self.call_vw(req)
        self.assertEqual(status, '200 OK')
        # Subdir should be listed here, but the object is the latest
        # version, and should not be listed either.
        self.assertEqual('[{"subdir": "v1/"}]', body)
