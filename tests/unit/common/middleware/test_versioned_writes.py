# Hack PYTHONPATH so "test" is swift's test directory
import os.path
import sys
from swift.common import swob
from swift.common.swob import Request
from oioswift.common.middleware import versioned_writes

sys.path.insert(1, os.path.abspath(os.path.join(__file__, '../../../../..')))
import test
from test.unit.common.middleware.test_versioned_writes import \
    VersionedWritesTestCase, FakeCache, local_tz


class OioVersionedWritesTestCase(VersionedWritesTestCase):

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
