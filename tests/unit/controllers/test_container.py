import unittest
from mock import patch
from mock import MagicMock as Mock

from oioswift.common.ring import FakeRing
from oioswift import server as proxy_server
from swift.common.swob import Request
from swift.proxy.controllers.base import headers_to_container_info
from swift.common.request_helpers import get_sys_meta_prefix

from tests.unit import FakeStorageAPI, FakeMemcache, debug_logger


class TestContainerController(unittest.TestCase):
    def setUp(self):

        self.logger = debug_logger('proxy-server')
        self.storage = FakeStorageAPI()

        self.account_info = {
            'status': 200,
            'container_count': '10',
            'total_object_count': '100',
            'bytes': '1000',
            'meta': {},
            'sysmeta': {}
        }

        self.app = proxy_server.Application(
            None, FakeMemcache(), account_ring=FakeRing(),
            container_ring=FakeRing(), storage=self.storage,
            logger=self.logger)

        class FakeAccountInfoContainerController(
                proxy_server.ContainerController):

            def account_info(controller, *args, **kwargs):
                patch_path = 'swift.proxy.controllers.base.get_info'
                with patch(patch_path) as mock_get_info:
                    mock_get_info.return_value = dict(self.account_info)
                    return super(FakeAccountInfoContainerController,
                                 controller).account_info(
                                    *args, **kwargs)
        _orig_get_controller = self.app.get_controller

        def wrapped_get_controller(*args, **kwargs):
            with patch('swift.proxy.server.ContainerController',
                       new=FakeAccountInfoContainerController):
                return _orig_get_controller(*args, **kwargs)
        self.app.get_controller = wrapped_get_controller

    def test_container_info(self):
        req = Request.blank('/v1/a/c', {'PATH_INFO': '/v1/a/c'}, method='HEAD')
        self.storage.container_show = Mock(return_value={})
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        self.assertTrue('swift.container/a/c' in resp.environ)
        self.assertEqual(
            headers_to_container_info(resp.headers, resp.status_int),
            resp.environ['swift.container/a/c'])

    def test_swift_owner(self):
        owner_headers = {
            'x-container-read': 'value', 'x-container-write': 'value',
            'x-container-sync-key': 'value', 'x-container-sync-to': 'value'}
        req = Request.blank('/v1/a/c', method='HEAD')
        meta = {}
        meta.update(('user.' + k, v) for k, v in owner_headers.iteritems())
        self.storage.container_show = Mock(return_value=meta)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        for k in owner_headers:
            self.assertTrue(k not in resp.headers)

        req = Request.blank(
            '/v1/a/c', environ={'swift_owner': True}, method='HEAD')
        self.storage.container_show = Mock(return_value=meta)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        for k in owner_headers:
            self.assertTrue(k in resp.headers)

    def test_sys_meta_headers_PUT(self):
        sys_meta_key = '%stest' % get_sys_meta_prefix('container')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Container-Meta-Test'

        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a/c', headers=hdrs_in, method='PUT')
        self.storage.container_create = Mock()
        req.get_response(self.app)
        meta = self.storage.container_create.call_args[1]['metadata']
        self.assertEqual(meta['user.' + sys_meta_key], 'foo')
        self.assertEqual(meta['user.' + user_meta_key], 'bar')

    def test_sys_meta_headers_POST(self):
        # check that headers in sys meta namespace make it through
        # the container controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('container')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Container-Meta-Test'
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a/c', headers=hdrs_in, method='POST')
        self.storage.container_set_properties = Mock()
        req.get_response(self.app)
        meta = self.storage.container_set_properties.call_args[0][2]
        self.assertEqual(meta['user.' + sys_meta_key], 'foo')
        self.assertEqual(meta['user.' + user_meta_key], 'bar')
