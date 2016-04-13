import unittest
from mock import MagicMock as Mock

from swift.common import constraints
from swift.common.swob import Request
from swift.common.request_helpers import get_sys_meta_prefix
from swift.proxy.controllers.base import headers_to_account_info
from oioswift.common.ring import FakeRing
from oioswift import server as proxy_server
from tests.unit import FakeStorageAPI, FakeMemcache, debug_logger


def get_fake_info(meta={}):
        info = {
                'ctime': 0,
                'containers': 2,
                'objects': 2,
                'bytes': 2,
                'metadata': meta
        }
        return info


class TestAccountController(unittest.TestCase):
    def setUp(self):
        self.logger = debug_logger('proxy-server')
        self.storage = FakeStorageAPI()

        self.app = proxy_server.Application(
            None, FakeMemcache(),
            account_ring=FakeRing(), container_ring=FakeRing(),
            storage=self.storage, logger=self.logger)

    def test_account_info(self):
        req = Request.blank(
            '/v1/AUTH_openio', {'PATH_INFO': '/v1/AUTH_openio'}, method='HEAD')

        info = get_fake_info()
        self.storage.account_show = Mock(return_value=info)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        self.assertTrue('swift.account/AUTH_openio' in resp.environ)
        self.assertEqual(
            headers_to_account_info(resp.headers, resp.status_int),
            resp.environ['swift.account/AUTH_openio'])

    def test_swift_owner(self):
        owner_headers = {
            'x-account-meta-temp-url-key': 'value',
            'x-account-meta-temp-url-key-2': 'value'}

        req = Request.blank('/v1/a', method='HEAD')
        info = get_fake_info(owner_headers)
        self.storage.account_show = Mock(return_value=info)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        for key in owner_headers:
            self.assertTrue(key not in resp.headers)

        req = Request.blank(
            '/v1/a', environ={'swift_owner': True}, method='HEAD')
        info = get_fake_info(owner_headers)
        self.storage.account_show = Mock(return_value=info)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        for key in owner_headers:
            self.assertTrue(key in resp.headers)

    def test_long_acct_names(self):
        long_acct_name = '%sLongAccountName' % (
            'Very' * (constraints.MAX_ACCOUNT_NAME_LENGTH // 4))

        req = Request.blank('/v1/%s' % long_acct_name, method='HEAD')
        self.storage.account_show = Mock()
        resp = req.get_response(self.app)
        self.assertEqual(400, resp.status_int)

        req = Request.blank('/v1/%s' % long_acct_name, method='GET')
        self.storage.account_show = Mock()
        resp = req.get_response(self.app)
        self.assertEqual(400, resp.status_int)

        req = Request.blank('/v1/%s' % long_acct_name, method='POST')
        self.storage.account_show = Mock()
        resp = req.get_response(self.app)
        self.assertEqual(400, resp.status_int)

    def test_sys_meta_headers_PUT(self):
        # check that headers in sys meta namespace make it through
        # the proxy controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('account')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Account-Meta-Test'
        # allow PUTs to account...
        self.app.allow_account_management = True
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a', headers=hdrs_in, method='PUT')
        self.storage.account_create = Mock()
        self.storage.account_update = Mock()
        req.get_response(self.app)
        meta = self.storage.account_update.call_args[0][1]
        self.assertEqual(meta[sys_meta_key], 'foo')
        self.assertEqual(meta[user_meta_key], 'bar')

    def test_sys_meta_headers_POST(self):
        # check that headers in sys meta namespace make it through
        # the proxy controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('account')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Account-Meta-Test'
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a', headers=hdrs_in, method='POST')
        self.storage.account_update = Mock()
        req.get_response(self.app)
        meta = self.storage.account_update.call_args[0][1]
        self.assertEqual(meta[sys_meta_key], 'foo')
        self.assertEqual(meta[user_meta_key], 'bar')

    def test_stripping_swift_admin_headers(self):
        # Verify that a GET/HEAD which receives privileged headers from the
        # account server will strip those headers for non-swift_owners

        meta = {
            'x-account-meta-harmless': 'hi mom',
            'x-account-meta-temp-url-key': 's3kr1t',
        }
        info = get_fake_info(meta)
        self.storage.account_show = Mock(return_value=info)
        l = ({}, info)
        self.storage.container_list = Mock(return_value=l)

        for verb in ('GET', 'HEAD'):
            for env in ({'swift_owner': True}, {'swift_owner': False}):
                req = Request.blank('/v1/acct', environ=env, method=verb)
                resp = req.get_response(self.app)
                self.assertEqual(resp.headers.get('x-account-meta-harmless'),
                                 'hi mom')
                privileged_header_present = (
                    'x-account-meta-temp-url-key' in resp.headers)
                self.assertEqual(privileged_header_present, env['swift_owner'])
