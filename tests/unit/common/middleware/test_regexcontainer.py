import os.path
import sys
import unittest
from swift.common import swob, utils
from swift.common.swob import Request
from oioswift.common.middleware import regexcontainer
from oio.common.autocontainer import ContainerBuilder

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__, '../../../../..')))  # noqa
from test.unit.common.middleware.helpers import FakeSwift


class OioRegexContainer(unittest.TestCase):
    def setUp(self):
        conf = {'sds_default_account': 'OPENIO'}
        self.filter_conf = {
            'strip_v1': 'true',
            'swift3_compat': 'true',
            'account_first': 'true',
            'stop_at_first_match': 'true',
            'pattern1': r'(\d{3})/(\d{3})/(\d)\d\d/\d\d(\d)/',
            'pattern2': r'(\d{3})/(\d)\d\d/\d\d(\d)/',
            'pattern3': r'^(cloud)/([0-9a-f][0-9a-f])',
            'pattern4': r'^(cloud)/([0-9a-f])',
            'pattern9': r'^/?([^/]+)',
        }

        if hasattr(ContainerBuilder, 'alternatives'):
            self.filter_conf['stop_at_first_match'] = 'false'

        self.app = FakeSwift()
        self.ch = regexcontainer.filter_factory(
            conf,
            **self.filter_conf)(self.app)

    def tearDown(self):
        pass

    def call_app(self, req, app=None):
        if app is None:
            app = self.app

        self.authorized = []

        def authorize(req):
            self.authorized.append(req)

        if 'swift.authorize' not in req.environ:
            req.environ['swift.authorize'] = authorize

        req.headers.setdefault("User-Agent", "Melted Cheddar")

        status = [None]
        headers = [None]

        def start_response(s, h, ei=None):
            status[0] = s
            headers[0] = h

        body_iter = app(req.environ, start_response)
        with utils.closing_if_possible(body_iter):
            body = b''.join(body_iter)

        return status[0], headers[0], body

    def call_rc(self, req):
        return self.call_app(req, app=self.ch)

    def _check_pattern(self, path_in, path_out):
        self.app.register('PUT', path_out, swob.HTTPCreated, {})
        req = Request.blank(path_in, method='PUT')
        resp = self.call_rc(req)
        self.assertEqual(resp[0], "201 Created")
        self.assertEqual(self.app.calls, [('PUT', path_out)])

    def test_pattern1(self):
        self._check_pattern(
            '/v1/a/c/111/222/456/789/o',
            '/v1/a/11122249/111/222/456/789/o')

    def test_pattern2(self):
        if self.filter_conf['stop_at_first_match'] == 'true':
            self.skipTest("require openio-sds >= 4.2")
        self.app.register('GET', '/v1/a/11122249/111/222/456/789/o',
                          swob.HTTPNotFound, {})
        self.app.register('GET', '/v1/a/11126/111/222/456/789/o',
                          swob.HTTPOk, {})
        req = Request.blank('/v1/a/c/111/222/456/789/o', method='GET')
        resp = self.call_rc(req)
        self.assertEqual(resp[0], "200 OK")
        self.assertEqual(
            self.app.calls,
            [('GET', '/v1/a/11122249/111/222/456/789/o'),
             ('GET', '/v1/a/11126/111/222/456/789/o')])

    def test_pattern3(self):
        self._check_pattern('/v1/a/c/cloud/ff_object',
                            '/v1/a/cloudff/cloud/ff_object')

    def test_pattern4(self):
        if self.filter_conf['stop_at_first_match'] == 'true':
            self.skipTest("require openio-sds >= 4.2")
        self.app.register('GET', '/v1/a/cloudff/cloud/ff_object',
                          swob.HTTPNotFound, {})
        self.app.register('GET', '/v1/a/cloudf/cloud/ff_object',
                          swob.HTTPOk, {})
        req = Request.blank('/v1/a/c/cloud/ff_object', method='GET')
        resp = self.call_rc(req)
        self.assertEqual(resp[0], "200 OK")
        self.assertEqual(
            self.app.calls,
            [('GET', '/v1/a/cloudff/cloud/ff_object'),
             ('GET', '/v1/a/cloudf/cloud/ff_object')])

    def test_pattern9(self):
        self._check_pattern('/v1/a/c/gc_regex/path/ob',
                            '/v1/a/gc_regex/gc_regex/path/ob')

    def test_get_without_matching_pattern(self):
        if self.filter_conf['stop_at_first_match'] == 'true':
            self.skipTest("require openio-sds >= 4.2")
        self.app.register('GET', '/v1/a/11122249/111/222/456/789/o',
                          swob.HTTPNotFound, {})
        self.app.register('GET', '/v1/a/11126/111/222/456/789/o',
                          swob.HTTPNotFound, {})
        self.app.register('GET', '/v1/a/111/111/222/456/789/o',
                          swob.HTTPNotFound, {})
        req = Request.blank('/v1/a/c/111/222/456/789/o', method='GET')
        resp = self.call_rc(req)
        self.assertEqual(resp[0], "404 Not Found")
        self.assertEqual(
            self.app.calls,
            [('GET', '/v1/a/11122249/111/222/456/789/o'),
             ('GET', '/v1/a/11126/111/222/456/789/o'),
             ('GET', '/v1/a/111/111/222/456/789/o')])

    def test_simple_listing(self):
        self._check_pattern('/v1/a/c/111/222/456/789/o',
                            '/v1/a/11122249/111/222/456/789/o')

        self.app.register('GET',
                          '/v1/a/11122249?prefix=/111/222/456/789/o',
                          swob.HTTPOk, {})

        req = Request.blank('/v1/a/c?prefix=/111/222/456/789/o', method='GET')
        resp = self.call_rc(req)
        self.assertEqual(resp[0], '200 OK')

    def test_fallback_listing(self):
        if self.filter_conf['stop_at_first_match'] == 'true':
            self.skipTest("require openio-sds >= 4.2")

        self.app.register('GET',
                          '/v1/a/11122249?prefix=/111/222/456/789/o',
                          swob.HTTPNotFound, {})
        self.app.register('GET',
                          '/v1/a/11126?prefix=/111/222/456/789/o',
                          swob.HTTPOk, {})

        req = Request.blank('/v1/a/c?prefix=/111/222/456/789/o', method='GET')
        resp = self.call_rc(req)
        self.assertEqual(resp[0], '200 OK')
        self.assertEqual(
            self.app.calls,
            [('GET', '/v1/a/11122249?prefix=/111/222/456/789/o'),
             ('GET', '/v1/a/11126?prefix=/111/222/456/789/o')])

    def test_swift3_mpu(self):
        self.app.register('PUT',
                          '/v1/a/cloudff+segments/cloud/ff_object',
                          swob.HTTPOk, {})
        req = Request.blank(
            '/v1/a/c+segments/cloud/ff_object', method='PUT')
        resp = self.call_rc(req)
        self.assertEqual(resp[0], '200 OK')

    def test_copy(self):
        self.app.register('PUT',
                          '/v1/a/cloudff/cloud/ff_object',
                          swob.HTTPOk, {})
        req = Request.blank(
            '/v1/a/c/cloud/ff_object', method='PUT',
            headers={'X-Copy-From': 'container/path/dir1/object'})
        resp = self.call_rc(req)
        self.assertEqual(resp[0], '200 OK')
        self.assertEqual(self.app.headers[0]['X-Copy-From'],
                         "/dir1/dir1/object")

    def test_fastcopy(self):
        self.app.register('PUT',
                          '/v1/a/cloudff/cloud/ff_object',
                          swob.HTTPOk, {})
        req = Request.blank('/v1/a/c/cloud/ff_object', method='PUT',
                            headers={'Oio-Copy-From': 'container/path/object'})
        resp = self.call_rc(req)
        self.assertEqual(resp[0], '200 OK')
        self.assertEqual(self.app.headers[0]['Oio-Copy-From'],
                         "/object/object")
