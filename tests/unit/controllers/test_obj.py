from mock import MagicMock as Mock
from mock import patch
import unittest

from oiopy import fakes
from oiopy import exceptions as exc
from eventlet import Timeout
from swift.proxy.controllers.base import get_info as _real_get_info
from swift.common.swob import Request
from oioswift.common.ring import FakeRing
from oioswift import server as proxy_server
from tests.unit import FakeStorageAPI, FakeMemcache, debug_logger


def fake_stream(l):
    for i in "X"*l:
        yield i


def fake_prepare_meta():
    return {
        'x-oio-content-meta-id': '',
        'x-oio-content-meta-version': '',
        'x-oio-content-meta-policy': '',
        'x-oio-content-meta-mime-type': '',
        'x-oio-content-meta-chunk-method': '',
    }


class PatchedObjControllerApp(proxy_server.Application):
    container_info = {}
    per_container_info = {}

    def __call__(self, *args, **kwargs):

        def _fake_get_info(app, env, account, container=None, **kwargs):
            if container:
                if container in self.per_container_info:
                    return self.per_container_info[container]
                return self.container_info
            else:
                return _real_get_info(app, env, account, container, **kwargs)

        mock_path = 'swift.proxy.controllers.base.get_info'
        with patch(mock_path, new=_fake_get_info):
            return super(
                PatchedObjControllerApp, self).__call__(*args, **kwargs)


class TestObjectController(unittest.TestCase):
    container_info = {
        'write_acl': None,
        'read_acl': None,
        'storage_policy': None,
        'sync_key': None,
        'versions': None,
    }

    def setUp(self):

        self.logger = debug_logger('proxy-server')
        self.storage = FakeStorageAPI()

        self.app = PatchedObjControllerApp(
            None, FakeMemcache(), account_ring=FakeRing(),
            container_ring=FakeRing(), storage=self.storage,
            logger=self.logger)
        self.app.container_info = dict(self.container_info)

    def test_DELETE_simple(self):
        req = Request.blank('/v1/a/c/o', method='DELETE')
        self.storage.object_delete = Mock()
        resp = req.get_response(self.app)
        self.storage.object_delete.assert_called_once_with('a', 'c', 'o')
        self.assertEqual(resp.status_int, 204)

    def test_DELETE_not_found(self):
        req = Request.blank('/v1/a/c/o', method='DELETE')
        self.storage.object_delete = Mock(side_effect=exc.NoSuchObject)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 404)

    def test_HEAD_simple(self):
        req = Request.blank('/v1/a/c/o', method='HEAD')
        ret_val = {
            'ctime': 0,
            'hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'length': 1,
        }
        self.storage.object_show = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_show.assert_called_once_with('a', 'c', 'o')
        self.assertEqual(resp.status_int, 200)
        self.assertIn('Accept-Ranges', resp.headers)

    def test_PUT_simple(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['content-length'] = '0'
        ret_val = ({}, 0, '')
        self.storage.object_create = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_create.assert_called_once_with(
                'a', 'c', obj_name='o', content_length=0, etag='',
                metadata={}, content_type='application/octet-stream',
                file_or_path=req.environ['wsgi.input'])
        self.assertEqual(resp.status_int, 201)

    def test_PUT_requires_length(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 411)

    def test_PUT_empty_bad_etag(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['Content-Length'] = '0'
        req.headers['Etag'] = '"openio"'
        meta = fake_prepare_meta()
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 0}]
        self.storage._content_prepare = Mock(return_value=(meta, chunks))
        with fakes.set_http_connect(200):
            resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 422)

    def test_PUT_if_none_match(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '*'
        req.headers['content-length'] = '0'
        ret_val = ({}, 0, '')
        self.storage.object_create = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 201)

    def test_PUT_if_none_match_denied(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '*'
        req.headers['content-length'] = '0'
        self.storage.object_create = Mock(side_effect=exc.PreconditionFailed)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 412)

    def test_PUT_if_none_match_not_star(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = 'foo'
        req.headers['content-length'] = '0'
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 400)

    def test_PUT_error_during_transfer_data(self):
        class FakeReader(object):
            def read(self, size):
                raise IOError()

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        meta = fake_prepare_meta()
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        self.storage._content_prepare = Mock(return_value=(meta, chunks))
        with fakes.set_http_connect(200):
            resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 499)

    def test_PUT_chunkreadtimeout_during_transfer_data(self):
        class FakeReader(object):
            def read(self, size):
                raise exc.ClientReadTimeout()

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        meta = fake_prepare_meta()
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        self.storage._content_prepare = Mock(return_value=(meta, chunks))
        with fakes.set_http_connect(200):
            resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 408)

    def test_PUT_timeout_during_transfer_data(self):
        class FakeReader(object):
            def read(self, size):
                raise Timeout()

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage._content_prepare = Mock(return_value=(meta, chunks))
        with fakes.set_http_connect(200):
            resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 499)

    def test_exception_during_transfer_data(self):
        class FakeReader(object):
            def read(self, size):
                raise Exception('exception message')

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage._content_prepare = Mock(return_value=(meta, chunks))
        with fakes.set_http_connect(200):
            resp = req.get_response(self.app)

        self.assertEqual(resp.status_int, 500)

    def test_GET_simple(self):
        req = Request.blank('/v1/a/c/o')

        ret_value = ({
            'hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'ctime': 0,
            'length': 1
            }, fake_stream(1))
        self.storage.object_fetch = Mock(return_value=ret_value)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 200)
        self.assertIn('Accept-Ranges', resp.headers)

    def test_GET_not_found(self):
        req = Request.blank('/v1/a/c/o')
        self.storage.object_fetch = Mock(side_effect=exc.NoSuchObject)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 404)

    def test_POST_as_COPY_simple(self):
        req = Request.blank('/v1/a/c/o', method='POST')
        meta = {
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "ctime": 0,
                "length": 0,
        }
        created = (
                {},
                0,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.storage.object_fetch = Mock(return_value=(meta, fake_stream(0)))
        self.storage.object_create = Mock(return_value=created)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 202)
        self.assertEqual(req.environ['QUERY_STRING'], '')
        self.assertTrue('swift.post_as_copy' in req.environ)

    def test_COPY_simple(self):
        req = Request.blank('/v1/a/c/o', method='COPY',
                            headers={'Content-Length': 0,
                                     'Destination': 'c/o-copy'})

        meta = {
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "ctime": 0,
                "length": 0,
        }

        created = (
                {},
                0,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.storage.object_fetch = Mock(return_value=(meta, fake_stream(0)))
        self.storage.object_create = Mock(return_value=created)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 201)

    def test_PUT_log_info(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['x-copy-from'] = 'some/where'
        req.headers['Content-Length'] = 0

        meta = {
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "ctime": 0,
                "length": 0,
        }
        created = (
                {},
                0,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.storage.object_fetch = Mock(return_value=(meta, fake_stream(0)))
        self.storage.object_create = Mock(return_value=created)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 201)
        self.assertEqual(
            req.environ.get('swift.log_info'), ['x-copy-from:some/where'])
        req = Request.blank('/v1/a/c/o')
        req.method = 'POST'
        req.headers['x-copy-from'] = 'else/where'

        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 202)
        self.assertEqual(req.environ.get('swift.log_info'), None)
