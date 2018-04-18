# These tests make a lot of assumptions about the inner working of oio-sds
# Python API, and thus will stop working at some point.

import unittest
from mock import MagicMock as Mock
from mock import patch, ANY

from eventlet import Timeout

from oio.common import exceptions as exc
from oio.common import green as oiogreen
from oio.common.http import CustomHttpConnection
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
        'x-oio-content-meta-mime-type': '',
        'id': '',
        'version': 42,
        'policy': 'SINGLE',
        'chunk_method': 'plain/nb_copy=1',
        'chunk_size': 1048576,
    }


class FakePutResponse(object):
    def __init__(self, **kwargs):
        self.status = 201
        self.headers = dict()
        self.__dict__.update(kwargs)

    def getheader(self, header):
        return self.headers.get(header)


def fake_http_connect(*args, **kwargs):
    conn = Mock(CustomHttpConnection)
    conn.getresponse = Mock(return_value=FakePutResponse(**kwargs))
    return conn


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
        self.storage = FakeStorageAPI(
            namespace='NS', timeouts={}, logger=self.logger)

        self.app = PatchedObjControllerApp(
            {'sds_namespace': "NS"}, FakeMemcache(), account_ring=FakeRing(),
            container_ring=FakeRing(), storage=self.storage,
            logger=self.logger)
        self.app.container_info = dict(self.container_info)
        self.storage.account.account_show = Mock(
            return_value={
                'ctime': 0,
                'containers': 1,
                'objects': 1,
                'bytes': 2,
                'metadata': {}
                })
        self.storage.container.container_get_properties = Mock(
                return_value={'properties': {}, 'system': {}})

    def test_DELETE_simple(self):
        req = Request.blank('/v1/a/c/o', method='DELETE')
        self.storage.object_delete = Mock()
        resp = req.get_response(self.app)
        self.storage.object_delete.assert_called_once_with(
            'a', 'c', 'o', version=None, headers=ANY)
        self.assertEqual(204, resp.status_int)

    def test_DELETE_not_found(self):
        req = Request.blank('/v1/a/c/o', method='DELETE')
        self.storage.object_delete = Mock(side_effect=exc.NoSuchObject)
        resp = req.get_response(self.app)
        self.storage.object_delete.assert_called_once_with(
            'a', 'c', 'o', version=None, headers=ANY)
        self.assertEqual(204, resp.status_int)

    def test_HEAD_simple(self):
        req = Request.blank('/v1/a/c/o', method='HEAD')
        ret_val = {
            'ctime': 0,
            'hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'length': 1,
            'deleted': False,
            'version': 42,
        }
        self.storage.object_show = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_show.assert_called_once_with(
            'a', 'c', 'o', version=None, headers=ANY)
        self.assertEqual(resp.status_int, 200)
        self.assertIn('Accept-Ranges', resp.headers)

    def test_GET_if_none_match_not_star(self):
        """
        An object with different hash exists -> accept
        """
        req = Request.blank('/v1/a/c/o', method='GET')
        req.headers['if-none-match'] = '0000'
        req.headers['content-length'] = '0'
        ret_val = {
            'ctime': 0,
            'hash': '1111',
            'length': 1,
            'deleted': False,
            'version': 42,
        }
        self.storage.object_show = Mock(return_value=ret_val)
        self.storage.object_fetch = Mock(return_value=(ret_val, None))
        resp = req.get_response(self.app)
        self.storage.object_show.assert_called_once()
        self.assertEqual(200, resp.status_int)

    def test_GET_if_none_match_not_star_denied(self):
        """
        An object with the same hash exists -> deny
        """
        req = Request.blank('/v1/a/c/o', method='GET')
        req.headers['if-none-match'] = '0000'
        req.headers['content-length'] = '0'
        ret_val = {'hash': '0000'}
        self.storage.object_show = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_show.assert_called_once()
        self.assertEqual(304, resp.status_int)

    def test_PUT_simple(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['content-length'] = '0'
        ret_val = ({}, 0, 'd41d8cd98f00b204e9800998ecf8427e')
        self.storage.object_create = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_create.assert_called_once_with(
                'a', 'c', obj_name='o', etag='',
                metadata={}, mime_type='application/octet-stream',
                file_or_path=req.environ['wsgi.input'], policy=None,
                headers=ANY)
        self.assertEqual(201, resp.status_int)
        self.assertIn('Last-Modified', resp.headers)
        self.assertIn('Etag', resp.headers)
        self.assertIn(ret_val[2], resp.headers['Etag'])

    def test_PUT_requires_length(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        resp = req.get_response(self.app)
        self.assertEqual(411, resp.status_int)

    def test_PUT_empty_bad_etag(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['Content-Length'] = '0'
        req.headers['Etag'] = '"openio"'
        meta = fake_prepare_meta()
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 0}]
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
        self.assertEqual(422, resp.status_int)

    def test_PUT_if_none_match(self):
        """
        No object with the same name exists -> accept
        """
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '*'
        req.headers['content-length'] = '0'
        ret_val = ({}, 0, '')
        self.storage.object_show = Mock(side_effect=exc.NoSuchObject)
        self.storage.object_create = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.assertEqual(201, resp.status_int)

    def test_PUT_if_none_match_denied(self):
        """
        An object with the same name exists -> deny
        """
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '*'
        req.headers['content-length'] = '0'
        ret_val = {'hash': ''}
        self.storage.object_show = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_show.assert_called_once()
        self.assertEqual(412, resp.status_int)

    def test_PUT_if_none_match_not_star_denied(self):
        """
        An object with the same name and hash exists -> deny
        """
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '0000'
        req.headers['content-length'] = '0'
        ret_val = {'hash': '0000'}
        self.storage.object_show = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.assertEqual(412, resp.status_int)

    def test_PUT_if_none_match_not_star(self):
        """
        An object with the same name exists,
        but it has different hash -> accept
        """
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '1111'
        req.headers['content-length'] = '0'
        ret_val = {'hash': '0000'}
        self.storage.object_show = Mock(return_value=ret_val)
        ret_val2 = ({}, 0, '')
        self.app.storage.object_create = Mock(return_value=ret_val2)
        resp = req.get_response(self.app)
        self.storage.object_show.assert_called_once()
        self.storage.object_create.assert_called_once()
        self.assertEqual(201, resp.status_int)

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
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
        self.assertEqual(499, resp.status_int)

    def test_PUT_chunkreadtimeout_during_data_transfer(self):
        """The gateway times out while reading from the client."""
        class FakeReader(object):
            def read(self, size):
                raise oiogreen.SourceReadTimeout(1)

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        meta = fake_prepare_meta()
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
            self.assertEqual(408, resp.status_int)

    def test_PUT_timeout_during_data_transfer(self):
        """The gateway times out while upload data to the server."""
        class FakeReader(object):
            def read(self, size):
                raise Timeout()

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
            self.assertEqual(503, resp.status_int)

    def test_PUT_truncated_input_empty(self):
        """The gateway does not receive data from the client."""
        class FakeReader(object):
            def read(self, size):
                return ''

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
            self.assertEqual(499, resp.status_int)

    def test_PUT_truncated_input_almost(self):
        """The gateway does not receive enough data from the client."""
        class FakeReader(object):
            MAX_COUNT = 5

            def __init__(self):
                self.count = 0

            def read(self, size):
                if self.count == self.MAX_COUNT:
                    return ''
                self.count += min(size, self.MAX_COUNT)
                return 'a'*min(size, self.MAX_COUNT)

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
            self.assertEqual(resp.status_int, 499)

    def test_PUT_conflict(self):
        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        # FIXME: we should be able to create the exception without code
        self.storage.object_create = Mock(side_effect=exc.Conflict(409))
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 409)

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
        resp = req.get_response(self.app)

        self.assertEqual(resp.status_int, 500)

    def test_GET_simple(self):
        req = Request.blank('/v1/a/c/o')

        ret_value = ({
            'hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'ctime': 0,
            'length': 1,
            'deleted': False,
            'version': 42,
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
