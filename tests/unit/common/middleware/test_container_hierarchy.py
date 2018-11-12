import os.path
import json
import mock
import sys
import unittest
from swift.common import swob, utils
from swift.common.swob import Request, HTTPException
from oioswift.common.middleware import container_hierarchy

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__, '../../../../..')))
from test.unit.common.middleware.helpers import FakeSwift  # noqa


class OioContainerHierarchy(unittest.TestCase):
    def setUp(self):
        conf = {'sds_default_account': 'OPENIO'}
        self.filter_conf = {
            'strip_v1': 'true',
            'swift3_compat': 'true',
            'account_first': 'true'
        }
        self.app = FakeSwift()
        self.ch = container_hierarchy.filter_factory(
            conf,
            **self.filter_conf)(self.app)

    def mock(self):
        self.ch._create_key = mock.MagicMock(return_value=None)
        self.ch._remove_key = mock.MagicMock(return_value=None)

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

    def call_ch(self, req):
        return self.call_app(req, app=self.ch)

    def test_simple_put(self):
        """check number of request generated by Container Hierarchy"""
        self.mock()
        self.app.register(
            'PUT', '/v1/a/c%2Fd1%2Fd2%2Fd3/o', swob.HTTPCreated, {})

        req = Request.blank('/v1/a/c/d1/d2/d3/o', method='PUT')
        resp = self.call_ch(req)

        self.assertEqual(resp[0], '201 Created')
        self.ch._create_key.assert_called_with(mock.ANY,
                                               'a', 'c', 'cnt', 'd1/d2/d3/')

    def test_fake_directory_put(self):
        self.mock()
        req = Request.blank('/v1/a/c/d1/d2/d3/', method='PUT')
        resp = self.call_ch(req)

        self.assertEqual(resp[0], '201 Created')
        self.ch._create_key.assert_called_with(mock.ANY,
                                               'a', 'c', 'obj', 'd1/d2/d3/')

    def test_get(self):
        self.app.register(
            'GET', '/v1/a/c%2Fd1%2Fd2%2Fd3/o', swob.HTTPOk, {})
        req = Request.blank('/v1/a/c/d1/d2/d3/o', method='GET')
        resp = self.call_ch(req)
        self.assertEqual(resp[0], '200 OK')

    def test_recursive_listing(self):
        self.ch.conn.keys = mock.MagicMock(return_value=['CS:a:cnt:d1/d2/d3/'])
        self.app.register(
            'GET',
            '/v1/a/c%2Fd1%2Fd2%2Fd3?prefix=&limit=10000&format=json',
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": "o",
                         "content_type": "application/octet-stream"}]))

        req = Request.blank('/v1/a/c?prefix=d1%2Fd2%2F', method='GET')
        resp = self.call_ch(req)

        data = json.loads(resp[2])
        self.assertEqual(data[0]['name'], 'd1/d2/d3/o')

    def test_listing_with_space(self):
        self.ch.conn.keys = mock.MagicMock(return_value=['CS:a:cnt:d 1/d2/'])
        self.app.register(
            'GET',
            '/v1/a/c%2Fd 1%2Fd2?prefix=&limit=10000&format=json',
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": "o",
                         "content_type": "application/octet-stream"}]))

        req = Request.blank('/v1/a/c?prefix=d%201%2Fd2%2F', method='GET')
        resp = self.call_ch(req)

        data = json.loads(resp[2])
        self.assertEqual(data[0]['name'], 'd 1/d2/o')

    def test_global_listing(self):
        self.app.register(
            'GET', '/v1/a', swob.HTTPOk, {})

        req = Request.blank('/v1/a', method='GET')
        resp = self.call_ch(req)
        self.assertEqual(resp[0], '200 OK')

    def test_delete_object(self):
        self.app.register(
            'PUT', '/v1/a/c%2Fd1%2Fd2%2Fd3/o', swob.HTTPCreated, {})

        req = Request.blank('/v1/a/c/d1/d2/d3/o', method='PUT')
        resp = self.call_ch(req)
        self.assertEqual(resp[0], '201 Created')
        self.assertIn('CS:a:c:cnt:d1/d2/d3/', self.ch.conn._keys)

        self.app.register(
            'GET', '/v1/a/c%2Fd1%2Fd2%2Fd3?prefix=&limit=1&format=json',
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": "o",
                         "content_type": "application/octet-stream"}]))
        self.app.register(
            'DELETE', '/v1/a/c%2Fd1%2Fd2%2Fd3/o', swob.HTTPNoContent, {})

        req = Request.blank('/v1/a/c/d1/d2/d3/o', method='DELETE')
        resp = self.call_ch(req)

        self.assertEqual(resp[0], '204 No Content')
        self.assertIn('CS:a:c:cnt:d1/d2/d3/', self.ch.conn._keys)

        self.app.register(
            'GET', '/v1/a/c%2Fd1%2Fd2%2Fd3?prefix=&limit=1&format=json',
            swob.HTTPOk, {}, json.dumps([]))

        req = Request.blank('/v1/a/c/d1/d2/d3/o', method='DELETE')
        resp = self.call_ch(req)
        self.assertEqual(resp[0], '204 No Content')

        self.assertNotIn('CS:a:c:cnt:d1/d2/d3/', self.ch.conn._keys)

    def test_fake_directory(self):
        req = Request.blank('/v1/a/container/d2/d3/', method='PUT')
        resp = self.call_ch(req)
        self.assertIn('CS:a:container:obj:d2/d3/', self.ch.conn._keys)
        req = Request.blank('/v1/a/container/d2/d3/', method='DELETE')
        resp = self.call_ch(req)
        self.assertEqual(resp[0], "204 No Content")
        self.assertNotIn('CS:a:container:obj:d2/d3/', self.ch.conn._keys)

    def _listing(self, is_recursive):
        self.ch.conn.keys = mock.MagicMock(
            return_value=['CS:a:bucket:cnt:d1/', 'CS:a:bucket:cnt:d1/d2/'])
        self.ch.conn.exist = mock.MagicMock(return_value=True)
        self.app.register(
            'GET',
            '/v1/a/bucket%2Fd1?prefix=d&limit=10000&format=json',
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": "o1",
                         "content_type": "application/octet-stream"}]))
        if is_recursive:
            self.app.register(
                'GET',
                '/v1/a/bucket%2Fd1%2Fd2?prefix=&limit=10000&format=json',
                swob.HTTPOk, {},
                json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                             "last_modified": "2018-04-20T09:40:59.000000",
                             "bytes": 0, "name": "o2",
                             "content_type": "application/octet-stream"}]))
        recursive = '' if is_recursive else '&delimiter=%2F'
        req = Request.blank('/v1/a/bucket?prefix=d1/d&limit=10%s' % recursive,
                            method='GET')
        resp = self.call_ch(req)

        names = [item.get('name', item.get('subdir'))
                 for item in json.loads(resp[2])]
        return names

    def test_listing_with_prefix(self):
        names = self._listing(False)
        self.assertIn('d1/o1', names)
        self.assertIn('d1/d2/', names)

    def test_listing_with_prefix_recursive(self):
        names = self._listing(True)
        self.assertIn('d1/o1', names)
        self.assertIn('d1/d2/o2', names)

    def test_listing_root_container(self):
        self.ch.conn.keys = mock.MagicMock(
            return_value=['CS:a:bucket:cnt:d1/'])
        self.app.register(
            'GET',
            '/v1/a/bucket?prefix=d&limit=10000&format=json',
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": "d0",
                         "content_type": "application/octet-stream"}]))
        req = Request.blank('/v1/a/bucket?prefix=d&limit=10&delimiter=%2F',
                            method='GET')
        resp = self.call_ch(req)
        names = [item.get('name', item.get('subdir'))
                 for item in json.loads(resp[2])]
        self.assertIn("d0", names)
        self.assertIn("d1/", names)

    def test_listing_with_marker(self):
        self.ch.conn.keys = mock.MagicMock(
            return_value=['CS:a:bucket:cnt:d1/',
                          'CS:a:bucket:cnt:d2/',
                          ])
        req = Request.blank('/v1/a/bucket?limit=10&delimiter=%2F&marker=d1/',
                            method='GET')
        resp = self.call_ch(req)
        names = [item.get('name', item.get('subdir'))
                 for item in json.loads(resp[2])]
        self.assertNotIn('d1/', names)
        self.assertIn('d2/', names)

    def test_listing_with_marker_multi_container(self):
        self.ch.conn.keys = mock.MagicMock(
            return_value=['CS:a:bucket:cnt:d1/',
                          'CS:a:bucket:cnt:d2/',
                          ])

        # with marker aa (as we inspect d1/)
        self.app.register(
            'GET',
            '/v1/a/bucket%2Fd1?marker=aa&prefix=&limit=10000&format=json', # noqa
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": "d0",
                         "content_type": "application/octet-stream"}]))
        # without marker on second container
        self.app.register(
            'GET',
            '/v1/a/bucket%2Fd2?prefix=&limit=10000&format=json',
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": "d0",
                         "content_type": "application/octet-stream"}]))
        req = Request.blank('/v1/a/bucket?limit=10&marker=d1/aa',
                            method='GET')
        resp = self.call_ch(req)
        names = [item.get('name', item.get('subdir'))
                 for item in json.loads(resp[2])]
        self.assertIn('d1/d0', names)
        self.assertIn('d2/d0', names)

    def test_duplicate_obj_cnt(self):
        self.ch.conn.keys = mock.MagicMock(
            return_value=['CS:a:bucket:cnt:d1/cnt/',
                          'CS:a:bucket:obj:d1/obj/',
                          ])
        req = Request.blank('/v1/a/bucket?limit=10&delimiter=%2F&marker=d1/',
                            method='GET')
        resp = self.call_ch(req)
        names = [item.get('name', item.get('subdir'))
                 for item in json.loads(resp[2])]
        self.assertIn('d1/', names)
        self.assertEqual(1, len(names))

    def test_remove_bucket(self):
        self.app.register(
            'DELETE',
            '/v1/a/bucket',
            swob.HTTPNoContent, {},
            "")
        req = Request.blank('/v1/a/bucket',
                            method='DELETE')
        resp = self.call_ch(req)
        self.assertEqual(resp[0], "204 No Content")

    def test_invalid_path(self):
        req = Request.blank('/v1/a/',
                            method='GET')
        with self.assertRaises(HTTPException) as cm:
            self.call_ch(req)
        self.assertEqual(cm.exception.status, "400 Bad Request")

    def test_path(self):
        cont = 'bucket'

        path = 'dir1/dir2/object'
        res = self.ch._fake_container_and_obj(cont, path.split('/'))
        self.assertEqual(res, (cont + '%2Fdir1%2Fdir2', 'object'))

        path = 'object'
        res = self.ch._fake_container_and_obj(cont, path.split('/'))
        self.assertEqual(res, (cont, 'object'))

    def test_mpu_path(self):
        cont = 'bucket+segments'
        uploadid = 'MzNkYWZlNjItNjg3Yy00ZmIyLWIwOGYtOTA2OGVlZTA2MzA5'

        path = ('dir1/dir2/object/%s/1' % uploadid).split('/')
        res = self.ch._fake_container_and_obj(cont, path, is_mpu=True)
        self.assertEqual(res, (cont + '%2Fdir1%2Fdir2',
                               'object/%s/1' % uploadid))

        path = ('dir1/dir2/object/' + uploadid).split('/')
        res = self.ch._fake_container_and_obj(cont, path, is_mpu=True)
        self.assertEqual(res, (cont + '%2Fdir1%2Fdir2',
                               'object/' + uploadid))

        path = ('object/%s/1' % uploadid).split('/')
        res = self.ch._fake_container_and_obj(cont, path, is_mpu=True)
        self.assertEqual(res, (cont,
                               'object/%s/1' % uploadid))

        path = ('object/' + uploadid).split('/')
        res = self.ch._fake_container_and_obj(cont, path, is_mpu=True)
        self.assertEqual(res, (cont,
                               'object/' + uploadid))

    def test_upload_in_progress(self):
        self.ch.conn.keys = mock.MagicMock(
            return_value=['CS:a:bucket+segments:cnt:d1/d2/d3/'])
        upload = ["obj/YmYwY2I1ZDYtNjMyYi00OGNiLWEzMzEtZDdhYTk0ODZkNWU2",
                  "root/MzNkYWZlNjItNjg3Yy00ZmIyLWIwOGYtOTA2OGVlZTA2MzA5"]
        self.app.register(
            'GET',
            '/v1/a/bucket+segments%2Fd1%2Fd2%2Fd3?prefix=&limit=10000&format=json',  # noqa
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": upload[0],
                         "content_type": "application/octet-stream"},
                        {"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 400, "name": upload[0] + '/1',
                         "content_type": "application/octet-stream"}]))
        self.app.register(
            'GET',
            '/v1/a/bucket+segments?prefix=&limit=10000&format=json',
            swob.HTTPOk, {},
            json.dumps([{"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 0, "name": upload[1],
                         "content_type": "application/octet-stream"},
                        {"hash": "d41d8cd98f00b204e9800998ecf8427e",
                         "last_modified": "2018-04-20T09:40:59.000000",
                         "bytes": 400, "name": upload[1] + '/1',
                         "content_type": "application/octet-stream"}]))
        req = Request.blank('/v1/a/bucket+segments',
                            method='GET')
        resp = self.call_ch(req)

        names = [item.get('name', item.get('subdir'))
                 for item in json.loads(resp[2])]
        self.assertEqual(names,
                         ['d1/d2/d3/' + upload[0],
                          'd1/d2/d3/' + upload[0] + '/1',
                          upload[1],
                          upload[1] + '/1'])

    def test_copy_headers(self):
        self.app.register(
            'PUT', '/v1/a/bucket%2Fdir1/target',
            swob.HTTPNoContent, {},
        )
        req = Request.blank(
            '/v1/a/bucket/dir1/target',
            method='PUT',
            headers={'Oio-Copy-From': '/v1/a/bucket/sub1/source'})

        resp = self.call_ch(req)
        self.assertEqual(resp[0], '204 No Content')
        self.assertEqual(self.app.headers[0]['Oio-Copy-From'],
                         "/v1%2Fa%2Fbucket%2Fsub1/source")
