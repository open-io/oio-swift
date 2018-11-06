# Copyright (C) 2016-2018 OpenIO SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os.path
import sys
import unittest
from swift.common import swob, utils
from swift.common.swob import Request
from oioswift.common.middleware import hashedcontainer
from oio.cli.common import clientmanager

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__, '../../../../..')))  # noqa
from test.unit.common.middleware.helpers import FakeSwift


class TestHashedContainer(unittest.TestCase):

    GLOBAL_CONF = {
        'sds_namespace': 'OPENIO',
        'sds_default_account': 'OPENIO',
        'sds_proxy_url': '127.0.0.1:666'
    }

    def setUp(self):
        self.app = FakeSwift()
        # prevent a call to oio-proxy
        clientmanager.ClientManager.nsinfo = {
            'options': {'flat_bitlength': '17'}}
        self.hc = hashedcontainer.filter_factory(self.GLOBAL_CONF)(self.app)

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

    def _check_conversion(self, path_in, path_out):
        self.app.register('PUT', path_out, swob.HTTPCreated, {})
        req = Request.blank(path_in, method='PUT')
        resp = self.call_app(req, app=self.hc)
        self.assertEqual(resp[0], "201 Created")
        self.assertEqual(self.app.calls, [('PUT', path_out)])

    def test_default_config(self):
        self._check_conversion(
            '/prefix/229/358493922_something',
            '/v1/OPENIO/6C800/prefix/229/358493922_something')

    def test_custom_bits(self):
        self.hc = hashedcontainer.filter_factory(
            self.GLOBAL_CONF, bits=12)(self.app)
        self._check_conversion(
            '/prefix/229/358493922_something',
            '/v1/OPENIO/6C8/prefix/229/358493922_something')
