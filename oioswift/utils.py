# Copyright (C) 2015-2018 OpenIO SAS
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

from functools import wraps

from swift.common.swob import HTTPMethodNotAllowed, HTTPNotAcceptable, \
    HTTPNotModified, HTTPPreconditionFailed, HTTPServiceUnavailable

from oio.common.exceptions import ServiceBusy, NoSuchContainer, NoSuchObject
try:
    # Since oio-sds 4.1.14
    from oio.common.exceptions import MethodNotAllowed
    # TODO(FVE): delete when `oio` >= 4.2
except ImportError:
    from oio.common.exceptions import ClientException as MethodNotAllowed


_FORMAT_MAP = {"xml": 'application/xml', "json": 'application/json',
               "plain": 'text/plain'}


def get_listing_content_type(req):
    req_format = req.params.get('format')
    if req_format:
        req.accept = _FORMAT_MAP.get(req_format.lower(),
                                     _FORMAT_MAP.get('plain'))
    req_format = req.accept.best_match(
        ['text/plain', 'application/json', 'application/xml', 'text/xml'])
    if not req_format:
        raise HTTPNotAcceptable()
    return req_format


def _mixed_join(iterable, sentinel):
    """concatenate any string type in an intelligent way."""
    iterator = iter(iterable)
    first_item = next(iterator, sentinel)
    if isinstance(first_item, bytes):
        return first_item + b''.join(iterator)
    return first_item + u''.join(iterator)


class IterO(object):
    def __init__(self, gen):
        self.gen = gen
        self.closed = False
        self.pos = 0
        self.sentinel = ''
        self.buf = None

    def _buf_append(self, string):
        if not self.buf:
            self.buf = string
        else:
            self.buf += string

    def close(self):
        if not self.closed:
            self.closed = True
            if hasattr(self.gen, 'close'):
                self.gen.close()

    def read(self, n=-1):
        if self.closed:
            raise ValueError('Closed file')
        if n < 0:
            self._buf_append(_mixed_join(self.buf, self.sentinel))
            result = self.buf[self.pos:]
            self.pos += len(result)
            return result
        new_pos = self.pos + n
        buf = []
        try:
            tmp_end_pos = 0 if self.buf is None else len(self.buf)
            while new_pos > tmp_end_pos or (self.buf is None and not buf):
                item = next(self.gen)
                tmp_end_pos += len(item)
                buf.append(item)
        except StopIteration:
            pass
        if buf:
            self._buf_append(_mixed_join(buf, self.sentinel))

        if self.buf is None:
            return self.sentinel

        new_pos = max(0, new_pos)
        try:
            return self.buf[self.pos:new_pos]
        finally:
            self.pos = min(new_pos, len(self.buf))


def handle_service_busy(fnc):
    @wraps(fnc)
    def _wrapped(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except ServiceBusy as e:
            headers = dict()
            headers['Retry-After'] = '1'
            return HTTPServiceUnavailable(request=req, headers=headers,
                                          body=e.message)
    return _wrapped


def handle_not_allowed(fnc):
    """Handle MethodNotAllowed ('405 Method not allowed') errors."""
    @wraps(fnc)
    def _wrapped(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except MethodNotAllowed as exc:
            headers = dict()
            if 'worm' in exc.message.lower():
                headers['Allow'] = 'GET, HEAD, PUT'
            else:
                # TODO(FVE): load Allow header from exception attributes
                pass
            return HTTPMethodNotAllowed(request=req, headers=headers)
    return _wrapped


def check_if_none_match(fnc):
    """Check if object exists, and if etag matches."""
    @wraps(fnc)
    def _handle_if_none_match(self, req, *args, **kwargs):
        if req.if_none_match is None:
            return fnc(self, req, *args, **kwargs)
        oio_headers = {'X-oio-req-id': self.trans_id}
        try:
            metadata = self.app.storage.object_show(
                self.account_name, self.container_name, self.object_name,
                version=req.environ.get('oio.query', {}).get('version'),
                headers=oio_headers)
        except (NoSuchObject, NoSuchContainer):
            return fnc(self, req, *args, **kwargs)
        # req.if_none_match will check for '*'.
        if metadata.get('hash') in req.if_none_match:
            if req.method in ('HEAD', 'GET'):
                raise HTTPNotModified(request=req)
            else:
                raise HTTPPreconditionFailed(request=req)
        return fnc(self, req, *args, **kwargs)
    return _handle_if_none_match
