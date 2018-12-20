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

from swift.common.swob import HTTPMethodNotAllowed, \
    HTTPNotFound, \
    HTTPNotModified, HTTPPreconditionFailed, HTTPServiceUnavailable

from oio.common.exceptions import ServiceBusy, NoSuchContainer, NoSuchObject,\
    OioTimeout
try:
    # Since oio-sds 4.1.14
    from oio.common.exceptions import MethodNotAllowed
    # TODO(FVE): delete when `oio` >= 4.2
except ImportError:
    from oio.common.exceptions import ClientException as MethodNotAllowed


_FORMAT_MAP = {"xml": 'application/xml', "json": 'application/json',
               "plain": 'text/plain'}


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
    def _service_busy_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except ServiceBusy as e:
            headers = dict()
            headers['Retry-After'] = '1'
            return HTTPServiceUnavailable(request=req, headers=headers,
                                          body=e.message)
    return _service_busy_wrapper


def handle_not_allowed(fnc):
    """Handle MethodNotAllowed ('405 Method not allowed') errors."""
    @wraps(fnc)
    def _not_allowed_wrapper(self, req, *args, **kwargs):
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
    return _not_allowed_wrapper


def handle_oio_timeout(fnc):
    """Catch OioTimeout errors and return '503 Service Unavailable'."""
    @wraps(fnc)
    def _oio_timeout_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except OioTimeout as exc:
            headers = dict()
            # TODO(FVE): choose the value according to the timeout
            headers['Retry-After'] = '1'
            return HTTPServiceUnavailable(request=req, headers=headers,
                                          body=str(exc))
    return _oio_timeout_wrapper


def handle_oio_no_such_container(fnc):
    """Catch NoSuchContainer errors and return '404 Not Found'"""
    @wraps(fnc)
    def _oio_no_such_container_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except NoSuchContainer:
            return HTTPNotFound(request=req)
    return _oio_no_such_container_wrapper


def check_if_none_match(fnc):
    """Check if object exists, and if etag matches."""
    @wraps(fnc)
    def _if_none_match_wrapper(self, req, *args, **kwargs):
        if req.if_none_match is None:
            return fnc(self, req, *args, **kwargs)
        oio_headers = {'X-oio-req-id': self.trans_id}
        try:
            metadata = self.app.storage.object_get_properties(
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
    return _if_none_match_wrapper
