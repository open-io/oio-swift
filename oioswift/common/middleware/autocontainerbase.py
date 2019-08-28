# Copyright (C) 2017-2018 OpenIO SAS
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

from functools import partial
import collections
from six.moves.urllib.parse import parse_qs, quote_plus
from swift.common.swob import HTTPBadRequest, Request
from swift.common.utils import config_true_value, split_path
from swift.common.wsgi import reiterate
from swift.common.request_helpers import get_sys_meta_prefix
from oio.common.autocontainer import ContainerBuilder

from swift.proxy.controllers.base import headers_to_container_info, \
    headers_to_account_info, get_cache_key


class AutoContainerBase(object):

    BYPASS_QS = "bypass-autocontainer"
    BYPASS_HEADER = "X-bypass-autocontainer"

    def __init__(self, app, acct,
                 strip_v1=False, account_first=False, swift3_compat=False,
                 stop_at_first_match=True, skip_metadata=False, **_kwargs):
        self.app = app
        self.account = acct
        self.bypass_header_key = ("HTTP_" +
                                  self.BYPASS_HEADER.upper().replace('-', '_'))
        self.con_builder = ContainerBuilder()
        self.account_first = account_first
        self.swift3_compat = swift3_compat
        self.strip_v1 = strip_v1
        self.skip_metadata = skip_metadata
        if (not stop_at_first_match and
                not hasattr(self.con_builder, 'alternatives')):
            raise ValueError("Disabling 'stop_at_first_match' parameter "
                             "is not supported with openio-sds < 4.2")
        self.stop_at_first_match = stop_at_first_match

    def should_bypass(self, env):
        """Should we bypass this filter?"""
        header = env.get(self.bypass_header_key, "").lower()
        query = parse_qs(env.get('QUERY_STRING', "")).get(self.BYPASS_QS, [""])
        return config_true_value(header) or config_true_value(query[0])

    def _extract_path(self, path):
        account = self.account
        # Remove leading '/' to be consistent with split_path()
        obj = path[1:]
        container = None

        try:
            if self.strip_v1:
                version, tail = split_path('/' + obj, 1, 2, True)
                if version in ('v1', 'v1.0'):
                    obj = tail

            if obj is not None and self.account_first:
                account, tail = split_path('/' + obj, 1, 2, True)
                obj = tail

            if obj is not None and self.swift3_compat:
                container, tail = split_path('/' + obj, 1, 2, True)
                obj = tail

            # Do not yield an empty object name
            if not obj:
                obj = None
        except ValueError:
            raise HTTPBadRequest()

        return account, container, obj

    def _save_bucket_name(self, env):
        req = Request(env)
        account, container, obj = self._extract_path(req.path_info)
        sys_meta_key = '%soio-bucket-name' % get_sys_meta_prefix('object')
        req.headers[sys_meta_key] = container

    def _convert_path(self, path):
        account, container, obj = self._extract_path(path)
        if obj is not None:
            # TODO(FVE): when supported, also pass account to con_builder()
            container = quote_plus(self.con_builder(obj))
        return account, container, obj

    def _alternatives(self, account, container, obj):
        # put S3 parts in dedicated container
        suffix = ("+segments" if container and container.endswith('+segments')
                  else "")
        if obj is None:
            yield account, container, obj
        elif self.stop_at_first_match:
            # TODO(FVE): when supported, also pass account to con_builder()
            yield account, quote_plus(self.con_builder(obj)) + suffix, obj
        else:
            for alt_container in self.con_builder.alternatives(obj):
                yield account, quote_plus(alt_container) + suffix, obj
        raise StopIteration

    @staticmethod
    def is_copy(env):
        """Tell if `env` represents an object copy operation."""
        return (env['REQUEST_METHOD'] == 'PUT' and
                ('HTTP_X_COPY_FROM' in env or 'HTTP_OIO_COPY_FROM' in env))

    @staticmethod
    def _save_response(env, status, headers, exc_info=None):
        env['last_status'] = status
        env['last_headers'] = headers
        env['last_exc_info'] = exc_info
        if 'first_status' not in env:
            env['first_status'] = status
            env['first_headers'] = headers
            env['first_exc_info'] = exc_info

    def _retry_loop(self, orig_env, start_response, path_to_modify,
                    env_modifier, alt_checker=None):
        """
        :param env_modifier: function copies and modifies the env
            dictionary, according to the alternative path parts
        :param alt_checker: function that checks the alternative
            path parts (may raise an exception)
        """
        local_env = {}
        query = parse_qs(orig_env.get('QUERY_STRING', ''), True)
        account, container, obj = self._extract_path(path_to_modify)
        is_container_req = container is not None and obj is None
        is_service_req = (account is not None and
                          container is None and
                          obj is None)
        if is_container_req and 'prefix' in query:
            obj = query['prefix'][0]
        elif is_service_req:
            env = env_modifier(orig_env, (account, ))
            return self.app(env, start_response)
        for alt in self._alternatives(account, container, obj):
            if alt_checker and not alt_checker(alt):
                return self.app(orig_env, start_response)
            env = env_modifier(orig_env, alt[:2] if is_container_req else alt)
            resp = self.app(env, partial(self._save_response, local_env))

            if isinstance(resp, collections.Iterable):
                # TODO when a MPU is completed, resp is an iterator
                # and we must fill last_status but it may break
                # next test
                resp = reiterate(resp)

            if 'last_status' not in local_env:
                # start_response() was not called. This happens when there is
                # no 'proxy-logging' just after 'catch_errors' in the pipeline.
                return resp
            if not local_env['last_status'].startswith('404'):
                # start_response() was called, and status is not 404.
                start_response(local_env['last_status'],
                               local_env['last_headers'],
                               local_env['last_exc_info'])
                return resp
            if 'first_resp' not in local_env:
                local_env['first_resp'] = resp

        start_response(local_env['first_status'],
                       local_env['first_headers'],
                       local_env['first_exc_info'])
        return local_env['first_resp']

    def _call_copy(self, env, start_response):
        """
        Run the retry loop (copy operations).
        """
        account, container, obj = self._convert_path(env.get('PATH_INFO'))
        if obj is None:
            # This is probably an account request
            return self.app(env, start_response)
        env['PATH_INFO'] = "/v1/%s/%s/%s" % (account, container, obj)

        for hdr in ("HTTP_OIO_COPY_FROM", "HTTP_X_COPY_FROM"):
            if hdr in env:
                from_value = env.get(hdr)
                from_header = hdr
                break
        else:
            raise HTTPBadRequest(body="Malformed copy-source header")

        # HTTP_X_COPY_FROM_ACCOUNT will just pass through
        if self.account_first:
            src_path = "/fake_account" + from_value
        else:
            src_path = from_value

        def modify_copy_from(orig_env, alternative):
            env_ = orig_env.copy()
            env_[from_header] = "/%s/%s" % (
                quote_plus(alternative[1]), alternative[2])
            return env_

        def check_container_obj(alternative):
            if not alternative[1] or not alternative[2]:
                raise HTTPBadRequest(body="Malformed copy-source header")
            return True

        return self._retry_loop(
            env, start_response, src_path,
            env_modifier=modify_copy_from,
            alt_checker=check_container_obj)

    def _mock_infocache(self, env):
        if not self.skip_metadata:
            return

        req = Request(env)
        # don't fake obj metadata
        account, container, _ = self._extract_path(req.path_info)
        req.environ.setdefault('swift.infocache', {})
        req.environ['swift.infocache'][get_cache_key(account)] = \
            headers_to_account_info({}, 0)
        if container:
            key = get_cache_key(account, container)
            req.environ['swift.infocache'][key] = \
                headers_to_container_info({}, 0)

    def _call(self, env, start_response):
        """
        Run the retry loop (regular operations).
        """
        def modify_path_info(orig_env, alternative):
            env_ = orig_env.copy()
            env_['PATH_INFO'] = '/'.join(('', 'v1') + alternative)
            return env_

        def check_obj(alternative):
            return alternative[2] is not None

        return self._retry_loop(
            env, start_response, env['PATH_INFO'],
            env_modifier=modify_path_info,
            alt_checker=check_obj)

    def __call__(self, env, start_response):
        self._save_bucket_name(env)

        self._mock_infocache(env)

        if self.should_bypass(env):
            return self.app(env, start_response)

        if self.is_copy(env):
            return self._call_copy(env, start_response)
        else:
            return self._call(env, start_response)
