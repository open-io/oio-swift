# Copyright (C) 2018 OpenIO SAS
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

import json
from paste.deploy import loadwsgi
from six.moves.urllib.parse import parse_qs, quote_plus, urlencode
from swift.common.swob import Request
from swift.common.utils import config_true_value, close_if_possible, \
    closing_if_possible, get_logger
from swift.common.wsgi import make_subrequest, loadcontext, PipelineWrapper
from oioswift.common.middleware.autocontainerbase import AutoContainerBase
from oio.common.exceptions import ConfigurationException

LOG = None
MIDDLEWARE_NAME = 'container_hierarchy'


class ContainerHierarchyMiddleware(AutoContainerBase):
    """
    Middleware that will spawn a container for each level of object path.
    """

    DELIMITER = '/'
    ENCODED_DELIMITER = '%2F'
    SWIFT_SOURCE = 'CH'

    def __init__(self, app, conf, acct, create_dir_placeholders=False,
                 **kwargs):
        super(ContainerHierarchyMiddleware, self).__init__(
            app, acct, **kwargs)
        self.create_dir_placeholders = create_dir_placeholders
        LOG.debug("%s: create_dir_placeholders set to %s",
                  self.SWIFT_SOURCE, self.create_dir_placeholders)

        self.check_pipeline(conf)

    def check_pipeline(self, conf):
        """
        Check that proxy-server.conf has an appropriate pipeline
        for container_hierarchy.
        """
        if conf.get('__file__', None) is None:
            return

        ctx = loadcontext(loadwsgi.APP, conf['__file__'])
        pipeline = str(PipelineWrapper(ctx)).split(' ')

        if 'swift3' in pipeline and not all((self.account_first,
                                             self.strip_v1,
                                             self.swift3_compat)):
            LOG.warn('account_first, strip_v1 and swift3_compat options '
                     'must be enabled when using %s along with swift3',
                     MIDDLEWARE_NAME)

        auth_index = -1
        if 'tempauth' in pipeline:
            LOG.debug('Use tempauth middleware.')
            auth_index = pipeline.index('tempauth')
        elif 'keystoneauth' in pipeline:
            LOG.debug('Use keystone middleware.')
            auth_index = pipeline.index('keystoneauth')
        if pipeline.index(MIDDLEWARE_NAME) < auth_index:
            raise ValueError(
                'Invalid pipeline %r: %s must be placed after authentication'
                % (pipeline, MIDDLEWARE_NAME))

    def _create_dir_marker(self, env, account, container, obj):
        """
        Create an empty object to mark a subdirectory. This is required to
        quickly recurse on subdirectories, since with this middleware they
        are stored on separate containers.
        """
        path = quote_plus(self.DELIMITER.join(
            ('', 'v1', account, container, obj)))
        req = make_subrequest(
            env, method='PUT', path=path, body='',
            swift_source=self.SWIFT_SOURCE)
        req.headers['If-None-Match'] = '*'
        req.headers['Content-Length'] = '0'
        resp = req.get_response(self.app)
        if not resp.is_success:
            LOG.warn('%s: Failed to create directory placeholder in %s: %s',
                     self.SWIFT_SOURCE, container, resp.status)
        close_if_possible(resp.app_iter)

    def _fake_container_and_obj(self, container, obj_parts, is_listing=False):
        """
        Aggregate object parts (except the last) into the container name.

        :returns: container name and object name
        """
        if len(obj_parts) > 1 and not obj_parts[-1] and not is_listing:
            container = self.ENCODED_DELIMITER.join(
                [container] + obj_parts[:-2])
            obj = obj_parts[-2] + self.DELIMITER
        else:
            container = self.ENCODED_DELIMITER.join(
                [container] + obj_parts[:-1])
            obj = obj_parts[-1] if obj_parts else ''
        return container, obj

    def _recursive_listing(self, env, account, ct_parts, header_cb):
        """
        For each subdirectory marker encountered, make a listing subrequest,
        and yield object list.
        """
        sub_path = quote_plus(self.DELIMITER.join(
            ('', 'v1', account, self.ENCODED_DELIMITER.join(ct_parts))))
        LOG.debug("%s: Recursively listing '%s'", self.SWIFT_SOURCE, sub_path)
        sub_req = make_subrequest(env.copy(), method='GET', path=sub_path,
                                  body='',
                                  swift_source=self.SWIFT_SOURCE)
        params = sub_req.params
        params['delimiter'] = self.DELIMITER
        params['limit'] = '10000'
        params['prefix'] = ''
        sub_req.params = params
        resp = sub_req.get_response(self.app)
        obj_prefix = ''
        if len(ct_parts) > 1:
            obj_prefix = self.DELIMITER.join(ct_parts[1:] + ('',))
        if not resp.is_success or resp.content_length == 0:
            LOG.warn("Failed to recursively list '%s': %s",
                     obj_prefix, resp.status)
            return
        with closing_if_possible(resp.app_iter):
            items = json.loads(resp.body)
        header_cb(resp.headers)
        subdirs = [x['subdir'][:-1] for x in items if 'subdir' in x]
        for obj in items:
            if 'name' in obj:
                obj['name'] = obj_prefix + obj['name']
                yield obj
        for subdir in subdirs:
            for obj in self._recursive_listing(
                    env, account, ct_parts + (subdir, ), header_cb):
                yield obj

    def __call__(self, env, start_response):
        if self.should_bypass(env):
            return self.app(env, start_response)
        req = Request(env)
        account, container, obj = self._extract_path(req.path_info)
        env2 = env.copy()
        qs = parse_qs(req.query_string)
        prefix = qs.get('prefix')  # returns a list or None
        LOG.debug("%s: Got %s request for container=%s, obj=%s, prefix=%s",
                  self.SWIFT_SOURCE, req.method, container, obj, prefix)
        must_recurse = False
        # TODO(FVE): check if this DELIMITER thing is relevant
        if obj is None or (self.DELIMITER not in obj and req.method == 'GET'):
            LOG.debug("%s: -> is a listing request", self.SWIFT_SOURCE)
            must_recurse = req.method == 'GET' and 'delimiter' not in qs
            if not prefix:
                obj_parts = ['']
            else:
                # FIXME(FVE): I'm not sure this is necessary
                if not prefix[0].endswith(self.DELIMITER):
                    prefix[0] += self.DELIMITER
                obj_parts = prefix[0].split(self.DELIMITER)
                # Get rid of the prefix, since objects are created
                # with only their basename (not the whole URL)
                qs['prefix'] = ''
                env2['QUERY_STRING'] = urlencode(qs, True)
                container, obj = self._fake_container_and_obj(
                    container, obj_parts, is_listing=True)
        else:
            LOG.debug("%s: -> is NOT listing request", self.SWIFT_SOURCE)
            obj_parts = obj.split(self.DELIMITER)
            if (len(obj_parts) > 1 and
                    self.create_dir_placeholders and
                    req.method == 'PUT'):
                ct = self.ENCODED_DELIMITER.join([container] + obj_parts[:-2])
                obj = obj_parts[-2] + self.DELIMITER
                self._create_dir_marker(env2, account, ct, obj)
            container, obj = self._fake_container_and_obj(container, obj_parts)
        LOG.debug("%s: Converted to container=%s, obj=%s",
                  self.SWIFT_SOURCE, container, obj)
        if must_recurse:
            oheaders = dict()

            def header_cb(header_dict):
                oheaders.update(header_dict)

            all_objs = [x for x in self._recursive_listing(
                        env, account, (container, ), header_cb)]
            body = json.dumps(all_objs)
            oheaders['X-Container-Object-Count'] = len(all_objs)
            # FIXME: aggregate X-Container-Bytes-Used
            # FIXME: aggregate X-Container-Object-Count
            # FIXME: send main bucket X-Timestamp
            # Content-Length is computed from body length
            oheaders['Content-Length'] = len(body)
            start_response("200 OK", oheaders.items())
            res = [body]
        elif obj is not None:
            env2['PATH_INFO'] = "/v1/%s/%s/%s" % (account, container, obj)
            res = self.app(env2, start_response)
        else:
            env2['PATH_INFO'] = "/v1/%s/%s/" % (account, container)
            res = self.app(env2, start_response)
        return res


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)
    global LOG
    LOG = get_logger(conf)
    LOG.warn('%s middleware is proof-of-concept '
             'and not suitable for production use!',
             MIDDLEWARE_NAME)

    acct = conf.get('sds_default_account')

    if acct is None:
        raise ConfigurationException('No OIO-SDS account configured')

    account_first = config_true_value(local_config.get('account_first'))
    swift3_compat = config_true_value(local_config.get('swift3_compat'))
    strip_v1 = config_true_value(local_config.get('strip_v1'))
    create_dir_placeholders = config_true_value(
        local_config.get('create_dir_placeholders'))

    def factory(app):
        return ContainerHierarchyMiddleware(
            app, global_conf, acct,
            strip_v1=strip_v1,
            account_first=account_first,
            swift3_compat=swift3_compat,
            create_dir_placeholders=create_dir_placeholders)
    return factory
