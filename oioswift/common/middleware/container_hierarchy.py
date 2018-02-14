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

from six.moves.urllib.parse import parse_qs, quote, urlencode
from swift.common.utils import config_true_value, close_if_possible, get_logger
from swift.common.wsgi import make_subrequest
from oioswift.common.middleware.autocontainerbase import AutoContainerBase
from oio.common.exceptions import ConfigurationException

LOG = None


class ContainerHierarchyMiddleware(AutoContainerBase):
    """
    Middleware that will spawn a container for each level of object path.
    """

    DELIMITER = '/'
    ENCODED_DELIMITER = '%2F'

    def __init__(self, app, acct, create_dir_placeholders=False, **kwargs):
        super(ContainerHierarchyMiddleware, self).__init__(
            app, acct, **kwargs)
        self.create_dir_placeholders = create_dir_placeholders

    def _create_empty_obj(self, env, account, container, obj):
        path = quote('/'.join(('', 'v1', account, container, obj)))
        req = make_subrequest(
            env, method='PUT', path=path, body='',
            swift_source='ContainerHierarchyMiddleware')
        req.headers['If-None-Match'] = '*'
        req.headers['Content-Length'] = '0'
        resp = req.get_response(self.app)
        if not resp.is_success:
            LOG.warn('Failed to create directory placeholder in %s: %s',
                     container, resp.status)
        close_if_possible(resp.app_iter)

    def __call__(self, env, start_response):
        if self.should_bypass(env):
            return self.app(env, start_response)
        account, container, obj = self._extract_path(env.get('PATH_INFO'))
        env2 = env.copy()
        if obj is None or self.DELIMITER not in obj:
            qs = parse_qs(env2.get('QUERY_STRING', ''))
            prefix = qs.get('prefix')  # returns a list or None
            if not prefix:
                return self.app(env, start_response)
            else:
                # Listing request
                # FIXME(FVE): I'm not sure this is necessary
                if not prefix[0].endswith(self.DELIMITER):
                    prefix[0] += self.DELIMITER
                obj_parts = prefix[0].split(self.DELIMITER)
                # Get rid of the prefix, since objects are created
                # with their basename (not the whole URL)
                qs['prefix'] = ''
                env2['QUERY_STRING'] = urlencode(qs, True)
        else:
            obj_parts = obj.split(self.DELIMITER)
            if self.create_dir_placeholders and \
                    env.get('REQUEST_METHOD') == 'PUT':
                ct = self.ENCODED_DELIMITER.join([container] + obj_parts[:-2])
                obj = obj_parts[-2] + '/'
                self._create_empty_obj(env2, account, ct, obj)
        container = self.ENCODED_DELIMITER.join([container] + obj_parts[:-1])
        obj = obj_parts[-1]
        env2['PATH_INFO'] = "/v1/%s/%s/%s" % (account, container, obj)
        return self.app(env2, start_response)


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)
    global LOG
    LOG = get_logger(conf)

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
            app, acct,
            strip_v1=strip_v1,
            account_first=account_first,
            swift3_compat=swift3_compat,
            create_dir_placeholders=create_dir_placeholders)
    return factory
