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

from swift.common.utils import get_remote_client, get_logger
from swift.common.swob import Request, HTTPForbidden


class VerbAclMiddleware(object):
    """
    Middleware that manages access (permission) to the methods
    based on the IP address.
    """

    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf)

        # TODO Check pipeline

        self.verb_acl = {}
        verb_acl = conf.get('verb_acl', None)
        if not verb_acl:
            raise ValueError('verb_acl: Not initialized in the config file.')
        for acl in verb_acl.split(';'):
            if acl.count(':') != 1:
                raise ValueError('verb_acl: Bad format in the config file')
            methods, blocks = acl.split(':', 1)
            for method in methods.split(','):
                if not method:
                    raise ValueError('verb_acl: Bad format in the config file')
                for block in blocks.split(','):
                    if not block:
                        raise ValueError(
                            'verb_acl: Bad format in the config file')
                    self.verb_acl.setdefault(method.upper(), []).append(block)
        self.logger.debug("Verb ACL: " + str(self.verb_acl))

    def __call__(self, env, start_response):
        req = Request(env)
        if req.method in self.verb_acl:
            remote = get_remote_client(req)
            for block in self.verb_acl[req.method]:
                if remote.startswith(block):
                    break
            else:
                raise HTTPForbidden(request=req,
                                    body='Forbidden method for %s' % remote)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    def factory(app):
        return VerbAclMiddleware(app, conf)
    return factory
