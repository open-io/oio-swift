# Copyright (c) 2010-2012 OpenStack Foundation
# Copyright (c) 2019 OpenIO SDS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Adaptation of WSGI tools for use with oioswift."""

from swift.common.wsgi import make_env as orig_make_env, \
    make_subrequest as orig_make_subrequest


PASSTHROUGH_ENV_KEYS = (
    'HTTP_X_BACKEND_VERSIONING_MODE_OVERRIDE',
)


def oio_make_env(env, *args, **kwargs):
    """Same as swift's make_env, but let some more headers pass through."""
    newenv = orig_make_env(env, *args, **kwargs)
    for name in PASSTHROUGH_ENV_KEYS:
        if name in env:
            newenv[name] = env[name]
    return newenv


def oio_make_subrequest(env, method=None, path=None, body=None, headers=None,
                        agent='Swift', swift_source=None,
                        make_env=oio_make_env):
    """
    Same as swift's make_subrequest, but let some more headers pass through.
    """
    return orig_make_subrequest(env, method=method, path=path, body=body,
                                headers=headers, agent=agent,
                                swift_source=swift_source,
                                make_env=make_env)
