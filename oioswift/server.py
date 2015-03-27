# Copyright (C) 2015 OpenIO SAS

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from logging import getLogger

from eventlet import Timeout
from webob import exc
from webob import Request

from oiopy.object_storage import StorageAPI
from oioswift.controller import AccountController, ContainerController, \
    ObjectController, InfoController
from oioswift.utils import split_path
from oioswift.utils import generate_tx_id


class Application(object):
    def __init__(self, conf):
        self.conf = conf
        self.logger = getLogger('oioswift')
        proxy_url = self.conf.get('sds_proxy_url')
        if not proxy_url:
            raise Exception('No SDS Proxy URL defined!')
        namespace = self.conf.get('sds_namespace')
        if not namespace:
            raise Exception('No SDS Namespace defined!')
        self.proxy_url = proxy_url
        self.namespace = namespace
        self.proxy_timeout = int(conf.get('proxy_timeout', 10))
        self.conn_timeout = float(conf.get('conn_timeout', 0.5))
        self.client_timeout = int(conf.get('client_timeout', 60))
        self.storage = StorageAPI(self.proxy_url, self.namespace)

    def dispatch_request(self, req):
        try:
            if req.content_length and req.content_length < 0:
                return exc.HTTPBadRequest('Invalid Content-Length')
            try:
                cls, path_parts = self.get_controller(req.path)
            except ValueError:
                return exc.HTTPNotFound()
            if not cls:
                return exc.HTTPPreconditionFailed('Bad URL')
            controller = cls(self, **path_parts)
            if 'oioswift.tx_id' not in req.environ:
                tx_id = generate_tx_id()
                req.environ['oioswift.tx_id'] = tx_id

            req.headers['x-trans-id'] = req.environ['oioswift.tx_id']
            controller.tx_id = req.environ['oioswift.tx_id']

            try:
                handler = getattr(controller, req.method)
            except AttributeError:
                return exc.HTTPMethodNotAllowed()
            if 'oioswift.authorize' in req.environ:
                resp = req.environ['oioswift.authorize'](req)
                if not resp:
                    del req.environ['oioswift.authorize']
                else:
                    return resp

            return handler(req)
        except exc.HTTPException as error:
            return error
        except (Exception, Timeout) as e:
            self.logger.exception('ERROR Unhandled exception in request')
            return exc.HTTPServerError()

    def get_controller(self, path):
        if path == '/info':
            d = dict()
            return InfoController, d
        version, account, container, obj = split_path(path, 1, 4, True)
        d = dict(version=version, account_id=account, container_id=container,
                 object_id=obj)
        if obj and container and account:
            return ObjectController, d
        elif container and account:
            return ContainerController, d
        elif account and not container and not obj:
            return AccountController, d
        return None, d

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    app = Application(conf)
    return app