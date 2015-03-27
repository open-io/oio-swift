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

from urllib import unquote

from webob import Response
from webob import exc

from oioswift.controller.base import Controller
from oioswift.utils import dateiso_from_timestamp
from oiopy import exceptions


def _make_object_headers(meta):
    headers = {}
    headers['Content-Type'] = meta.get('mime-type')
    headers['ETag'] = meta.get('hash')
    headers['Last-Modified'] = dateiso_from_timestamp(
        float(meta.get('ctime')))
    headers['Content-Length'] = meta.get('length')
    return headers


class ObjectController(Controller):
    def __init__(self, app, account_id, container_id, object_id, **kwargs):
        Controller.__init__(self, app)
        self.account_id = unquote(account_id)
        self.container_id = unquote(container_id)
        self.object_id = unquote(object_id)

    def GET(self, req):
        storage = self.app.storage

        try:
            meta, stream = storage.fetch_object(self.container_id,
                                                self.object_id, with_meta=True)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return exc.HTTPNotFound()

        headers = _make_object_headers(meta)
        return Response(app_iter=stream, status=200, headers=headers)

    def HEAD(self, req):
        storage = self.app.storage
        try:
            meta = storage.get_object_metadata(self.container_id,
                                               self.object_id)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return exc.HTTPNotFound()

        headers = _make_object_headers(meta)
        return Response(None, 200, headers=headers)

    def DELETE(self, req):
        storage = self.app.storage

        try:
            storage.delete_object(self.container_id, self.object_id)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return exc.HTTPNotFound()
        return exc.HTTPNoContent()

    def PUT(self, req):
        content_length = req.content_length
        storage = self.app.storage

        if content_length is None:
            content_length = 0
        stream = req.body_file
        try:
            storage.create_object(self.container_id, obj_name=self.object_id,
                                  file_or_path=stream,
                                  content_length=content_length)
        except exceptions.NoSuchContainer:
            return exc.HTTPNotFound()
        except exceptions.ClientReadTimeout:
            return exc.HTTPRequestTimeout()
        except exceptions.OioException:
            return Response('The client was disconnected during request.', 499)
        return exc.HTTPCreated()

