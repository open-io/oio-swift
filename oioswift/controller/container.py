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

import json
from urllib import unquote

from webob import Response
from webob import exc
from eventlet import Timeout

from oioswift.utils import dateiso_from_timestamp
from oioswift.utils import get_listing_content_type
from oioswift.controller.base import Controller
from oiopy import exceptions


class ContainerController(Controller):
    def __init__(self, app, account_id, container_id, **kwargs):
        Controller.__init__(self, app)
        self.account_id = unquote(account_id)
        self.container_id = unquote(container_id)

    def GET(self, req):
        storage = self.app.storage

        marker = req.GET.get("marker", None)
        limit = req.GET.get("limit", None)
        end_marker = req.GET.get("end_marker", None)
        prefix = req.GET.get("prefix", None)
        delimiter = req.GET.get("delimiter", None)
        try:
            object_list = storage.list_container_objects(self.container_id,
                                                         prefix=prefix,
                                                         limit=limit,
                                                         delimiter=delimiter,
                                                         marker=marker,
                                                         end_marker=end_marker)
        except exceptions.NoSuchContainer:
            return exc.HTTPNotFound()
        except exceptions.OioException:
            return exc.HTTPServerError()

        req_format = get_listing_content_type(req)

        if req_format.endswith('/xml'):
            out = ['<?xml version="1.0" encoding="UTF-8"?>',
                   '<container name="%s">' % self.container_id]
            for obj in object_list:
                out.append('<object>')
                out.append('<name>%s</name>' % obj.name)
                out.append('<bytes>%s</bytes>' % obj.size)
                out.append('<hash>%s</hash>' % obj.hash)
                out.append('<content_type></content_type>')
                last_modified = dateiso_from_timestamp(obj.ctime)
                out.append('<last_modified>%s</last_modified>' % last_modified)
                out.append('</object>')
            out.append('</container>')
            result_list = "\n".join(out)
        elif req_format == 'application/json':
            out = []
            for obj in object_list:
                last_modified = dateiso_from_timestamp(obj.ctime)
                out.append({"name": obj.name, "bytes": obj.size,
                            "content_type": "", "last_modified": last_modified,
                            "hash": obj.hash})
            result_list = json.dumps(out)
        else:
            result_list = "\n".join(obj.name for obj in object_list) + '\n'
        return Response(result_list, content_type=req_format)

    def HEAD(self, req):
        storage = self.app.storage
        try:
            with Timeout(5):
                meta = storage.get_container_metadata(self.container_id)
        except exceptions.NoSuchContainer:
            return exc.HTTPNotFound()
        headers = {}
        headers['X-Container-Object-Count'] = '0'
        headers['X-Container-Bytes-Used'] = meta.get("sys-m2-usage", "0")
        headers['Content-Type'] = 'text/plain; charset=utf-8'

        return Response(None, 204, headers=headers)

    def PUT(self, req):
        storage = self.app.storage
        try:
            storage.create(self.container_id)
        except exceptions.OioException:
            return exc.HTTPServerError()
        return exc.HTTPCreated()

    def POST(self, req):
        storage = self.app.storage
        try:
            storage.create(self.container_id)
        except exceptions.OioException:
            return exc.HTTPServerError()
        return exc.HTTPCreated()

