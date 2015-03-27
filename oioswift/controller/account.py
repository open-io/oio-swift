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

from oioswift.utils import get_listing_content_type
from oioswift.controller.base import Controller


class AccountController(Controller):
    def __init__(self, app, account_id, **kwargs):
        Controller.__init__(self, app)
        self.account_id = unquote(account_id)

    def GET(self, req):
        if req.GET.get("marker", "") != "":
            container_list = []
        else:
            container_list = [("test", 0, 0)]

        if not len(container_list):
            return Response(None, 204)

        headers = {}
        headers["x-account-container-count"] = '1'
        headers["x-account-object-count"] = '0'
        headers["x-account-bytes-used"] = '0'

        req_format = get_listing_content_type(req)
        if req_format.endswith('/xml'):
            out = ['<?xml version="1.0" encoding="UTF-8"?>',
                   '<account name="%s">' % self.account_id]
            for (name, count, total_bytes) in container_list:
                out.append('<container>')
                out.append('<name>%s</name>' % name)
                out.append('<count>%s</count>' % count)
                out.append('<bytes>%s</bytes>' % total_bytes)
                out.append('</container>')
            out.append('</account>')
            result_list = "\n".join(out)
        elif req_format == 'application/json':
            out = []
            for (name, count, total_bytes) in container_list:
                out.append({"name": name, "count": count,
                            "bytes": total_bytes})
            result_list = json.dumps(out)
        else:
            output = ''
            for (name, count, total_bytes) in container_list:
                output += '\n%s\n' % name
            result_list = output
        return Response(result_list, 200, content_type=req_format)

    def HEAD(self, req):
        headers = {}
        headers["Account"] = "AUTH_test"
        headers["X-Account-Meta-Temp-URL-Key"] = ""
        headers["x-account-container-count"] = '0'
        headers["x-account-object-count"] = '0'
        headers["x-account-bytes-used"] = '0'
        headers["Containers"] = '0'
        headers["Objects"] = '0'
        headers["Bytes"] = '0'
        headers["Content-Type"] = "text/plain; charset=utf-8"

        return Response(None, 200, headers=headers)


