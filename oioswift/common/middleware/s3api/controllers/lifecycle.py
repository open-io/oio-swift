# Copyright (c) 2017 OpenStack Foundation.
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

from swift.common.utils import public

from oioswift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation
from oioswift.common.middleware.s3api.etree import fromstring, \
    DocumentInvalid, XMLSyntaxError
from oioswift.common.middleware.s3api.response import HTTPOk, \
    NoSuchLifecycleConfiguration, MalformedXML
from oioswift.common.middleware.s3api.utils import sysmeta_header


LIFECYCLE_HEADER = sysmeta_header('container', 'lifecycle')
MAX_LIFECYCLE_BODY_SIZE = 64 * 1024  # Arbitrary


class LifecycleController(Controller):
    """
    Handles the following APIs:

     - GET Bucket lifecycle
     - PUT Bucket lifecycle
     - DELETE Bucket lifecycle

    """

    @public
    @bucket_operation(err_resp=NoSuchLifecycleConfiguration)
    def GET(self, req):
        """
        Handles GET Bucket lifecycle.
        """
        info = req.get_container_info(self.app)
        body = info['sysmeta'].get('swift3-lifecycle')
        if not body:
            raise NoSuchLifecycleConfiguration()

        return HTTPOk(body=body, content_type='application/xml')

    @public
    @bucket_operation()
    def PUT(self, req):
        """
        Handles PUT Bucket lifecycle.
        """
        body = req.xml(MAX_LIFECYCLE_BODY_SIZE)
        try:
            # Just validate the body
            fromstring(body, 'LifecycleConfiguration')
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))

        req.headers[LIFECYCLE_HEADER] = body
        subreq = req.to_swift_req('POST', req.container_name, None,
                                  headers=req.headers)
        return subreq.get_response(self.app)

    @public
    @bucket_operation()
    def DELETE(self, req):
        """
        Handles DELETE Bucket lifecycle.
        """
        req.headers[LIFECYCLE_HEADER] = ""
        subreq = req.to_swift_req('POST', req.container_name, None,
                                  headers=req.headers)
        return subreq.get_response(self.app)
