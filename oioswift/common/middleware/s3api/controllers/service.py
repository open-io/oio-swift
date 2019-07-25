# Copyright (c) 2010-2014 OpenStack Foundation.
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

from swift.common.utils import json, public, last_modified_date_to_timestamp

from oioswift.common.middleware.s3api.controllers.base import Controller
from oioswift.common.middleware.s3api.etree import Element, SubElement, \
    tostring
from oioswift.common.middleware.s3api.response import HTTPOk, AccessDenied, \
    NoSuchBucket
from oioswift.common.middleware.s3api.utils import validate_bucket_name, \
    S3Timestamp
from oioswift.common.middleware.s3api.cfg import CONF


class ServiceController(Controller):
    """
    Handles account level requests.
    """
    @public
    def GET(self, req):
        """
        Handle GET Service request
        """
        resp = req.get_response(self.app, query={'format': 'json'})

        containers = json.loads(resp.body)

        containers = filter(
            lambda item: validate_bucket_name(item['name']), containers)

        # we don't keep the creation time of a bucket (s3cmd doesn't
        # work without that) so we use something bogus.
        elem = Element('ListAllMyBucketsResult')

        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = req.user_id
        SubElement(owner, 'DisplayName').text = req.user_id

        buckets = SubElement(elem, 'Buckets')
        for c in containers:
            if 'last_modified' in c:
                ts = last_modified_date_to_timestamp(c['last_modified'])
                creation_date = S3Timestamp(ts).s3xmlformat
            else:
                creation_date = '2009-02-03T16:45:09.000Z'
            if CONF.s3_acl and CONF.check_bucket_owner:
                try:
                    c_resp = req.get_response(self.app, 'HEAD', c['name'])
                    if 'X-Timestamp' in c_resp.sw_headers:
                        creation_date = S3Timestamp(
                            c_resp.sw_headers['X-Timestamp']).s3xmlformat
                except AccessDenied:
                    continue
                except NoSuchBucket:
                    continue

            bucket = SubElement(buckets, 'Bucket')
            SubElement(bucket, 'Name').text = c['name']
            SubElement(bucket, 'CreationDate').text = creation_date

        body = tostring(elem)

        return HTTPOk(content_type='application/xml', body=body)
