# Copyright (c) 2018 OpenIO SAS.
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
from oioswift.common.middleware.s3api.controllers import BucketController
from oioswift.common.middleware.s3api.response import BucketAlreadyExists, \
    NoSuchBucket


class UniqueBucketController(BucketController):
    """
    Handles bucket requests, ensure bucket names are globally unique.
    """

    @public
    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        # We are about to create a container, reserve its name.
        can_create = req.bucket_db.reserve(req.container_name, req.account)
        if not can_create:
            raise BucketAlreadyExists(req.container_name)

        try:
            resp = super(UniqueBucketController, self).PUT(req)
        except Exception:
            # Container creation failed, remove reservation.
            req.bucket_db.release(req.container_name)
            raise

        # Container creation succeeded, confirm reservation.
        req.bucket_db.set_owner(req.container_name, req.account)
        return resp

    @public
    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        try:
            resp = super(UniqueBucketController, self).DELETE(req)
        except NoSuchBucket:
            ct_owner = req.bucket_db.get_owner(req.container_name)
            if ct_owner == req.account:
                # The bucket used to be ours, but for some reason
                # it has not been released.
                req.bucket_db.release(req.container_name)
            raise

        if resp.is_success:
            # Container deletion succeeded, reset owner.
            req.bucket_db.release(req.container_name)

        return resp
