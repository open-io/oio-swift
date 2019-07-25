# Copyright (c) 2014,2017-2018 OpenStack Foundation.
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

from oioswift.common.middleware.s3api.controllers.base import Controller, \
    UnsupportedController
from oioswift.common.middleware.s3api.controllers.service import \
    ServiceController
from oioswift.common.middleware.s3api.controllers.bucket import \
    BucketController
from oioswift.common.middleware.s3api.controllers.obj import \
    ObjectController
from oioswift.common.middleware.s3api.controllers.unique_bucket import \
    UniqueBucketController

from oioswift.common.middleware.s3api.controllers.acl import AclController
from oioswift.common.middleware.s3api.controllers.s3_acl import S3AclController
from oioswift.common.middleware.s3api.controllers.multi_delete import \
    MultiObjectDeleteController
from oioswift.common.middleware.s3api.controllers.multi_upload import \
    UploadController, PartController, UploadsController
from oioswift.common.middleware.s3api.controllers.lifecycle import \
    LifecycleController
from oioswift.common.middleware.s3api.controllers.location import \
    LocationController
from oioswift.common.middleware.s3api.controllers.logging import \
    LoggingStatusController
from oioswift.common.middleware.s3api.controllers.tagging import \
    TaggingController
from oioswift.common.middleware.s3api.controllers.versioning import \
    VersioningController
from oioswift.common.middleware.s3api.controllers.cors import CorsController

__all__ = [
    'Controller',
    'ServiceController',
    'BucketController',
    'ObjectController',
    'UniqueBucketController',

    'AclController',
    'S3AclController',
    'CorsController',
    'LifecycleController',
    'MultiObjectDeleteController',
    'PartController',
    'TaggingController',
    'UploadsController',
    'UploadController',
    'LocationController',
    'LoggingStatusController',
    'VersioningController',

    'UnsupportedController',
]
