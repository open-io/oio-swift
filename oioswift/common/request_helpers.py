# Copyright (c) 2018 OpenIO SAS
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

from swift.common import exceptions, request_helpers
from swift.common.swob import HTTPBadRequest, HTTPForbidden


class OioSegmentedIterable(request_helpers.SegmentedIterable):
    """
    SegmentedIterable subclass that does not melt all segment errors
    into SegmentError.
    """

    def validate_first_segment(self):
        try:
            return super(OioSegmentedIterable, self).validate_first_segment()
        except exceptions.SegmentError as err:
            if 'got 403 while retrieving' in err.args[0]:
                raise HTTPForbidden(request=self.req)
            elif 'got 400 while retrieving' in err.args[0]:
                raise HTTPBadRequest(request=self.req)
            else:
                raise
