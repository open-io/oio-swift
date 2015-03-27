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

from urllib import quote
from uuid import uuid4
from datetime import datetime
import time

from webob import exc


_format_map = {"xml": 'application/xml', "json": 'application/json',
               "plain": 'text/plain'}


def get_listing_content_type(req):
    req_format = req.GET.get('format')
    if req_format:
        req.accept = _format_map.get(req_format.lower(),
                                     _format_map.get('plain'))
    req_format = req.accept.best_match(
        ['text/plain', 'application/json', 'application/xml', 'text/xml'])
    if not req_format:
        raise exc.HTTPNotAcceptable()
    return req_format


def dateiso_from_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).isoformat()


_true_values = {'true', '1', 'yes', 'on', 't', 'y'}


def config_true_value(value):
    return value is True or \
           (isinstance(value, basestring) and value.lower() in _true_values)


"""
function taken from
https://github.com/openstack/swift/blob/master/swift/common/utils.py
"""
def split_path(path, minsegs=1, maxsegs=None, inc_trailing=False):
    if not maxsegs:
        maxsegs = minsegs
    if minsegs > maxsegs:
        raise ValueError('minsegs > maxsegs: %d > %d' % (minsegs, maxsegs))
    if inc_trailing:
        segs = path.split('/', maxsegs)
        minsegs += 1
        maxsegs += 1
        count = len(segs)
        if segs[0] or count < minsegs or count > maxsegs or '' in segs[
                                                                  1:minsegs]:
            raise ValueError('Invalid path: %s' % quote(path))
    else:
        minsegs += 1
        maxsegs += 1
        segs = path.split('/', maxsegs)
        count = len(segs)
        if (segs[0] or count < minsegs or count > maxsegs + 1 or
                    '' in segs[1:minsegs] or
                (count == maxsegs + 1 and segs[maxsegs])):
            raise ValueError('Invalid path: %s' % quote(path))
    segs = segs[1:maxsegs]
    segs.extend([None] * (maxsegs - 1 - len(segs)))
    return segs


def generate_tx_id():
    return 'tx%s-%010x' % (uuid4().hex[:21], time.time())






