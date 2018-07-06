# Copyright (c) 2015-2016 OpenStack Foundation
# Copyright (c) 2018 OpenIO SAS
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

from swift.common.middleware.crypto.crypto_utils import Crypto

try:
    # Since Queens
    from swift.common.utils import strict_b64decode
except ImportError:
    import base64
    import binascii
    import string
    import six

    def strict_b64decode(value, allow_line_breaks=False):
        '''
        Validate and decode Base64-encoded data.
        The stdlib base64 module silently discards bad characters, but we often
        want to treat them as an error.
        :param value: some base64-encoded data
        :param allow_line_breaks: if True, ignore carriage returns and newlines
        :returns: the decoded data
        :raises ValueError: if ``value`` is not a string, contains invalid
                            characters, or has insufficient padding
        '''
        if isinstance(value, bytes):
            try:
                value = value.decode('ascii')
            except UnicodeDecodeError:
                raise ValueError
        if not isinstance(value, six.text_type):
            raise ValueError
        # b64decode will silently discard bad characters, but we want to
        # treat them as an error
        valid_chars = string.digits + string.ascii_letters + '/+'
        strip_chars = '='
        if allow_line_breaks:
            valid_chars += '\r\n'
            strip_chars += '\r\n'
        if any(c not in valid_chars for c in value.strip(strip_chars)):
            raise ValueError
        try:
            return base64.b64decode(value)
        except (TypeError, binascii.Error):  # (py2 error, py3 error)
            raise ValueError


ALGO_HEADER = 'X-Amz-Server-Side-Encryption-Customer-Algorithm'
KEY_HEADER = 'X-Amz-Server-Side-Encryption-Customer-Key'
KEY_MD5_HEADER = 'X-Amz-Server-Side-Encryption-Customer-Key-Md5'


def decode_secret(b64_secret):
    """Decode and check a base64 encoded secret key."""
    binary_secret = strict_b64decode(b64_secret, allow_line_breaks=True)
    if len(binary_secret) != Crypto.key_length:
        raise ValueError
    return binary_secret
