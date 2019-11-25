# Copyright (c) 2015-2016 OpenStack Foundation
# Copyright (c) 2018-2019 OpenIO SAS
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
from swift.common.swob import header_to_environ_key

from swift.common.utils import strict_b64decode

ALGO_HEADER = 'X-Amz-Server-Side-Encryption-Customer-Algorithm'
KEY_HEADER = 'X-Amz-Server-Side-Encryption-Customer-Key'
KEY_MD5_HEADER = 'X-Amz-Server-Side-Encryption-Customer-Key-Md5'
SRC_ALGO_HEADER = 'X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm'
SRC_KEY_HEADER = 'X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key'
SRC_KEY_MD5_HEADER = \
    'X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5'

ALGO_ENV_KEY = header_to_environ_key(ALGO_HEADER)
KEY_ENV_KEY = header_to_environ_key(KEY_HEADER)
KEY_MD5_ENV_KEY = header_to_environ_key(KEY_MD5_HEADER)
SRC_ALGO_ENV_KEY = header_to_environ_key(SRC_ALGO_HEADER)
SRC_KEY_ENV_KEY = header_to_environ_key(SRC_KEY_HEADER)
SRC_KEY_MD5_ENV_KEY = header_to_environ_key(SRC_KEY_MD5_HEADER)


def decode_secret(b64_secret):
    """Decode and check a base64 encoded secret key."""
    binary_secret = strict_b64decode(b64_secret, allow_line_breaks=True)
    if len(binary_secret) != Crypto.key_length:
        raise ValueError
    return binary_secret
