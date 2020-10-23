#!/usr/bin/env python
# coding=utf8

from __future__ import print_function
from six.moves.urllib.parse import urlencode
from six import PY3

import json
import subprocess
import time
import unittest

AWS = ["aws", "--endpoint-url", "http://localhost:5000", "s3api"]


def to_str(val):
    if PY3:
        return val
    return val.decode('utf8')


def run_s3api(*params, **kwargs):
    print(*params)
    cmd = AWS + list(params)
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        # some s3api commands return nothing and json.loads
        # doesn't like it
        if not out:
            return {}
    except subprocess.CalledProcessError as exc:
        print(exc.output)
        raise
    return json.loads(out)


class TaggingTest(unittest.TestCase):
    def setUp(self):
        self.bucket = "test-%d" % int(time.time())
        run_s3api("create-bucket", "--bucket", self.bucket)

    def tearDown(self):
        try:
            run_s3api("delete-object", "--bucket", self.bucket,
                      "--key", "magic")
        except subprocess.CalledProcessError:
            pass
        run_s3api("delete-bucket", "--bucket", self.bucket)

    def test_unicode_tagging(self):
        tagging = {'unicode': '♜♞♝♛♚♝♞♜'}
        run_s3api("put-object", "--bucket", self.bucket, "--key", "magic",
                  "--tagging", urlencode(tagging))
        data = run_s3api("get-object-tagging", "--bucket", self.bucket,
                         "--key", "magic")
        self.assertEqual(data['TagSet'][0]['Value'],
                         to_str(tagging['unicode']))

        tagging = {'été': ''}
        run_s3api("put-object", "--bucket", self.bucket, "--key", "magic",
                  "--tagging", urlencode(tagging))
        data = run_s3api("get-object-tagging", "--bucket", self.bucket,
                         "--key", "magic")
        self.assertEqual(data['TagSet'][0]['Key'], to_str('été'))

    def test_empty_value_and_empty_key(self):
        run_s3api("put-object", "--bucket", self.bucket, "--key", "magic",
                  "--tagging", 'k=&')
        data = run_s3api("get-object-tagging", "--bucket", self.bucket,
                         "--key", "magic")
        self.assertEqual(len(data['TagSet']), 1)
        self.assertEqual(data['TagSet'][0]['Key'], 'k')
        self.assertEqual(len(data['TagSet'][0]['Value']), 0)

    def test_duplicate_tag(self):
        try:
            run_s3api("put-object", "--bucket", self.bucket, "--key", "magic",
                      "--tagging", 'k=&k=')
            assert 0, "InvalidParameter not raised"
        except subprocess.CalledProcessError as exc:
            self.assertIn(b'x-amz-tagging', exc.output)

    def test_tagging_with_mpu(self):
        data = run_s3api("create-multipart-upload",
                         "--bucket", self.bucket,
                         "--key", "magic",
                         "--tagging", "key=val")
        upload_id = data['UploadId']
        data = run_s3api("upload-part",
                         "--bucket", self.bucket, "--key", "magic",
                         "--upload-id", upload_id,
                         "--part-number", "1",
                         "--body", "/etc/magic")
        mpu_parts = [{"ETag": data['ETag'], "PartNumber": 1}]
        data = run_s3api("complete-multipart-upload",
                         "--bucket", self.bucket, "--key", "magic",
                         "--upload-id",  upload_id,
                         "--multipart-upload",
                         json.dumps({"Parts": mpu_parts}))

        data = run_s3api("get-object-tagging", "--bucket", self.bucket,
                         "--key", "magic")
        self.assertEqual(data['TagSet'][0]['Key'], 'key')
        self.assertEqual(data['TagSet'][0]['Value'], 'val')


if __name__ == "__main__":
    unittest.main()
