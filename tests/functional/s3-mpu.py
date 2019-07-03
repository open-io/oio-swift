#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import subprocess
import string
import random
import json
import os

ENDPOINT = os.getenv("USE_ENDPOINT", "http://127.0.0.1:5000")
AWS = ["aws", "--endpoint", ENDPOINT]

random_chars = string.lowercase + string.digits


def random_str(size, chars=random_chars):
    return ''.join(random.choice(chars) for _ in range(size))


def run_aws(*params, **kwargs):
    cmd = AWS + list(params)
    print(*cmd)
    out = subprocess.check_output(cmd)
    data = out.decode('utf8')
    return json.loads(data) if data else data


def run_test(bucket, path):
    """
    It will create a bucket, upload an object with MPU:
    - check upload in progress (with or without prefix)
    - check parts of current upload
    - copy an object by using copy of MPU
    """
    size = 10 * 1024 * 1024
    mpu_size = 524288 * 10

    print("******")
    print("bucket:", bucket)
    print("object:", path)
    print("size:", size)
    print("MPU chunksize:", mpu_size)

    # create bucket
    data = run_aws("s3api", "create-bucket", "--bucket", bucket)
    assert data['Location'] == '/%s' % bucket

    full_data = b"*" * size

    # create MPU
    data = run_aws("s3api", "create-multipart-upload",
                   "--bucket", bucket, "--key", path)
    upload_id = data['UploadId']

    # list uploads in progress
    data = run_aws("s3api", "list-multipart-uploads", "--bucket", bucket)
    assert len(data.get('Uploads', [])) == 1, \
        "Found more than current upload: %s" % data

    # list uploads in progress with bucket prefix
    data = run_aws("s3api", "list-multipart-uploads",
                   "--bucket", bucket, "--prefix", path)
    assert len(data.get('Uploads', [])) == 1

    # list MPU of upload: should be empty
    data = run_aws("s3api", "list-parts", "--bucket", bucket,
                   "--key", path, "--upload-id", upload_id)
    assert len(data.get('Parts', [])) == 0

    mpu_parts = []
    for idx, start in enumerate(range(0, size, mpu_size), start=1):
        raw = full_data[start:start+mpu_size]
        open("/tmp/part", "wb").write(raw)
        data = run_aws("s3api", "upload-part", "--bucket", bucket,
                       "--key", path, "--part-number", str(idx),
                       "--upload-id", upload_id, "--body", "/tmp/part")
        os.unlink("/tmp/part")
        print("UPLOAD", json.dumps(data))
        mpu_parts.append({"ETag": data['ETag'], "PartNumber": idx})

    # list MPU
    data = run_aws("s3api", "list-parts", "--bucket", bucket, "--key", path,
                   "--upload-id", upload_id)
    assert len(data.get('Parts', [])) == 2

    # list uploads in progress
    data = run_aws("s3api", "list-multipart-uploads", "--bucket", bucket)
    assert len(data.get('Uploads', [])) == 1

    # list uploads in progress with bucket prefix
    data = run_aws("s3api", "list-multipart-uploads", "--bucket", bucket,
                   "--prefix", path)
    assert len(data.get('Uploads', [])) == 1

    # complete MPU
    data = run_aws("s3api", "complete-multipart-upload", "--bucket", bucket,
                   "--key", path, "--upload-id",  upload_id,
                   "--multipart-upload", json.dumps({"Parts": mpu_parts}))

    print("MPU COMPLETE", data)
    assert data['Key'] == path
    assert data['ETag'].endswith('-2"')

    data = run_aws("s3api", "head-object", "--bucket", bucket, "--key", path)
    assert data['ContentLength'] == size

    data = run_aws("s3api", "head-object", "--bucket", bucket, "--key", path,
                   "--part-number", "1")
    assert data.get('ContentLength', -1) == mpu_size

    # create a new object MPU by copying previous object as part of new object
    path2 = "dédé/copie"
    data = run_aws("s3api", "create-multipart-upload", "--bucket", bucket,
                   "--key", path2)
    upload_id = data['UploadId']

    src = "%s/%s" % (bucket, path)
    copy_mpu_parts = []
    for idx in (1, 2):
        data = run_aws("s3api", "upload-part-copy", "--bucket", bucket,
                       "--key", path2, "--copy-source", src,
                       "--part-number", str(idx), "--upload-id", upload_id)
        copy_mpu_parts.append({"ETag": data['CopyPartResult']['ETag'],
                               "PartNumber": idx})

    # complete MPU
    data = run_aws("s3api", "complete-multipart-upload", "--bucket", bucket,
                   "--key", path2, "--upload-id",  upload_id,
                   "--multipart-upload", json.dumps({"Parts": copy_mpu_parts}))
    print(data, copy_mpu_parts)
    assert data['Key'] == path2.decode('utf-8')
    assert data['ETag'].endswith('-2"')

    data = run_aws("s3api", "head-object", "--bucket", bucket, "--key", path2)
    assert data['ContentLength'] == size * 2

    data = run_aws("s3api", "head-object", "--bucket", bucket, "--key", path2,
                   "--part-number", "1")
    assert data.get('ContentLength', -1) == size


def main():
    run_test(random_str(10),
             "docker/registry/v2/repositories/hello/_uploads/333633b0-503f-4b2a-9b43-e56ec6445ef3/data")  # noqa
    run_test(random_str(10),
             "CBB_DESKTOP-1LC5CCV/C:/Bombay/Logs/titi:/12121212/titi")
    run_test(random_str(10), random_str(10))


if __name__ == "__main__":
    main()
