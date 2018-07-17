#!/bin/bash

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET=bucket-$RANDOM

# AWS="aws --profil amazon"
# BUCKET=openio.michael

echo "Bucket name: $BUCKET"

set -x
set -e

${AWS} s3api create-bucket --bucket ${BUCKET}

${AWS} s3api put-object --bucket ${BUCKET} --key small --body /etc/passwd --acl public-read-write --metadata key1=val1,key2=val2

${AWS} s3api copy-object --bucket ${BUCKET} --copy-source ${BUCKET}/small --key copy

# check metadata of copied object
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key copy)
echo "$data" | grep key1

# check ACL of copied object: it should be reset !
data=$(${AWS} s3api get-object-acl --bucket ${BUCKET} --key copy)
if [ $(echo "$data" | grep -c Grantee) -ne 1 ]; then
    echo "Invalid data"
    exit 1
fi

### METADATA

${AWS} s3api copy-object --bucket ${BUCKET} --copy-source ${BUCKET}/small --key copy --metadata key3=val3,key4=val4

# since --metadata-directive REPLACE was not specified, old metadata are kept
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key copy)
echo "$data" | grep key1

# and new metadata should be ignored
# Known issue on swift3: https://bugs.launchpad.net/swift3/+bug/1433875
echo "$data" | grep key3 && echo "new metadata should be ignored (swift3 issue #1433875)"

${AWS} s3api copy-object --bucket ${BUCKET} --copy-source ${BUCKET}/small --key copy --metadata key3=val3,key4=val4 --metadata-directive REPLACE

# since --metadata-directive REPLACE was specified, new metadata are used
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key copy)
echo "$data" | grep key3

# and old metadata should be discarded
# Known issue on swift3: https://bugs.launchpad.net/swift3/+bug/1433875
echo "$data" | grep key1 && echo "old metadata shoud be dropped (swift3 issue #1433875)"


### ACL

${AWS} s3api copy-object --bucket ${BUCKET} --copy-source ${BUCKET}/small --key copy --acl public-read-write
# check ACL of copied object: it should be reset !
data=$(${AWS} s3api get-object-acl --bucket ${BUCKET} --key copy)
if [ $(echo "$data" | grep -c Grantee) -ne 3 ]; then
    echo "Invalid data"
    exit 1
fi

echo "OK"
