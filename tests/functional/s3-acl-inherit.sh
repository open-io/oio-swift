#!/bin/bash

# In [filter:swift3] you must set:
#  - s3_acl = true
#  - s3_acl_inherit = true

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET=bucket-$RANDOM

echo "Bucket name: $BUCKET"

set -e

${AWS} s3api create-bucket --bucket ${BUCKET}

# This should not be readable by user tester2 because no acl is specified
${AWS} s3api put-object --bucket ${BUCKET} --key 'unreadable-by-tester2' --body /etc/passwd
echo 'This should not be readable by user tester2 because no acl is specified'
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key 'unreadable-by-tester2' --profile tester2 2>&1 || true)
grep "Forbidden" <<< $data || ( echo $data ; exit 1)

# New acl to permit new object to readable by user tester2
${AWS} s3api put-bucket-acl --bucket ${BUCKET} --grant-read id=tester2:tester2 --grant-full-control id=admin:admin

# File is readable by user tester2
echo 'File is readable by user tester2'
${AWS} s3api put-object --bucket ${BUCKET} --key 'readable-by-tester2' --body /etc/passwd
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key 'readable-by-tester2' --profile tester2)
grep "Forbidden" <<< $data && ( echo $data ; exit 1)

# Remove read permission to user tester2 the bucket
${AWS} s3api put-bucket-acl --bucket ${BUCKET} --grant-full-control id=admin:admin

# Old file is still readable
echo 'Old file is still readable'
${AWS} s3api head-object --bucket ${BUCKET} --key 'readable-by-tester2' --profile tester2

# New file is unreadable
echo 'New file is unreadable'
${AWS} s3api put-object --bucket ${BUCKET} --key 'unreadable-by-tester22' --body /etc/passwd
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key 'unreadable-by-tester22' --profile tester2 2>&1 || true)
grep "Forbidden" <<< $data || ( echo $data ; exit 1)

# New file is not modifiable
echo 'New file is not modifiable'
${AWS} s3api put-object --bucket ${BUCKET} --key 'unmodifiable-by-tester22' --body /etc/passwd
data=$(${AWS} s3api put-object --bucket ${BUCKET} --key 'unmodifiable-by-tester22' --body /etc/passwd --profile tester2 2>&1 || true)
grep "AccessDenied" <<< $data || ( echo $data ; exit 1)

# New acl to permit new object to readable by user tester2
${AWS} s3api put-bucket-acl --bucket ${BUCKET} --grant-write id=tester2:tester2 --grant-full-control id=admin:admin

# New file is modifiable
echo 'New file is modifiable'
${AWS} s3api put-object --bucket ${BUCKET} --key 'modifiable-by-tester22' --body /etc/passwd
${AWS} s3api put-object --bucket ${BUCKET} --key 'modifiable-by-tester22' --body /etc/passwd --profile tester2

# But old file is still not readable...
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key 'unmodifiable-by-tester22' --profile tester2 2>&1 || true)
grep "Forbidden" <<< $data || ( echo $data ; exit 1)

# But old file is modifiable as permission WRITE was given
echo 'But old file is modifiable as permission WRITE was given'
${AWS} s3api put-object --bucket ${BUCKET} --key 'unmodifiable-by-tester22' --body /etc/passwd --profile tester2

echo 'cleanup'
${AWS} s3api delete-objects --bucket ${BUCKET} --delete 'Objects=[{Key=unreadable-by-tester2},{Key=readable-by-tester2},{Key=modifiable-by-tester22},{Key=unmodifiable-by-tester22},{Key=unreadable-by-tester22}]'
${AWS} s3api list-objects --bucket ${BUCKET}
${AWS} s3api delete-bucket --bucket ${BUCKET}
