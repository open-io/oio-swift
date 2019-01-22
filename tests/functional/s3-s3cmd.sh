#!/bin/bash

S3CMD="s3cmd"
AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET=bucket-$RANDOM

echo "Bucket name: $BUCKET"

set -e

${S3CMD} mb s3://${BUCKET}

echo "Upload a file with Content-Type text/plain"
${S3CMD} put /etc/passwd s3://${BUCKET} --content-type "text/plain"

echo "Check Content-Type is text/plain"
contenttype=$(${AWS} s3api head-object --bucket ${BUCKET} --key passwd | jq .ContentType)
[ ${contenttype} = '"text/plain"' ]

echo Modify object by adding a new header
${S3CMD} modify s3://${BUCKET}/passwd --add-header "X-Content":"test"

echo "Check Content-Type is not updated"
contenttype=$(${AWS} s3api head-object --bucket ${BUCKET} --key passwd | jq .ContentType)
[ ${contenttype} = '"text/plain"' ]

${S3CMD} rm s3://${BUCKET}/passwd

${S3CMD} rb s3://${BUCKET}
