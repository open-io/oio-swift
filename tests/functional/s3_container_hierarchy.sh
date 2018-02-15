#!/bin/bash

GW_NETLOC="127.0.0.1:5000"
BUCKET="bucket0"
OBJ_SRC="/etc/resolv.conf"
AWS_CMD="aws --endpoint-url http://${GW_NETLOC} --no-verify-ssl"

set -e

echo "Creating bucket ${BUCKET}"
$AWS_CMD s3 mb "s3://${BUCKET}"

echo "Uploading some objects in bucket ${BUCKET}"
$AWS_CMD s3 cp "${OBJ_SRC}" "s3://${BUCKET}/file_at_root"
$AWS_CMD s3 cp "${OBJ_SRC}" "s3://${BUCKET}/subdir1/file_in_subdir1"
$AWS_CMD s3 cp "${OBJ_SRC}" "s3://${BUCKET}/subdir1/subdir2/file_in_subdir2"

echo "Listing objects at root of bucket ${BUCKET}"
LS_OUT=$($AWS_CMD s3 ls "s3://${BUCKET}")

echo "${LS_OUT}" | grep -q "PRE"
echo "${LS_OUT}" | grep -q "file_at_root"
LINES=$(echo "${LS_OUT}" | wc -l)
[ "$LINES" -eq "2" ]

echo "Listing objects from bucket ${BUCKET} recursively"
LS_REC_OUT=$($AWS_CMD s3 ls --recursive "s3://${BUCKET}" | awk '{print $4}')

set +e
read -d '' EXPECTED << EOF
file_at_root
subdir1/file_in_subdir1
subdir1/subdir2/file_in_subdir2
EOF
set -e

[ "${LS_REC_OUT}" = "${EXPECTED}" ]

echo "OK"
