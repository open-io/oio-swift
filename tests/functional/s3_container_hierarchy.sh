#!/bin/bash

GW_NETLOC="127.0.0.1:5000"
#GW_NETLOC="127.0.0.1:5001"
BUCKET="bucket0"
OBJ_SRC="/etc/resolv.conf"
AWS_CMD="aws --endpoint-url http://${GW_NETLOC} --no-verify-ssl"
#AWS_CMD="aws --endpoint-url http://${GW_NETLOC} --no-verify-ssl --profile keystone"

set -e

echo "Creating bucket ${BUCKET}"
$AWS_CMD s3 mb "s3://${BUCKET}"

echo "Uploading some objects in bucket ${BUCKET}"
$AWS_CMD s3 cp "${OBJ_SRC}" "s3://${BUCKET}/file_at_root"
$AWS_CMD s3 cp "${OBJ_SRC}" "s3://${BUCKET}/subdir1/file_in_subdir1"
$AWS_CMD s3 cp "${OBJ_SRC}" "s3://${BUCKET}/subdir1/subdir2/file_in_subdir2"

echo "Uploading multipart object in bucket ${BUCKET}/subdir1/multi_in_subdir1"
MULTI_FILE=$(mktemp -t container_hierarchy_XXXXXX.dat)
dd if=/dev/zero of="${MULTI_FILE}" count=21 bs=1M
$AWS_CMD s3 cp "${MULTI_FILE}" "s3://${BUCKET}/subdir1/multi_in_subdir1"
rm "${MULTI_FILE}"

echo "Checking existing objects (HEAD)"
$AWS_CMD s3api head-object --bucket "${BUCKET}" --key "file_at_root"
$AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/file_in_subdir1"
$AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/subdir2/file_in_subdir2"

echo "Checking existing objects with trailing slashes (HEAD)"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "file_at_root/" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/file_in_subdir1/" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/subdir2/file_in_subdir2/" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"

echo "Checking directory placeholders (HEAD)"
$AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/"
$AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/subdir2/"

echo "Checking invalid objects (HEAD)"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "invalid_at_root" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/invalid_in_subdir1" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/subdir2/invalid_in_subdir2" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/invalid_dir/file_in_invalid_dir" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"

echo "Checking invalid objects with trailing slashes (HEAD)"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "invalid_at_root/" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/invalid_in_subdir1/" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/subdir2/invalid_in_subdir2/" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"
HEAD_OUT=$($AWS_CMD s3api head-object --bucket "${BUCKET}" --key "subdir1/invalid_dir/file_in_invalid_dir/" 2>&1 | tail -n 1)
echo "${HEAD_OUT}" | grep "Not Found"

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
subdir1/multi_in_subdir1
subdir1/subdir2/file_in_subdir2
EOF
set -e

[ "${LS_REC_OUT}" = "${EXPECTED}" ]

$AWS_CMD s3 rm "s3://${BUCKET}/file_at_root"
$AWS_CMD s3 rm "s3://${BUCKET}/subdir1/file_in_subdir1"
$AWS_CMD s3 rm "s3://${BUCKET}/subdir1/multi_in_subdir1"
$AWS_CMD s3 rm "s3://${BUCKET}/subdir1/subdir2/file_in_subdir2"

$AWS_CMD s3 rm "s3://${BUCKET}/subdir1/subdir2/"
$AWS_CMD s3 rm "s3://${BUCKET}/subdir1/"
$AWS_CMD s3 rb "s3://${BUCKET}/"

echo "OK"
