#!/bin/bash

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET="bucket-$RANDOM"

OBJ1_1="/etc/passwd"
OBJ1_2="/etc/fstab"

OBJ1_1_MD5=$(md5sum "$OBJ1_1" | cut -d ' ' -f 1)
OBJ1_2_MD5=$(md5sum "$OBJ1_2" | cut -d ' ' -f 1)

set -e

echo "Cerating bucket $BUCKET"
${AWS} s3 mb "s3://${BUCKET}"

echo "Putting an object before enabling versioning"
${AWS} s3 cp "${OBJ1_1}" "s3://${BUCKET}/obj1"

echo "Listing objects versions"
${AWS} s3api list-object-versions --bucket "${BUCKET}"

echo "Enabling versioning"
${AWS} s3api put-bucket-versioning --versioning-configuration Status=Enabled --bucket "${BUCKET}"

echo "Putting another object over the first one"
${AWS} s3 cp  "${OBJ1_2}" "s3://${BUCKET}/obj1"

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
echo "$ALL_OBJ_VERS" | grep "${OBJ1_1_MD5}"
echo "$ALL_OBJ_VERS" | grep "${OBJ1_2_MD5}"

# The first of the list is the latest version
OBJ1_1_ID=$(jq ".Versions[1].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ1_2_ID=$(jq ".Versions[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")

echo "Deleting the most recent version"
${AWS} s3api delete-object --bucket "${BUCKET}" --key "obj1" --version-id "${OBJ1_2_ID}"

echo "Listing objects versions"
${AWS} s3api list-object-versions --bucket "${BUCKET}" | grep "${OBJ1_1_MD5}"

echo "Deleting the last remaining version"
${AWS} s3api delete-object --bucket "${BUCKET}" --key "obj1" --version-id "${OBJ1_1_ID}"

echo "Deleting the bucket"
${AWS} s3 rb "s3://${BUCKET}"
