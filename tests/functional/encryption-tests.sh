#!/bin/bash

# This script expects a swift gateway with encryption middleware.

export OIO_NS="${OIO_NS:-OPENIO}"
# We suppose the gateway is using tempauth and the user is "demo:demo"
export OIO_ACCOUNT="${OIO_ACCOUNT:-AUTH_demo}"

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"
BUCKET=bucket-$RANDOM
ETAG_REGEX='s/(.*ETag.*)([[:xdigit:]]{32})(.*)/\2/p'
WORKDIR=$(mktemp -d -t encryption-tests-XXXX)
OBJ_1_SRC="/etc/magic"
OBJ_2_SRC="${WORKDIR}/bigfile_src"
dd if=/dev/urandom of="$OBJ_2_SRC" bs=1k count=20480
OBJ_1_CHECKSUM=$(md5sum "${OBJ_1_SRC}" | cut -d ' ' -f 1)
OBJ_2_CHECKSUM=$(md5sum "${OBJ_2_SRC}" | cut -d ' ' -f 1)

set -e

cd "$WORKDIR"
echo "Creating bucket $BUCKET"
${AWS} s3 mb "s3://$BUCKET"

echo "Uploading $OBJ_1_SRC"
${AWS} s3 cp "${OBJ_1_SRC}" "s3://$BUCKET/obj_1"

echo "Uploading a bigger file"
${AWS} s3 cp "${OBJ_2_SRC}" "s3://$BUCKET/obj_2"

echo "Checking objects appears in listings"
${AWS} s3 ls "s3://$BUCKET" | grep "obj_1"
${AWS} s3 ls "s3://$BUCKET" | grep "obj_2"

echo "Checking reported checksum of obj_1"
OBJ_1_ETAG=$(${AWS} s3api head-object --bucket "$BUCKET" --key "obj_1" | sed -n -E -e "${ETAG_REGEX}")
[ "$OBJ_1_ETAG" == "$OBJ_1_CHECKSUM" ]

echo "Downloading it"
${AWS} s3 cp "s3://$BUCKET/obj_1" ./

echo "Checking downloaded object"
echo "$OBJ_1_CHECKSUM obj_1" | md5sum -c -

echo "Downloading same object with openio CLI"
openio object save "$BUCKET" "obj_1" --file "./obj_1.openio"

echo "Checking it is different (because it is cyphered)"
[ "$OBJ_1_CHECKSUM" != "$(md5sum ./obj_1.openio | cut -d ' ' -f 1)" ]

echo "Checking its hash"
OBJ_1_HASH=$(openio object show -f value -c hash "$BUCKET" "obj_1")
[ "${OBJ_1_HASH,,}" == "$(md5sum ./obj_1.openio | cut -d ' ' -f 1)" ]

echo "Removing it"
${AWS} s3 rm "s3://$BUCKET/obj_1"

echo "Downloading obj_2"
${AWS} s3 cp "s3://$BUCKET/obj_2" ./

echo "Checking downloaded object"
echo "$OBJ_2_CHECKSUM obj_2" | md5sum -c -

echo "Removing obj2"
${AWS} s3 rm "s3://$BUCKET/obj_2"

echo "Removing bucket $BUCKET"
${AWS} s3 rb "s3://$BUCKET"

set +e

cd -
rm -rf "$WORKDIR"
