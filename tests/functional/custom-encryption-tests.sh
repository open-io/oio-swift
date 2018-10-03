#!/bin/bash

# This script expects a swift gateway with OIO's custom encryption middleware.

export OIO_NS="${OIO_NS:-OPENIO}"
# We suppose the gateway is using tempauth and the user is "demo:demo"
export OIO_ACCOUNT="${OIO_ACCOUNT:-AUTH_demo}"

ALGO="AES256"
SECRET="abcdef0123456789ABCDEF0123456789"

PORT=${PORT:-5000}
AWS="aws --endpoint-url http://localhost:${PORT} --no-verify-ssl"
ENC_OPTS="--sse-c $ALGO --sse-c-key $SECRET"
ENC_OPTS_EXT="--sse-customer-algorithm $ALGO --sse-customer-key $SECRET"

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
{AWS} s3 mb "s3://$BUCKET"

echo "Uploading $OBJ_1_SRC"
${AWS} s3 cp "${OBJ_1_SRC}" "s3://$BUCKET/obj_1"

echo "Uploading $OBJ_1_SRC, with encryption"
${AWS} s3 cp "${OBJ_1_SRC}" "s3://$BUCKET/obj_1_cyphered" ${ENC_OPTS}

echo "Uploading a bigger file"
${AWS} s3 cp "${OBJ_2_SRC}" "s3://$BUCKET/obj_2"

echo "Uploading a bigger file, with encryption"
${AWS} s3 cp "${OBJ_2_SRC}" "s3://$BUCKET/obj_2_cyphered" ${ENC_OPTS}

echo "Checking objects appears in listings"
LISTING=$(${AWS} s3 ls "s3://$BUCKET")
echo "$LISTING" | grep "\\<obj_1\\>"
echo "$LISTING" | grep "obj_1_cyphered"
echo "$LISTING" | grep "\\<obj_2\\>"
echo "$LISTING" | grep "obj_2_cyphered"

echo "Checking reported checksum of obj_1"
OBJ_1_ETAG=$(${AWS} s3api head-object --bucket "$BUCKET" --key "obj_1" | sed -n -E -e "${ETAG_REGEX}")
[ "$OBJ_1_ETAG" == "$OBJ_1_CHECKSUM" ]

echo "Downloading it"
${AWS} s3 cp "s3://$BUCKET/obj_1" ./

echo "Checking downloaded object"
echo "$OBJ_1_CHECKSUM obj_1" | md5sum -c -

echo "Downloading same object with openio CLI"
openio object save "$BUCKET" "obj_1" --file "./obj_1.openio"

echo "Checking it is the same (because it is not cyphered)"
[ "$OBJ_1_CHECKSUM" == "$(md5sum ./obj_1.openio | cut -d ' ' -f 1)" ]

echo "Checking reported checksum of obj_1_cyphered"
OBJ_1_ETAG=$(${AWS} s3api head-object --bucket "$BUCKET" --key "obj_1_cyphered" ${ENC_OPTS_EXT} | sed -n -E -e "${ETAG_REGEX}")
[ "$OBJ_1_ETAG" == "$OBJ_1_CHECKSUM" ]

set -x
echo "Adding some metadata, and checking it"
${AWS} s3api copy-object --bucket "$BUCKET" --key "obj_1_cyphered" --copy-source "${BUCKET}/obj_1_cyphered" ${ENC_OPTS_EXT} --metadata "a=b" --metadata-directive REPLACE
OBJ_1_MD=$(${AWS} s3api head-object --bucket "$BUCKET" --key "obj_1_cyphered" ${ENC_OPTS_EXT} | jq ".Metadata")
echo "$OBJ_1_MD" | grep '"a": "b"'

echo "Downloading it"
${AWS} s3 cp "s3://$BUCKET/obj_1_cyphered" ./ ${ENC_OPTS}

echo "Checking downloaded object"
echo "$OBJ_1_CHECKSUM obj_1_cyphered" | md5sum -c -

echo "Downloading same object with openio CLI"
openio object save "$BUCKET" "obj_1_cyphered" --file "./obj_1_cyphered.openio"

echo "Checking it is different (because it is cyphered)"
[ "$OBJ_1_CHECKSUM" != "$(md5sum ./obj_1_cyphered.openio | cut -d ' ' -f 1)" ]

echo "Checking its hash"
OBJ_1_HASH=$(openio object show -f value -c hash "$BUCKET" "obj_1_cyphered")
[ "${OBJ_1_HASH,,}" == "$(md5sum ./obj_1_cyphered.openio | cut -d ' ' -f 1)" ]

echo "Removing obj_1 and obj_1_cyphered"
${AWS} s3 rm "s3://$BUCKET/obj_1"
${AWS} s3 rm "s3://$BUCKET/obj_1_cyphered"

echo "Downloading obj_2"
${AWS} s3 cp "s3://$BUCKET/obj_2" ./

echo "Checking downloaded object"
echo "$OBJ_2_CHECKSUM obj_2" | md5sum -c -

echo "Downloading obj_2_cyphered"
${AWS} s3 cp "s3://$BUCKET/obj_2_cyphered" ./ ${ENC_OPTS}

echo "Checking downloaded object"
echo "$OBJ_2_CHECKSUM obj_2_cyphered" | md5sum -c -

echo "Removing obj_2 and obj_2_cyphered"
${AWS} s3 rm "s3://$BUCKET/obj_2"
${AWS} s3 rm "s3://$BUCKET/obj_2_cyphered"


set +e

# used as invalid to read object from S3
SECRET2="ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
# used as new key during Server Side Copy
SECRET3="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

echo "Upload small object"
${AWS} s3 cp $OBJ_1_SRC s3://${BUCKET}/magic \
    --sse-c-key $SECRET --sse-c AES256

echo "Download object without key"
rm -f $WORKDIR/magic
${AWS} s3 cp s3://${BUCKET}/magic $WORKDIR/magic
if [ -f $WORKDIR/magic ]; then
    echo "(E) Read should failed with a bad key"
    RET=1
fi

echo "Download object with nonmatching key"
rm -f $WORKDIR/magic
${AWS} s3 cp s3://${BUCKET}/magic $WORKDIR/magic \
    --sse-c-key "$SECRET2" --sse-c AES256
if [ -f $WORKDIR/magic ]; then
    echo "(E) Invalid read, it should be forbidden (bad key)"
    RET=1
fi

echo "Copy object to unprotect one"
${AWS} s3 cp s3://${BUCKET}/magic s3://${BUCKET}/magic_copy \
    --sse-c-copy-source-key "$SECRET" --sse-c-copy-source AES256

echo "Retrieve unprotected object"
${AWS} s3 cp s3://${BUCKET}/magic_copy $WORKDIR/magic_copy
cmp $WORKDIR/magic_copy $OBJ_1_SRC
if [ $? -ne 0 ]; then
    echo "(E) Invalid server-side copy, file is not same as source"
    RET=1
fi


### SLO
echo "Upload SLO object"
${AWS} s3 cp $OBJ_2_SRC s3://${BUCKET}/32M \
    --sse-c-key "$SECRET" --sse-c AES256

echo "Download object with proper key"
${AWS} s3 cp s3://${BUCKET}/32M $WORKDIR/32M \
    --sse-c-key "$SECRET" --sse-c AES256
cmp $WORKDIR/32M $OBJ_2_SRC
if [ $? -ne 0 ]; then
    echo "(E) Invalid read, file is not same as source"
    RET=1
fi

echo "Download object with other key"
rm -f $WORKDIR/32M
${AWS} s3 cp s3://${BUCKET}/32M $WORKDIR/32M \
    --sse-c-key "$SECRET2" --sse-c AES256
if [ $? -eq 0 ]; then
    echo "(E) Read should failed with a bad key"
    RET=1
fi

echo "Download object without key"
rm -f $WORKDIR/32M
${AWS} s3 cp s3://${BUCKET}/32M $WORKDIR/32M
if [ $? -eq 0 ]; then
    echo "(E) Read should failed without key"
    RET=1
fi

echo "Copy object to unciphered new object"
rm -f $WORKDIR/32M_copy
${AWS} s3 cp s3://${BUCKET}/32M s3://${BUCKET}/32M_copy \
    --sse-c-copy-source-key "$SECRET" --sse-c-copy-source AES256
if [ $? -ne 0 ]; then
    echo "(E) Server Side Copy has failed"
    RET=1
fi

echo "Downloading unciphered copy object"
rm -f $WORKDIR/32M_copy
${AWS} s3 cp s3://${BUCKET}/32M_copy $WORKDIR/32M_copy
if [ -f $WORKDIR/32M_copy ]; then
    cmp $WORKDIR/32M_copy $OBJ_2_SRC
    if [ $? -ne 0 ]; then
        echo "(E) Invalid read, file is not same as source (SSC)"
        RET=1
    fi
else
    echo "(E) Invalid read, file is missing (SSC)"
    RET=1
fi

echo "Copy object on bucket with a new key"
${AWS} s3 cp s3://${BUCKET}/32M s3://${BUCKET}/32M_copy2 \
    --sse-c-copy-source-key "$SECRET" --sse-c-copy-source AES256 \
    --sse-c-key "$SECRET3" --sse-c AES256
if [ $? -ne 0 ]; then
    echo "(E) Server Side Copy has failed (2 keys)"
    RET=1
fi

echo "Download copied object with new key"
rm -f $WORKDIR/32M_copy2
${AWS} s3 cp s3://${BUCKET}/32M_copy2 $WORKDIR/32M_copy2 \
    --sse-c-key "$SECRET3" --sse-c AES256
cmp $WORKDIR/32M_copy2 $OBJ_2_SRC
if [ $? -ne 0 ]; then
    echo "(E) Invalid read, file is not same as source (2 keys)"
    RET=1
fi

echo "Removing bucket $BUCKET"
${AWS} s3 rb "s3://$BUCKET"

cd -
rm -rf "$WORKDIR"

exit $RET
