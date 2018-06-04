#!/bin/bash

export OIO_NS="${1:-OPENIO}"
export OIO_ACCOUNT="${2:-AUTH_demo}"

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"
BUCKET="bucket-$RANDOM"

set -e

SMALL_FILE="/etc/resolv.conf"
MULTI_FILE=$(mktemp -t multipart_XXXXXX.dat)
dd if=/dev/zero of="${MULTI_FILE}" count=21 bs=1M

echo "Creating bucket ${BUCKET}"
${AWS} s3 mb "s3://$BUCKET"

echo
echo "Testing the deletion of parts when a multipart object is overwritten"
echo "--------------------------------------------------------------------"
echo
echo "Uploading a multipart object in bucket ${BUCKET}"
${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/obj"

echo "Counting segments with openio CLI"
SEG_COUNT=$(openio object list ${BUCKET}+segments -f value | wc -l)

dd if=/dev/zero of="${MULTI_FILE}" count=1 bs=1M oflag=append conv=notrunc
echo "Overwriting with a bigger object"
${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/obj"

echo "Counting segments with openio CLI (should be the same)"
SEG_COUNT2=$(openio object list ${BUCKET}+segments -f value | wc -l)
[ "$SEG_COUNT" -eq "$SEG_COUNT2" ]

echo "Overwriting with a small object (not multipart)"
${AWS} s3 cp "$SMALL_FILE" "s3://$BUCKET/obj"

echo "Counting segments with openio CLI (should be zero)"
SEG_COUNT3=$(openio object list ${BUCKET}+segments -f value | wc -l)
[ "$SEG_COUNT3" -eq "0" ]

echo
echo "Cleanup"
echo "-------"
${AWS} s3 rm "s3://$BUCKET/obj"
${AWS} s3 rb "s3://$BUCKET"
rm "$MULTI_FILE"
