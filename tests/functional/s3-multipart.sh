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
SEGS=$(openio object list ${BUCKET}+segments -f value)
[ -n "$SEGS" ]
SEG_COUNT=$(echo -n "${SEGS}" | wc -l)

echo "Fetching this object"
${AWS} s3 cp "s3://$BUCKET/obj" obj
diff "${MULTI_FILE}" obj

echo "Changing object metadata"
${AWS} s3api put-object-acl --acl public-read --bucket ${BUCKET} --key "obj"

ACL=$(${AWS} s3api get-object-acl --bucket ${BUCKET} --key "obj")
[[ "${ACL}" == *'"Permission": "READ"'* ]]

echo "Counting segments with openio CLI (should be the same, we just changed metadata)"
SEGS2=$(openio object list ${BUCKET}+segments -f value)
[ -n "$SEGS2" ]
SEG_COUNT2=$(echo -n "${SEGS2}" | wc -l)
[ "$SEG_COUNT" -eq "$SEG_COUNT2" ]
[ "$SEGS" == "$SEGS2" ]

echo "Fetching this object"
${AWS} s3 cp "s3://$BUCKET/obj" obj
diff "${MULTI_FILE}" obj

dd if=/dev/zero of="${MULTI_FILE}" count=1 bs=1M oflag=append conv=notrunc
echo "Overwriting with a bigger object"
${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/obj"

echo "Counting segments with openio CLI (should be the same, object is just slightly bigger)"
SEGS3=$(openio object list ${BUCKET}+segments -f value)
[ -n "$SEGS3" ]
SEG_COUNT3=$(echo -n "${SEGS3}" | wc -l)
[ "$SEG_COUNT2" -eq "$SEG_COUNT3" ]
[ "$SEGS2" != "$SEGS3" ]

echo "Fetching this bigger object"
${AWS} s3 cp "s3://$BUCKET/obj" obj
diff "${MULTI_FILE}" obj

echo "Overwriting with a small object (not multipart)"
${AWS} s3 cp "$SMALL_FILE" "s3://$BUCKET/obj"

echo "Counting segments with openio CLI (should be zero)"
SEGS4=$(openio object list ${BUCKET}+segments -f value)
[ -z "$SEGS4" ]
SEG_COUNT4=$(echo -n "${SEGS4}" | wc -l)
[ "$SEG_COUNT4" -eq "0" ]

echo "Fetching this small object"
${AWS} s3 cp "s3://$BUCKET/obj" obj
diff "${SMALL_FILE}" obj

echo
echo "Cleanup"
echo "-------"
${AWS} s3 rm "s3://$BUCKET/obj"
${AWS} s3 rb "s3://$BUCKET"
rm "$MULTI_FILE"
rm obj
