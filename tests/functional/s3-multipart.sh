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

echo "Check ETAG with more than 10 parts"
dd if=/dev/zero of=$MULTI_FILE bs=1M count=55
${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/obj"
DATA=$(${AWS} s3api head-object --bucket ${BUCKET} --key obj)
ETAG=$(echo $DATA | jq -r .ETag)

[ "$ETAG" == '"c9975699ef630d1f3dfc7224b16d1a25-11"' ]

OBJ_META=$(${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a25-11 obj)
ETAG=$(jq -r ".ETag|tostring" <<< "$OBJ_META")
[ "$ETAG" == '"c9975699ef630d1f3dfc7224b16d1a25-11"' ]
diff "${MULTI_FILE}" obj
if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a25-12 obj; then
    false
fi
if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a25 obj; then
    false
fi
if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a20-12 obj; then
    false
fi

echo "Fetching object with part number"
PART_FILE=$(mktemp -t part_XXXXXX.dat)
dd if="${MULTI_FILE}" of="${PART_FILE}" count=5 bs=1M
DATA=$(${AWS} s3api head-object --bucket ${BUCKET} --key obj --part-number 1)
ETAG=$(echo $DATA | jq -r .ETag)
[ "$ETAG" == '"c9975699ef630d1f3dfc7224b16d1a25-11"' ]
CONTENT_LENGTH=$(jq -r ".ContentLength|tostring" <<< "$DATA")
[ "$CONTENT_LENGTH" == '5242880' ]

PART_META=$(${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a25-11 --part-number 1 part)
ETAG=$(jq -r ".ETag|tostring" <<< "$PART_META")
[ "$ETAG" == '"c9975699ef630d1f3dfc7224b16d1a25-11"' ]
CONTENT_LENGTH=$(jq -r ".ContentLength|tostring" <<< "$PART_META")
[ "$CONTENT_LENGTH" == '5242880' ]
diff "${PART_FILE}" part

# Without swift3 etag properties
openio --oio-ns "${OIO_NS}" --oio-account "${OIO_ACCOUNT}" object unset "${BUCKET}" obj --property x-object-sysmeta-swift3-etag --property x-object-sysmeta-container-update-override-etag
DATA=$(${AWS} s3api head-object --bucket ${BUCKET} --key obj)
ETAG=$(echo $DATA | jq -r .ETag)
[ "$ETAG" == '"aeeb9a4f5125d76819644941190ce95b-N"' ]
OBJ_META=$(${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match aeeb9a4f5125d76819644941190ce95b-N obj)
ETAG=$(jq -r ".ETag|tostring" <<< "$OBJ_META")
[ "$ETAG" == '"aeeb9a4f5125d76819644941190ce95b-N"' ]
diff "${MULTI_FILE}" obj
OBJ_META=$(${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match aeeb9a4f5125d76819644941190ce95b obj)
ETAG=$(jq -r ".ETag|tostring" <<< "$OBJ_META")
[ "$ETAG" == '"aeeb9a4f5125d76819644941190ce95b-N"' ]
diff "${MULTI_FILE}" obj
if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match aeeb9a4f5125d76819644941190ce95b-12 obj; then
    false
fi
if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match aeeb9a4f5125d76819644941190ce950-N obj; then
    false
fi
if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match aeeb9a4f5125d76819644941190ce950 obj; then
    false
fi

echo
echo "Cleanup"
echo "-------"
${AWS} s3 rm "s3://$BUCKET/obj"
${AWS} s3 rb "s3://$BUCKET"
rm "$MULTI_FILE"
rm obj
