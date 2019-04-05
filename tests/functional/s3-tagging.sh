#!/bin/bash

GW_NETLOC="localhost:5000"
AWS="aws --endpoint-url http://${GW_NETLOC} --no-verify-ssl"
BUCKET="bucket0-${RANDOM}"
OBJ_SRC="/etc/resolv.conf"

set -e
set -x

echo "-> Bucket does not exist, bucket operations"
OUT=$(${AWS} --profile default s3api get-bucket-tagging --bucket "$BUCKET" 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified bucket does not exist"

OUT=$(${AWS} --profile default s3api put-bucket-tagging --bucket "$BUCKET" --tagging 'TagSet=[{Key=organization,Value=marketing}]' 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified bucket does not exist"

OUT=$(${AWS} --profile default s3api delete-bucket-tagging --bucket "$BUCKET" 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified bucket does not exist"


echo "-> Bucket does not exist, object operations"
OUT=$(${AWS} --profile default s3api get-object-tagging --bucket "$BUCKET" --key object 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified bucket does not exist"

OUT=$(${AWS} --profile default s3api put-object-tagging --bucket "$BUCKET" --key object --tagging 'TagSet=[{Key=organization,Value=marketing}]' 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified bucket does not exist"

OUT=$(${AWS} --profile default s3api delete-object-tagging --bucket "$BUCKET" --key object 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified bucket does not exist"


echo "-> Bucket exists, object does not exist, bucket operations"
${AWS} --profile default s3 mb "s3://$BUCKET"
# OK

OUT=$(${AWS} --profile default s3api get-bucket-tagging --bucket "$BUCKET" 2>&1 | tail -n 1)
echo "$OUT" | grep "There is no tag set associated with the bucket or object"

${AWS} --profile default s3api delete-bucket-tagging --bucket "$BUCKET" 2>&1
# OK

${AWS} --profile default s3api put-bucket-tagging --bucket "$BUCKET" --tagging 'TagSet=[{Key=organization,Value=marketing}]'
# OK

OUT=$(${AWS} --profile default s3api get-bucket-tagging --bucket "$BUCKET" | jq -S ".TagSet")
echo "$OUT"
[ "$(echo "$OUT" | md5sum)" = "411b4cd1fdcc50a00868df18ff18383f  -" ]

${AWS} --profile default s3api delete-bucket-tagging --bucket "$BUCKET" 2>&1
# OK

OUT=$(${AWS} --profile default s3api get-bucket-tagging --bucket "$BUCKET" 2>&1 | tail -n 1)
echo "$OUT" | grep "There is no tag set associated with the bucket or object"


echo "-> Bucket exists, object does not exist, object operations"
OUT=$(${AWS} --profile default s3api get-object-tagging --bucket "$BUCKET" --key object 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified key does not exist"

OUT=$(${AWS} --profile default s3api put-object-tagging --bucket "$BUCKET" --key object --tagging 'TagSet=[{Key=organization,Value=marketing}]' 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified key does not exist"

OUT=$(${AWS} --profile default s3api delete-object-tagging --bucket "$BUCKET" --key object 2>&1 | tail -n 1)
echo "$OUT" | grep "The specified key does not exist"


echo "-> Bucket exists, object exists, object operations"
${AWS} --profile default s3 cp "${OBJ_SRC}" "s3://${BUCKET}/object"

# We could think this would raise an error, but actually it returns an empty tagset
#OUT=$(${AWS} --profile default s3api get-object-tagging --bucket "$BUCKET" --key object 2>&1 | tail -n 1)
#echo "$OUT" | grep "There is no tag set associated with the bucket or object"
OUT=$(${AWS} --profile default s3api get-object-tagging --bucket "$BUCKET" --key object 2>&1 | jq -S ".TagSet")
echo "$OUT"
[ "$(echo "$OUT" | md5sum)" = "58e0494c51d30eb3494f7c9198986bb9  -" ]

${AWS} --profile default s3api delete-object-tagging --bucket "$BUCKET" --key object
# OK

${AWS} --profile default s3api put-object-tagging --bucket "$BUCKET" --key object --tagging 'TagSet=[{Key=organization,Value=marketing}]'
# OK

OUT=$(${AWS} --profile default s3api get-object-tagging --bucket "$BUCKET" --key object | jq -S ".TagSet")
echo "$OUT"
[ "$(echo "$OUT" | md5sum)" = "411b4cd1fdcc50a00868df18ff18383f  -" ]

${AWS} --profile default s3api delete-object-tagging --bucket "$BUCKET" --key object
# OK

#OUT=$(${AWS} --profile default s3api get-object-tagging --bucket "$BUCKET" --key object 2>&1 | tail -n 1)
#echo "$OUT" | grep "There is no tag set associated with the bucket or object"
OUT=$(${AWS} --profile default s3api get-object-tagging --bucket "$BUCKET" --key object 2>&1 | jq -S ".TagSet")
echo "$OUT"
[ "$(echo "$OUT" | md5sum)" = "58e0494c51d30eb3494f7c9198986bb9  -" ]


echo "-> OK, removing fixtures"
${AWS} --profile default s3 rm "s3://$BUCKET/object"
${AWS} --profile default s3 rb "s3://$BUCKET"
