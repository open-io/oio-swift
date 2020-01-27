#!/bin/bash

# "default" is administrator
AWSA1ADM="aws --profile default --endpoint-url http://localhost:5000"
# "user1" is only allowed some operations
AWSA1U1="aws --profile user1 --endpoint-url http://localhost:5000"
# "as2adm" is administrator
AWSA2ADM="aws --profile a2adm --endpoint-url http://localhost:5000"
# "a2u1" is only allowed some operations
AWSA2U1="aws --profile a2u1 --endpoint-url http://localhost:5000"

U1_BUCKET="user1bucket"
SHARED_BUCKET="sharedbucket"
TEMPDIR=$(mktemp -td s3-iam-XXXXXX)
BIGFILE="$TEMPDIR/bigfile"
dd if=/dev/urandom of="${BIGFILE}" bs=1M count=16

set -e
set -x

test_create_bucket() {
  # user1 cannot create buckets
  OUT=$(${AWSA1U1} s3 mb s3://$U1_BUCKET 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # admin can create buckets
  ${AWSA1ADM} s3 mb s3://$U1_BUCKET
  ${AWSA1ADM} s3 mb s3://$SHARED_BUCKET
}

test_create_objects() {
  # user1 cannot create any object in the shared bucket...
  OUT=$(${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # but can create objects prefixed by its user name
  ${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic
  ${AWSA1U1} s3 cp "${BIGFILE}" s3://${SHARED_BUCKET}/user1_bigfile

  # admin can create any object in the shared bucket
  ${AWSA1ADM} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic
  ${AWSA1ADM} s3 cp "${BIGFILE}" s3://${SHARED_BUCKET}/bigfiles/bigfile

  # user1 can create any object in its own bucket
  ${AWSA1U1} s3 cp /etc/magic s3://${U1_BUCKET}/magic
  ${AWSA1U1} s3 cp /etc/magic s3://${U1_BUCKET}/not_so_magic
  ${AWSA1U1} s3 cp "${BIGFILE}" s3://${U1_BUCKET}/bigfiles/bigfile
}

test_multipart_ops() {
  # user1 can create a multipart upload
  UPLOAD_ID=$(${AWSA1U1} s3api create-multipart-upload --bucket ${SHARED_BUCKET} --key user1_mpu \
              | jq -r .UploadId)

  # user1 can upload parts
  ${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_mpu \
    --part-number 1 --upload-id "${UPLOAD_ID}" --body "${BIGFILE}"
  ${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_mpu \
    --part-number 2 --upload-id "${UPLOAD_ID}" --body "${BIGFILE}"

  # user1 cannot list parts
  OUT=$(${AWSA1U1} s3api list-parts --bucket ${SHARED_BUCKET} --key user1_mpu \
        --upload-id "${UPLOAD_ID}" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 cannot list multipart uploads
  OUT=$(${AWSA1U1} s3api list-multipart-uploads --bucket ${SHARED_BUCKET} \
        2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 cannot abort a multipart upload
  OUT=$(${AWSA1U1} s3api abort-multipart-upload --bucket ${SHARED_BUCKET} \
        --key user1_mpu --upload-id "${UPLOAD_ID}" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # admin can list parts
  ${AWSA1ADM} s3api list-parts --bucket ${SHARED_BUCKET} --key user1_mpu \
    --upload-id "${UPLOAD_ID}"

  # admin can list multipart uploads
  ${AWSA1ADM} s3api list-multipart-uploads --bucket ${SHARED_BUCKET}

  # admin can abort a multipart upload
  ${AWSA1ADM} s3api abort-multipart-upload --bucket ${SHARED_BUCKET} \
    --key user1_mpu --upload-id "${UPLOAD_ID}"
}

test_read_objects() {
  # user1 can read any object from the shared bucket
  ${AWSA1U1} s3 ls s3://${SHARED_BUCKET}/
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/magic "$TEMPDIR/magic"
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/user1_magic "$TEMPDIR/user1_magic"
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/bigfiles/bigfile "$TEMPDIR/bigfile_from_shared_bucket"

  # admin can read objects from any bucket
  ${AWSA1ADM} s3 cp s3://${U1_BUCKET}/magic "$TEMPDIR/magic"
  ${AWSA1ADM} s3 cp s3://${U1_BUCKET}/bigfiles/bigfile "$TEMPDIR/bigfile_from_u1_bucket"
}

test_delete_objects() {
  # user1 can delete objects from its own bucket
  ${AWSA1U1} s3 rm s3://${U1_BUCKET}/magic
  ${AWSA1U1} s3 rm s3://${U1_BUCKET}/bigfiles/bigfile

  # user1 cannot delete objects from the shared bucket...
  OUT=$(${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  # except objects prefixed by its user name.
  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic

  # admin can delete objects from any bucket
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/magic
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/user1_bigfile
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/bigfiles/bigfile
  ${AWSA1ADM} s3 rm s3://${U1_BUCKET}/not_so_magic
}

test_delete_buckets() {
  # user1 cannot delete buckets
  OUT=$(${AWSA1U1} s3 rb s3://$U1_BUCKET 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # admin can delete any bucket
  ${AWSA1ADM} s3 rb s3://$U1_BUCKET
  ${AWSA1ADM} s3 rb s3://$SHARED_BUCKET
}

test_create_bucket
test_create_objects
test_multipart_ops
test_read_objects
test_delete_objects
test_delete_buckets

rm -r "$TEMPDIR"
