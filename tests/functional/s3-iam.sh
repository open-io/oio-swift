#!/bin/bash

# "default" is administrator
AWS="aws --profile default --endpoint-url http://localhost:5000"
# "user1" is only allowed some operations
AWSU1="aws --profile user1 --endpoint-url http://localhost:5000"

U1_BUCKET="user1bucket"
SHARED_BUCKET="sharedbucket"
TEMPDIR=`mktemp -td s3-iam-XXXXXX`

set -e
set -x

# user1 cannot create buckets
OUT=$(${AWSU1} s3 mb s3://$U1_BUCKET 2>&1 | tail -n 1)
echo "$OUT" | grep "AccessDenied"

# admin can create buckets
${AWS} s3 mb s3://$U1_BUCKET
${AWS} s3 mb s3://$SHARED_BUCKET

# user1 cannot create any object in the shared bucket...
OUT=$(${AWSU1} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
echo "$OUT" | grep "AccessDenied"

# but can create objects prefixed by its user name
${AWSU1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic

# admin can create any object in the shared bucket
${AWS} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic

# user1 can create any object in its own bucket
${AWSU1} s3 cp /etc/magic s3://${U1_BUCKET}/magic
${AWSU1} s3 cp /etc/magic s3://${U1_BUCKET}/not_so_magic

# user1 can read any object from the shared bucket
${AWSU1} s3 ls s3://${SHARED_BUCKET}/
${AWSU1} s3 cp s3://${SHARED_BUCKET}/magic "$TEMPDIR/magic"
${AWSU1} s3 cp s3://${SHARED_BUCKET}/user1_magic "$TEMPDIR/user1_magic"

# admin can read objects from any bucket
${AWS} s3 cp s3://${U1_BUCKET}/magic "$TEMPDIR/magic"

# user1 can delete objects from its own bucket
${AWSU1} s3 rm s3://${U1_BUCKET}/magic

# user1 cannot delete objects from the shared bucket...
OUT=$(${AWSU1} s3 rm s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
echo "$OUT" | grep "AccessDenied"
# except objects prefixed by its user name.
${AWSU1} s3 rm s3://${SHARED_BUCKET}/user1_magic

# admin can delete objects from any bucket
${AWS} s3 rm s3://${SHARED_BUCKET}/magic
${AWS} s3 rm s3://${U1_BUCKET}/not_so_magic

# user1 cannot delete buckets
OUT=$(${AWSU1} s3 rb s3://$U1_BUCKET 2>&1 | tail -n 1)
echo "$OUT" | grep "AccessDenied"

# admin can delete any bucket
${AWS} s3 rb s3://$U1_BUCKET
${AWS} s3 rb s3://$SHARED_BUCKET

rm -r "$TEMPDIR"
