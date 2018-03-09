#!/bin/bash

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET=bucket-$RANDOM

echo "Bucket name: $BUCKET"

dd if=/dev/zero of=bigfile bs=1M count=25
dd if=/dev/urandom of=randfile bs=1M count=30

set -x
set -e

${AWS} s3api create-bucket --bucket ${BUCKET}
${AWS} s3api put-object --bucket ${BUCKET} --key small --body /etc/passwd
# ${AWS} s3api put-object --bucket ${BUCKET} --key root --body bigfile
${AWS} s3 cp bigfile s3://${BUCKET}/root

${AWS} s3 cp s3://${BUCKET}/root testfile
[ "$(md5sum bigfile | cut -d\  -f1)" = "$(md5sum testfile | cut -d\  -f1)" ]
rm testfile

# OVERWRITE MPU
# ${AWS} s3api cp --bucket ${BUCKET} --key root --body randfile
${AWS} s3 cp randfile s3://${BUCKET}/root

${AWS} s3 cp s3://${BUCKET}/root testfile
[ "$(md5sum randfile | cut -d\  -f1)" = "$(md5sum testfile | cut -d\  -f1)" ]
rm testfile

${AWS} s3api put-object --bucket ${BUCKET} --key dir1/dir2/object --body /etc/passwd

OUT=$( ${AWS} s3api list-objects --bucket ${BUCKET} )
echo ${OUT} | grep small
echo ${OUT} | grep root
echo ${OUT} | grep dir1/dir2/object

OUT=$( ${AWS} s3 ls --recursive s3://${BUCKET} )
echo ${OUT} | grep small
echo ${OUT} | grep root
echo ${OUT} | grep dir1/dir2/object


S3CMD="/home/murlock/openio/resources/s3cmd"
${AWS} s3 cp bigfile s3://${BUCKET}/subdir/bigfile

${AWS} s3 cp s3://${BUCKET}/subdir/bigfile testfile
[ "$(md5sum bigfile | cut -d\  -f1)" = "$(md5sum testfile | cut -d\  -f1)" ]
rm testfile

# OVERWRITE MPU
${AWS} s3 cp randfile s3://${BUCKET}/subdir/bigfile
${AWS} s3 cp s3://${BUCKET}/subdir/bigfile testfile
[ "$(md5sum randfile | cut -d\  -f1)" = "$(md5sum testfile | cut -d\  -f1)" ]
rm testfile

# OVERWRITE MPU with simple file
${AWS} s3 cp /etc/passwd s3://${BUCKET}/subdir/bigfile
# CHECK MD5
${AWS} s3 cp s3://${BUCKET}/subdir/bigfile testfile
[ "$(md5sum /etc/passwd | cut -d\  -f1)" = "$(md5sum testfile | cut -d\  -f1)" ]
rm testfile


# CREATE SIMPLE OBJECT
${AWS} s3 cp /etc/passwd s3://${BUCKET}/subdir/simple
# OVERWRITE IT WITH MPU
${AWS} s3 cp randfile s3://${BUCKET}/subdir/bigfile
# CHECK MD5
${AWS} s3 cp s3://${BUCKET}/subdir/bigfile testfile
[ "$(md5sum randfile | cut -d\  -f1)" = "$(md5sum testfile | cut -d\  -f1)" ]
rm testfile

OUT=$( ${AWS} s3 ls --recursive s3://${BUCKET} )
echo ${OUT} | grep subdir/bigfile

# wait for event to be accounted
sleep 0.5
OUT=$( openio container list -f csv --quote none -c Name --oio-account AUTH_demo | grep ${BUCKET} )
echo ${OUT} | grep ${BUCKET}+segments

# SUBDIR

echo aa > aa

${AWS} s3api put-object --bucket ${BUCKET} --key d1/d2/d3/d4/o1 --body aa
${AWS} s3api put-object --bucket ${BUCKET} --key d1/d2/d3/d4/o2 --body aa
${AWS} s3api put-object --bucket ${BUCKET} --key v1/o2 --body aa
sleep 0.5
CNT=$( ${AWS} s3api list-objects --bucket ${BUCKET} | grep -c Key )
[ "$CNT" -ne 8 ]

# COPY S3<=>S3

BCK1=bucket-${RANDOM}
BCK2=bucket-${RANDOM}

${AWS} s3api create-bucket --bucket ${BCKT1}
${AWS} s3api create-bucket --bucket ${BCKT2}

# INIT
${AWS} s3 cp bigfile s3://${BUCKET}/root

# COPY AT ROOT
${AWS} s3 cp s3://${BCK1}/root s3://${BCK2}/root

# COPY AT SUBDIR
${AWS} s3 cp s3://${BCK1}/root s3://${BCK2}/d1/d2/d3/bigfile

# COPY SAME BUCKET
${AWS} s3 cp s3://${BCK1}/root s3://${BCK1}/same_bucket/bigfile

echo "OK"

# FIXME should check container created
