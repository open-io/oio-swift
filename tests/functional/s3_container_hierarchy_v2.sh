#!/bin/bash

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"
BUCKET=bucket-$RANDOM
LISTING_VERSIONING=$(cat $CONF_GW | grep support_listing_versioning | cut -d= -f2 | sed 's/ //g' )

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

${AWS} s3 cp /etc/passwd  s3://${BUCKET}/dir1/dir2/object

OUT=$( ${AWS} s3api list-objects --bucket ${BUCKET} )
echo ${OUT} | grep small
echo ${OUT} | grep root
echo ${OUT} | grep dir1/dir2/object

OUT=$( ${AWS} s3 ls --recursive s3://${BUCKET} )
echo ${OUT} | grep small
echo ${OUT} | grep root
echo ${OUT} | grep dir1/dir2/object

# LISTING WITH : (simulate cloudberry)

echo "$LISTING_VERSIONING"
if [ "$LISTING_VERSIONING" != "true" ]; then
    d=$(date +%s)
    ${AWS} s3api put-object --bucket ${BUCKET} --key key1/key2/dot:/${d}/

    OUT=$( ${AWS} s3 ls s3://${BUCKET}/key1/key2 )
    echo ${OUT} | grep key2/
    OUT=$( ${AWS} s3 ls s3://${BUCKET}/key1/key2/dot )
    echo ${OUT} | grep dot

    OUT=$( ${AWS} s3api list-objects --bucket ${BUCKET} )
    echo ${OUT} | grep dot
    OUT=$( ${AWS} s3api list-objects --bucket ${BUCKET} --prefix key1/key2/dot:/${d}/ )
    echo ${OUT} | grep dot
fi

# UPLOAD WITH VERSIONING LIKE CloudBerry


for subpath in "CBB_DESKTOP-1LC5CCV/C:/Bombay/Logs" ""; do

    echo "############# PATH: ${subpath} #############"
    subpath2=
    if [ ! -z ${subpath} ];then
        subpath2="${subpath}/"
    fi
    echo "##### Single Object"
    ${AWS} s3 cp /etc/passwd s3://${BUCKET}/${subpath2}fichier:/${d}/fichier
    ${AWS} s3 cp s3://${BUCKET}/${subpath2}fichier:/${d}/fichier /tmp/fichier
    [ "$(md5sum /etc/passwd | cut -d\  -f1)" = "$(md5sum /tmp/fichier | cut -d\  -f1)" ]

    cntpath=$(echo ${subpath}| sed  's~/~%2F~g')
    if [ -n "${cntpath}" ]; then
        openio object list ${BUCKET}%2F${cntpath} -f csv --quote none -c Name --oio-account AUTH_demo | grep fichier
    else
        openio object list ${BUCKET} -f csv --quote none -c Name --oio-account AUTH_demo  | grep fichier
    fi

    echo "##### MPU Object"
    ${AWS} s3 cp randfile s3://${BUCKET}/${subpath2}fichier:/${d}/fichier
    ${AWS} s3 cp s3://${BUCKET}/${subpath2}fichier:/${d}/fichier /tmp/fichier
    [ "$(md5sum randfile | cut -d\  -f1)" = "$(md5sum /tmp/fichier | cut -d\  -f1)" ]

    cntpath=$(echo ${subpath}| sed  's~/~%2F~g')
    if [ -n "${cntpath}" ]; then
        openio object list ${BUCKET}+segments%2F${cntpath} -f csv --quote none -c Name --oio-account AUTH_demo | grep fichier
    else
        openio object list ${BUCKET}+segments -f csv --quote none -c Name --oio-account AUTH_demo | grep fichier
    fi
done

# LISTING WITH SPACE

${AWS} s3api put-object --bucket ${BUCKET} --key "directory 1/directory 2/object" --body /etc/passwd
${AWS} s3api put-object --bucket ${BUCKET} --key "directory 1/directory 2/other one" --body /etc/passwd

OUT=$( ${AWS} s3api list-objects --bucket ${BUCKET} )
echo ${OUT} | grep object
echo ${OUT} | grep "other one"

OUT=$( ${AWS} s3 ls "s3://${BUCKET}/directory 1/directory 2/" )
echo ${OUT} | grep object
echo ${OUT} | grep "other one"

# LISTING WITH MULTIPLE SLASH
${AWS} s3api put-object --bucket ${BUCKET} --key "/slash//subdir///object" --body /etc/passwd
OUT=$( ${AWS} s3api list-objects --bucket ${BUCKET} )
echo ${OUT} | grep "/slash//subdir///object"
OUT=$( ${AWS} s3 ls "s3://${BUCKET}//slash//subdir///" )
echo ${OUT} | grep "object"
${AWS} s3 cp bigfile s3://${BUCKET}//slash//subdir///bigfile
OUT=$( ${AWS} s3api list-objects --bucket ${BUCKET} )
echo ${OUT} | grep "/slash//subdir///bigfile"
OUT=$( ${AWS} s3 ls "s3://${BUCKET}//slash//subdir///" )
echo ${OUT} | grep "bigfile"

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
${AWS} s3 cp randfile s3://${BUCKET}/subdir/simple
# CHECK MD5
${AWS} s3 cp s3://${BUCKET}/subdir/simple testfile
[ "$(md5sum randfile | cut -d\  -f1)" = "$(md5sum testfile | cut -d\  -f1)" ]
rm testfile

OUT=$( ${AWS} s3 ls --recursive s3://${BUCKET} )
echo ${OUT} | grep subdir/simple

# wait for event to be accounted
sleep 0.5
OUT=$( openio container list -f csv --quote none -c Name --oio-account AUTH_demo | grep ${BUCKET} )
echo ${OUT} | grep ${BUCKET}+segments

# CHECK BUCKET NAME METADATA
OUT=$( openio object show ${BUCKET} small --oio-account AUTH_demo -f shell | grep oio.bucket.name | cut -d = -f 2)
if [ "${OUT}" != "\"${BUCKET}\"" ]
then
    echo "ERROR: bucket name not on metadata"
    exit 1
fi
# SUBDIR

echo aa > aa

${AWS} s3api put-object --bucket ${BUCKET} --key d1/d2/d3/d4/o1 --body aa
${AWS} s3api put-object --bucket ${BUCKET} --key d1/d2/d3/d4/o2 --body aa
${AWS} s3api put-object --bucket ${BUCKET} --key v1/o2 --body aa
sleep 0.5
CNT=$( ${AWS} s3api list-objects --bucket ${BUCKET} | grep -c Key )
OBJECT=14
if [ "$LISTING_VERSIONING" != "true" ]; then
    OBJECT=$((OBJECT + 1))
fi
[ "$CNT" -eq $OBJECT ]

# Check HEAD on directory "Object"
${AWS} s3api put-object  --bucket ${BUCKET} --key dir1/dir2/
${AWS} s3api head-object --bucket ${BUCKET} --key dir1/dir2/

# UTF-8 PATH
# The '?' are caused by "s3 ls": https://github.com/aws/aws-cli/issues/3902
BUCKET_UTF8=bucket-${RANDOM}
${AWS} s3api create-bucket --bucket ${BUCKET_UTF8}
${AWS} s3 cp /etc/passwd s3://${BUCKET_UTF8}/rêve/file
${AWS} s3api head-object --bucket ${BUCKET_UTF8} --key rêve/file
${AWS} s3 cp /etc/passwd s3://${BUCKET_UTF8}/intérêt
${AWS} s3api head-object --bucket ${BUCKET_UTF8} --key intérêt
${AWS} s3 cp /etc/passwd s3://${BUCKET_UTF8}/test/gâteau
${AWS} s3api head-object --bucket ${BUCKET_UTF8} --key test/gâteau
ALL_OBJECTS=$(${AWS} s3api list-objects --bucket ${BUCKET_UTF8})
echo -e "${ALL_OBJECTS}" | grep "rêve/file"
echo -e "${ALL_OBJECTS}" | grep "intérêt"
echo -e "${ALL_OBJECTS}" | grep "test/gâteau"
DIRECTORY_LIST=$(${AWS} s3 ls s3://${BUCKET_UTF8})
[ $(echo -e "${DIRECTORY_LIST}" | wc -l) -eq 3 ]
echo -e "${DIRECTORY_LIST}" | grep "r?ve/"
echo -e "${DIRECTORY_LIST}" | grep "test/"
echo -e "${DIRECTORY_LIST}" | grep "int?r?t"
DIRECTORY_LIST=$(${AWS} s3api list-objects --bucket ${BUCKET_UTF8} --delimiter /)
echo -e "${DIRECTORY_LIST}" | grep "rêve/"
echo -e "${DIRECTORY_LIST}" | grep "test/"
echo -e "${DIRECTORY_LIST}" | grep "intérêt"
DIRECTORY_LIST=$(${AWS} s3 ls s3://${BUCKET_UTF8}/rêve/)
[ $(echo -e "${DIRECTORY_LIST}" | wc -l) -eq 1 ]
echo -e "${DIRECTORY_LIST}" | grep "file"
DIRECTORY_LIST=$(${AWS} s3api list-objects --bucket ${BUCKET_UTF8} --prefix rêve/ --delimiter /)
echo -e "${DIRECTORY_LIST}" | grep "file"
DIRECTORY_LIST=$(${AWS} s3 ls s3://${BUCKET_UTF8}/test/)
[ $(echo -e "${DIRECTORY_LIST}" | wc -l) -eq 1 ]
echo -e "${DIRECTORY_LIST}" | grep "g?teau"
DIRECTORY_LIST=$(${AWS} s3api list-objects --bucket ${BUCKET_UTF8} --prefix test/ --delimiter /)
echo -e "${DIRECTORY_LIST}" | grep "gâteau"

# COPY S3<=>S3

BCK1=bucket-${RANDOM}
BCK2=bucket-${RANDOM}

${AWS} s3api create-bucket --bucket ${BCK1}
${AWS} s3api create-bucket --bucket ${BCK2}

# INIT
${AWS} s3 cp bigfile s3://${BCK1}/root

# COPY AT ROOT
${AWS} s3 cp s3://${BCK1}/root s3://${BCK2}/root

# COPY AT SUBDIR
${AWS} s3 cp s3://${BCK1}/root s3://${BCK2}/d1/d2/d3/bigfile

# COPY SAME BUCKET
${AWS} s3 cp s3://${BCK1}/root s3://${BCK1}/same_bucket/bigfile

# COPY WITH UTF-8 PATH
${AWS} s3 cp s3://${BCK1}/root s3://${BCK1}/répertoire/bigfile

${AWS} s3api list-objects --bucket ${BCK1}

echo "OK"

# FIXME should check container created
