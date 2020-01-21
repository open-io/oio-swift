#!/bin/bash

export OIO_NS="${1:-OPENIO}"
export OIO_ACCOUNT="${2:-AUTH_demo}"
MASK_EMPTY_PREFIXES=$(grep mask_empty_prefixes "$GW_CONF" | cut -d= -f2 | sed 's/ //g' )

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET="bucket-ch-vers-$RANDOM"

OBJ_0="/etc/magic"
OBJ_1="/etc/passwd"

set -x
set -e

echo "*** Creating bucket $BUCKET ***"
${AWS} s3 mb "s3://${BUCKET}"


echo "*** Creating object with PATH $BUCKET ***"
${AWS} s3 cp ${OBJ_0} s3://${BUCKET}/path/obj

echo "*** Check container ***"
MAX_VERSIONS=$(openio container show ${BUCKET}%2Fpath -f json | jq -r ".max_versions")
[ "$MAX_VERSIONS" == 'Namespace default' ]

echo "*** Enable versioning ***"
${AWS} s3api put-bucket-versioning --versioning-configuration Status=Enabled --bucket "${BUCKET}"

echo "Upload new version"
${AWS} s3 cp ${OBJ_1} s3://${BUCKET}/path/obj

echo "*** Check container ***"
MAX_VERSIONS=$(openio container show ${BUCKET}%2Fpath -f json | jq -r ".max_versions")
[ "$MAX_VERSIONS" == "-1" ]


echo "*** Suspend versioning ***"
${AWS} s3api put-bucket-versioning --versioning-configuration Status=Suspended --bucket "${BUCKET}"

${AWS} s3 cp ${OBJ_1} s3://${BUCKET}/path/obj

MAX_VERSIONS=$(openio container show ${BUCKET}%2Fpath -f json | jq -r ".max_versions")
[ "$MAX_VERSIONS" == "1" ]

echo "*** Enable versioning ***"
${AWS} s3api put-bucket-versioning --versioning-configuration Status=Enabled --bucket "${BUCKET}"

echo "*** Delete current version ***"
${AWS} s3 rm s3://${BUCKET}/path/obj

echo "*** Creating empty object ***"
${AWS} s3api put-object --bucket ${BUCKET} --key dir1/dir2/
DATA=$(${AWS} s3api list-object-versions --bucket ${BUCKET})
echo ${DATA} | grep dir1/dir2/
${AWS} s3 rm s3://${BUCKET}/dir1/dir2/

if [ "$MASK_EMPTY_PREFIXES" == "true" ]; then
    echo "*** Check redis key is not removed ***"
    RESULT="1"
    if grep -E "^redis_keys_format.*=.*v3" "$GW_CONF"; then
        # v3 format
        CMD="zrank CS:AUTH_demo:${BUCKET}:cnt path/"
	RESULT="0"
    elif grep -E "^redis_keys_format.*=.*v2" "$GW_CONF"; then
        # v2 format
        CMD="hget CS:AUTH_demo:${BUCKET}:cnt path/"
    else
        # old format
        CMD="get CS:AUTH_demo:${BUCKET}:cnt:path/"
    fi
    VAL=$(redis-cli $CMD)
    [ "$VAL" == "$RESULT" ]

    echo "*** Check number of objects ***"

    OBJS=$(${AWS} s3api list-object-versions --bucket ${BUCKET} | grep -c "Key")
    [ ${OBJS} -eq 3 ]

    echo "*** Suppress everything ***"

    DATA=$(${AWS} s3api list-object-versions --bucket ${BUCKET})

    VERS=$(echo ${DATA} | jq -r ".DeleteMarkers[0].VersionId")
    ${AWS} s3api delete-object --bucket ${BUCKET} --key path/obj --version-id $VERS
    VERS=$(echo ${DATA} | jq -r ".Versions[0].VersionId")
    ${AWS} s3api delete-object --bucket ${BUCKET} --key path/obj --version-id $VERS
    VERS=$(echo ${DATA} | jq -r ".Versions[1].VersionId")
    ${AWS} s3api delete-object --bucket ${BUCKET} --key path/obj --version-id $VERS

    echo "*** Check bucket is empty ***"

    DATA=$(${AWS} s3api list-object-versions --bucket ${BUCKET})
    [ -z "$DATA" ]
fi

${AWS} s3api delete-bucket --bucket ${BUCKET}

echo "Test Done"
