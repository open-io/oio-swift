#!/bin/bash

export OIO_NS="${1:-OPENIO}"
export OIO_ACCOUNT="${2:-AUTH_demo}"

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET="bucket-$RANDOM"

OBJ_0="/etc/magic"
OBJ_1="/etc/passwd"
OBJ_2="/etc/fstab"
MULTI_FILE=$(mktemp -t multipart_XXXXXX.dat)

OBJ_0_EXPECTED_MD5=$(md5sum "$OBJ_0" | cut -d ' ' -f 1)
OBJ_1_EXPECTED_MD5=$(md5sum "$OBJ_1" | cut -d ' ' -f 1)
OBJ_2_EXPECTED_MD5=$(md5sum "$OBJ_2" | cut -d ' ' -f 1)

set -e
set -x

echo "*** Creating bucket $BUCKET ***"
${AWS} s3 mb "s3://${BUCKET}"

echo "Listing current version, and checking"
CUR_VERS=$(${AWS} s3api list-objects --bucket "${BUCKET}")
[[ -z "$CUR_VERS" ]]

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
[[ -z "$ALL_OBJ_VERS" ]]

echo "*** Putting an object before enabling versioning ***"
${AWS} s3 cp "${OBJ_0}" "s3://${BUCKET}/obj"

echo "Listing current version, and checking"
CUR_VERS=$(${AWS} s3api list-objects --bucket "${BUCKET}")
OBJ_0_KEY=$(jq -r ".Contents[0].Key|tostring" <<< "$CUR_VERS")
OBJ_0_MD5=$(jq -r ".Contents[0].ETag|tostring" <<< "$CUR_VERS")
[[ "$OBJ_0_KEY" == "obj" ]]
[[ "$OBJ_0_MD5" == "\"$OBJ_0_EXPECTED_MD5\"" ]]

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
NB_DELETE_MARKERS=$(jq -r ".DeleteMarkers|length" <<< "$ALL_OBJ_VERS")
NB_VERSIONS=$(jq -r ".Versions|length" <<< "$ALL_OBJ_VERS")
[[ "$NB_DELETE_MARKERS" -eq "0" ]]
[[ "$NB_VERSIONS" -eq "1" ]]
OBJ_0_KEY=$(jq -r ".Versions[0].Key|tostring" <<< "$ALL_OBJ_VERS")
OBJ_0_ID=$(jq -r ".Versions[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ_0_MD5=$(jq -r ".Versions[0].ETag|tostring" <<< "$ALL_OBJ_VERS")
OBJ_0_ISLATEST=$(jq -r ".Versions[0].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
[[ "$OBJ_0_KEY" == "obj" ]]
[[ "$OBJ_0_MD5" == "\"$OBJ_0_EXPECTED_MD5\"" ]]
[[ "$OBJ_0_ISLATEST" == "true" ]]
OBJ_0_EXPECTED_ID=$OBJ_0_ID

echo "Fetching current version, and checking"
${AWS} s3 cp "s3://${BUCKET}/obj" obj
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_0_EXPECTED_MD5" ]]

echo "Fetching objects versions, and checking all versions appear"
OBJ_0_META=$(${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_0_EXPECTED_ID" obj)
OBJ_0_MD5=$(jq -r ".ETag|tostring" <<< "$OBJ_0_META")
[[ "$OBJ_0_MD5" == "\"$OBJ_0_EXPECTED_MD5\"" ]]
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_0_EXPECTED_MD5" ]]

echo "*** Putting a second object before enabling versioning ***"
${AWS} s3 cp "${OBJ_1}" "s3://${BUCKET}/obj"

echo "Listing current version, and checking"
CUR_VERS=$(${AWS} s3api list-objects --bucket "${BUCKET}")
OBJ_1_KEY=$(jq -r ".Contents[0].Key|tostring" <<< "$CUR_VERS")
OBJ_1_MD5=$(jq -r ".Contents[0].ETag|tostring" <<< "$CUR_VERS")
[[ "$OBJ_1_KEY" == "obj" ]]
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
NB_DELETE_MARKERS=$(jq -r ".DeleteMarkers|length" <<< "$ALL_OBJ_VERS")
NB_VERSIONS=$(jq -r ".Versions|length" <<< "$ALL_OBJ_VERS")
[[ "$NB_DELETE_MARKERS" -eq "0" ]]
[[ "$NB_VERSIONS" -eq "1" ]]
OBJ_1_KEY=$(jq -r ".Versions[0].Key|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ID=$(jq -r ".Versions[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ_1_MD5=$(jq -r ".Versions[0].ETag|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ISLATEST=$(jq -r ".Versions[0].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
[[ "$OBJ_1_KEY" == "obj" ]]
[[ "$OBJ_0_ID" -lt "$OBJ_1_ID" ]]
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ "$OBJ_1_ISLATEST" == "true" ]]
OBJ_1_EXPECTED_ID=$OBJ_1_ID

echo "Fetching current version, and checking"
${AWS} s3 cp "s3://${BUCKET}/obj" obj
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_1_EXPECTED_MD5" ]]

echo "Fetching objects versions, and checking all versions appear"
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_0_EXPECTED_ID" obj; then
    false
fi
OBJ_1_META=$(${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_1_EXPECTED_ID" obj)
OBJ_1_MD5=$(jq -r ".ETag|tostring" <<< "$OBJ_1_META")
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_1_EXPECTED_MD5" ]]

echo "*** Enabling versioning ****"
${AWS} s3api put-bucket-versioning --versioning-configuration Status=Enabled --bucket "${BUCKET}"

echo "*** Putting another object over the first one ***"
PUT_RES=$(${AWS} s3api put-object --bucket ${BUCKET} --key obj --body "${OBJ_2}")
# PUT_ID=$(jq -r ".VersionId|tonumber" <<< "$PUT_RES") FIXME(adu) Wait to use object_create_ext

echo "Listing current version, and checking"
CUR_VERS=$(${AWS} s3api list-objects --bucket "${BUCKET}")
OBJ_2_KEY=$(jq -r ".Contents[0].Key|tostring" <<< "$CUR_VERS")
OBJ_2_MD5=$(jq -r ".Contents[0].ETag|tostring" <<< "$CUR_VERS")
[[ "$OBJ_2_KEY" == "obj" ]]
[[ "$OBJ_2_MD5" == "\"$OBJ_2_EXPECTED_MD5\"" ]]

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
NB_DELETE_MARKERS=$(jq -r ".DeleteMarkers|length" <<< "$ALL_OBJ_VERS")
NB_VERSIONS=$(jq -r ".Versions|length" <<< "$ALL_OBJ_VERS")
[[ "$NB_DELETE_MARKERS" -eq "0" ]]
[[ "$NB_VERSIONS" -eq "2" ]]
OBJ_1_KEY=$(jq -r ".Versions[1].Key|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ID=$(jq -r ".Versions[1].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ_1_MD5=$(jq -r ".Versions[1].ETag|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ISLATEST=$(jq -r ".Versions[1].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
OBJ_2_KEY=$(jq -r ".Versions[0].Key|tostring" <<< "$ALL_OBJ_VERS")
OBJ_2_ID=$(jq -r ".Versions[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ_2_MD5=$(jq -r ".Versions[0].ETag|tostring" <<< "$ALL_OBJ_VERS")
OBJ_2_ISLATEST=$(jq -r ".Versions[0].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
[[ "$OBJ_1_KEY" == "obj" ]]
[[ "$OBJ_2_KEY" == "obj" ]]
[[ "$OBJ_1_EXPECTED_ID" -eq "$OBJ_1_ID" ]]
[[ "$OBJ_1_ID" -lt "$OBJ_2_ID" ]]
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ "$OBJ_2_MD5" == "\"$OBJ_2_EXPECTED_MD5\"" ]]
[[ "$OBJ_1_ISLATEST" == "false" ]]
[[ "$OBJ_2_ISLATEST" == "true" ]]
# [[ "$OBJ_2_ID" == "$PUT_ID" ]] FIXME(adu) Wait to use object_create_ext
OBJ_2_EXPECTED_ID=$OBJ_2_ID

echo "Fetching current version, and checking"
${AWS} s3 cp "s3://${BUCKET}/obj" obj
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_2_EXPECTED_MD5" ]]

echo "Fetching objects versions, and checking all versions appear"
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_0_EXPECTED_ID" obj; then
    false
fi
OBJ_1_META=$(${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_1_EXPECTED_ID" obj)
OBJ_1_MD5=$(jq -r ".ETag|tostring" <<< "$OBJ_1_META")
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_1_EXPECTED_MD5" ]]
OBJ_2_META=$(${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_2_EXPECTED_ID" obj)
OBJ_2_MD5=$(jq -r ".ETag|tostring" <<< "$OBJ_2_META")
[[ "$OBJ_2_MD5" == "\"$OBJ_2_EXPECTED_MD5\"" ]]
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_2_EXPECTED_MD5" ]]

echo "*** Putting a delete marker ***"
${AWS} s3 rm "s3://${BUCKET}/obj"

echo "Listing current version, and checking"
CUR_VERS=$(${AWS} s3api list-objects --bucket "${BUCKET}")
[[ -z "$CUR_VERS" ]]

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
NB_DELETE_MARKERS=$(jq -r ".DeleteMarkers|length" <<< "$ALL_OBJ_VERS")
NB_VERSIONS=$(jq -r ".Versions|length" <<< "$ALL_OBJ_VERS")
[[ "$NB_DELETE_MARKERS" -eq "1" ]]
[[ "$NB_VERSIONS" -eq "2" ]]
OBJ_1_KEY=$(jq -r ".Versions[1].Key|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ID=$(jq -r ".Versions[1].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ_1_MD5=$(jq -r ".Versions[1].ETag|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ISLATEST=$(jq -r ".Versions[1].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
OBJ_2_KEY=$(jq -r ".Versions[0].Key|tostring" <<< "$ALL_OBJ_VERS")
OBJ_2_ID=$(jq -r ".Versions[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ_2_MD5=$(jq -r ".Versions[0].ETag|tostring" <<< "$ALL_OBJ_VERS")
OBJ_2_ISLATEST=$(jq -r ".Versions[0].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
DELETE_MARKER_KEY=$(jq -r ".DeleteMarkers[0].Key|tostring" <<< "$ALL_OBJ_VERS")
DELETE_MARKER_ID=$(jq -r ".DeleteMarkers[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
DELETE_MARKER_ISLATEST=$(jq -r ".DeleteMarkers[0].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
[[ "$OBJ_1_KEY" == "obj" ]]
[[ "$OBJ_2_KEY" == "obj" ]]
[[ "$DELETE_MARKER_KEY" == "obj" ]]
[[ "$OBJ_1_EXPECTED_ID" -eq "$OBJ_1_ID" ]]
[[ "$OBJ_2_EXPECTED_ID" -eq "$OBJ_2_ID" ]]
[[ "$OBJ_2_ID" -lt "$DELETE_MARKER_ID" ]]
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ "$OBJ_2_MD5" == "\"$OBJ_2_EXPECTED_MD5\"" ]]
[[ "$OBJ_1_ISLATEST" == "false" ]]
[[ "$OBJ_2_ISLATEST" == "false" ]]
[[ "$DELETE_MARKER_ISLATEST" == "false" ]] # FIXME(adu) Should be true
DELETE_MARKER_EXPECTED_ID=$DELETE_MARKER_ID

echo "Fetching current version, and checking"
if ${AWS} s3 cp "s3://${BUCKET}/obj" obj; then
    false
fi

echo "Fetching objects versions, and checking all versions appear"
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_0_EXPECTED_ID" obj; then
    false
fi
OBJ_1_META=$(${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_1_EXPECTED_ID" obj)
OBJ_1_MD5=$(jq -r ".ETag|tostring" <<< "$OBJ_1_META")
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_1_EXPECTED_MD5" ]]
OBJ_2_META=$(${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_2_EXPECTED_ID" obj)
OBJ_2_MD5=$(jq -r ".ETag|tostring" <<< "$OBJ_2_META")
[[ "$OBJ_2_MD5" == "\"$OBJ_2_EXPECTED_MD5\"" ]]
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_2_EXPECTED_MD5" ]]

echo "*** Deleting the most recent version (not the delete marker) ***"
${AWS} s3api delete-object --bucket "${BUCKET}" --key "obj" --version-id "${OBJ_2_ID}"

echo "Listing current version, and checking"
CUR_VERS=$(${AWS} s3api list-objects --bucket "${BUCKET}")
[[ -z "$CUR_VERS" ]]

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
NB_DELETE_MARKERS=$(jq -r ".DeleteMarkers|length" <<< "$ALL_OBJ_VERS")
NB_VERSIONS=$(jq -r ".Versions|length" <<< "$ALL_OBJ_VERS")
[[ "$NB_DELETE_MARKERS" -eq "1" ]]
[[ "$NB_VERSIONS" -eq "1" ]]
OBJ_1_KEY=$(jq -r ".Versions[0].Key|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ID=$(jq -r ".Versions[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ_1_MD5=$(jq -r ".Versions[0].ETag|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ISLATEST=$(jq -r ".Versions[0].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
DELETE_MARKER_KEY=$(jq -r ".DeleteMarkers[0].Key|tostring" <<< "$ALL_OBJ_VERS")
DELETE_MARKER_ID=$(jq -r ".DeleteMarkers[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
DELETE_MARKER_ISLATEST=$(jq -r ".DeleteMarkers[0].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
[[ "$OBJ_1_KEY" == "obj" ]]
[[ "$DELETE_MARKER_KEY" == "obj" ]]
[[ "$OBJ_1_EXPECTED_ID" -eq "$OBJ_1_ID" ]]
[[ "$DELETE_MARKER_EXPECTED_ID" -eq "$DELETE_MARKER_ID" ]]
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ "$OBJ_1_ISLATEST" == "false" ]]
[[ "$DELETE_MARKER_ISLATEST" == "false" ]] # FIXME(adu) Should be true

echo "Fetching current version, and checking"
if ${AWS} s3 cp "s3://${BUCKET}/obj" obj; then
    false
fi

echo "Fetching objects versions, and checking all versions appear"
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_0_EXPECTED_ID" obj; then
    false
fi
OBJ_1_META=$(${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_1_EXPECTED_ID" obj)
OBJ_1_MD5=$(jq -r ".ETag|tostring" <<< "$OBJ_1_META")
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_1_EXPECTED_MD5" ]]
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_2_EXPECTED_ID" obj; then
    false
fi

echo "*** Deleting the delete marker ***"
${AWS} s3api delete-object --bucket "${BUCKET}" --key "obj" --version-id "${DELETE_MARKER_ID}"

echo "Listing current version, and checking"
CUR_VERS=$(${AWS} s3api list-objects --bucket "${BUCKET}")
OBJ_1_KEY=$(jq -r ".Contents[0].Key|tostring" <<< "$CUR_VERS")
OBJ_1_MD5=$(jq -r ".Contents[0].ETag|tostring" <<< "$CUR_VERS")
[[ "$OBJ_1_KEY" == "obj" ]]
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
NB_DELETE_MARKERS=$(jq -r ".DeleteMarkers|length" <<< "$ALL_OBJ_VERS")
NB_VERSIONS=$(jq -r ".Versions|length" <<< "$ALL_OBJ_VERS")
[[ "$NB_DELETE_MARKERS" -eq "0" ]]
[[ "$NB_VERSIONS" -eq "1" ]]
OBJ_1_KEY=$(jq -r ".Versions[0].Key|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ID=$(jq -r ".Versions[0].VersionId|tonumber" <<< "$ALL_OBJ_VERS")
OBJ_1_MD5=$(jq -r ".Versions[0].ETag|tostring" <<< "$ALL_OBJ_VERS")
OBJ_1_ISLATEST=$(jq -r ".Versions[0].IsLatest|tostring" <<< "$ALL_OBJ_VERS")
[[ "$OBJ_1_KEY" == "obj" ]]
[[ "$OBJ_1_EXPECTED_ID" -eq "$OBJ_1_ID" ]]
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ "$OBJ_1_ISLATEST" == "true" ]]

echo "Fetching current version, and checking"
${AWS} s3 cp "s3://${BUCKET}/obj" obj
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_1_EXPECTED_MD5" ]]

echo "Fetching objects versions, and checking all versions appear"
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_0_EXPECTED_ID" obj; then
    false
fi
OBJ_1_META=$(${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_1_EXPECTED_ID" obj)
OBJ_1_MD5=$(jq -r ".ETag|tostring" <<< "$OBJ_1_META")
[[ "$OBJ_1_MD5" == "\"$OBJ_1_EXPECTED_MD5\"" ]]
[[ $(md5sum obj | cut -d ' ' -f 1) == "$OBJ_1_EXPECTED_MD5" ]]
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_2_EXPECTED_ID" obj; then
    false
fi

echo "*** Deleting the last remaining version ***"
${AWS} s3api delete-object --bucket "${BUCKET}" --key "obj" --version-id "${OBJ_1_ID}"

echo "Listing current version, and checking"
CUR_VERS=$(${AWS} s3api list-objects --bucket "${BUCKET}")
[[ -z "$CUR_VERS" ]]

echo "Listing objects versions, and checking all versions appear"
ALL_OBJ_VERS=$(${AWS} s3api list-object-versions --bucket "${BUCKET}")
[[ -z "$ALL_OBJ_VERS" ]]

echo "Fetching current version, and checking"
if ${AWS} s3 cp "s3://${BUCKET}/obj" obj; then
    false
fi

echo "Fetching objects versions, and checking all versions appear"
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_0_EXPECTED_ID" obj; then
    false
fi
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_1_EXPECTED_ID" obj; then
    false
fi
if ${AWS} s3api get-object --bucket "${BUCKET}" --key obj --version-id "$OBJ_2_EXPECTED_ID" obj; then
    false
fi


echo "*** Check objname and versions with path ***"

echo "Prepare bucket"
PUT_RES=$(${AWS} s3api put-object --bucket ${BUCKET} --key v1/v2/v3/obj --body "${OBJ_0}")
# PUT_ID1=$(jq -r ".VersionId|tonumber" <<< "$PUT_RES") FIXME(adu) Wait to use object_create_ext

PUT_RES=$(${AWS} s3api put-object --bucket ${BUCKET} --key v1/v2/v3/obj --body "${OBJ_1}")
# PUT_ID2=$(jq -r ".VersionId|tonumber" <<< "$PUT_RES") FIXME(adu) Wait to use object_create_ext

CUR_VERS=$(${AWS} s3api list-object-versions --bucket ${BUCKET})

OBJ_0_KEY=$(jq -r ".Versions[0].Key|tostring" <<< "$CUR_VERS")
OBJ_0_ID=$(jq -r ".Versions[0].VersionId|tostring" <<< "$CUR_VERS")
OBJ_1_KEY=$(jq -r ".Versions[0].Key|tostring" <<< "$CUR_VERS")
OBJ_1_ID=$(jq -r ".Versions[1].VersionId|tostring" <<< "$CUR_VERS")

[[ "$OBJ_0_KEY" == "v1/v2/v3/obj" ]]
[[ "$OBJ_1_KEY" == "v1/v2/v3/obj" ]]
# [[ "$PUT_ID1" == "$OBJ_1_ID" ]] FIXME(adu) Wait to use object_create_ext
# [[ "$PUT_ID2" == "$OBJ_0_ID" ]] FIXME(adu) Wait to use object_create_ext

# OS-247
${AWS} s3api delete-object --bucket ${BUCKET} --key v1/v2/v3/obj --version-id "${OBJ_1_ID}"
${AWS} s3api delete-object --bucket ${BUCKET} --key v1/v2/v3/obj --version-id "${OBJ_0_ID}"


echo "######################################"
echo "### Deletion of large object parts ###"
echo "######################################"

echo "Uploading a large object"
dd if=/dev/zero of="${MULTI_FILE}" count=21 bs=1M
${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/obj"

echo "Counting segments with openio CLI"
SEGS=$(openio object list ${BUCKET}+segments -f value)
[ -n "$SEGS" ]
SEG_COUNT=$(echo -n "${SEGS}" | wc -l)

OBJ_VER=$(${AWS} s3api head-object --bucket ${BUCKET} --key obj | jq -r ".VersionId")

echo "Deleting the object (should create a delete marker)"
${AWS} s3 rm "s3://$BUCKET/obj"

echo "Counting segments with openio CLI (should be the same, the object is still there)"
SEGS2=$(openio object list ${BUCKET}+segments -f value)
[ -n "$SEGS2" ]
SEG_COUNT2=$(echo -n "${SEGS2}" | wc -l)
[ "$SEG_COUNT" -eq "$SEG_COUNT2" ]
[ "$SEGS" == "$SEGS2" ]

echo "Explicitly deleting the old version of the object"
${AWS} s3api delete-object --bucket ${BUCKET} --key obj --version-id "$OBJ_VER"

echo "Counting segments with openio CLI (should be zero, manifest has been deleted)"
SEGS4=$(openio object list ${BUCKET}+segments -f value)
[ -z "$SEGS4" ]
SEG_COUNT4=$(echo -n "${SEGS4}" | wc -l)
[ "$SEG_COUNT4" -eq "0" ]

echo "Deleting the delete marker (without specifying any version)"
${AWS} s3 rm "s3://$BUCKET/obj"

echo "######################################"
echo "### Prefixes with versioning       ###"
echo "######################################"


${AWS} s3 cp /etc/magic s3://${BUCKET}/prefix/magic
${AWS} s3 rm s3://${BUCKET}/prefix/magic

${AWS} s3api list-objects --bucket ${BUCKET} --delimiter /

${AWS} s3api list-objects --bucket ${BUCKET} --delimiter / | grep "prefix" && {
    echo "Found prefix, should be hidden"
    exit 1
}
${AWS} s3api list-object-versions --bucket ${BUCKET}  --delimiter / | grep "prefix" || {
    echo "Missing prefix, should be visible"
    exit 1
}


echo "######################################"
echo "### Metadata modification          ###"
echo "######################################"

echo "Uploading a large object"
${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/mdobj"

echo "Setting tags"
${AWS} s3api put-object-tagging --bucket "$BUCKET" --key "mdobj" --tagging 'TagSet=[{Key=organization,Value=marketing}]'

echo "Checking the object did not lose its SLO metadata"
OBJ_META=$(openio object show ${BUCKET} mdobj -f yaml | grep meta)
[ "$(echo "$OBJ_META" | grep -c 'x-static-large-object')" -eq 1 ]
[ "$(echo "$OBJ_META" | grep -c 'x-object-sysmeta-slo')" -eq 2 ]
[ "$(echo "$OBJ_META" | grep -c 'x-object-sysmeta-swift3-acl')" -eq 1 ]
[ "$(echo "$OBJ_META" | grep -c 'x-object-sysmeta-swift3-tagging')" -eq 1 ]

OBJ_VER=$(${AWS} s3api head-object --bucket ${BUCKET} --key mdobj | jq -r ".VersionId")

echo  "Deleting the object"
${AWS} s3api delete-object --bucket $BUCKET --key mdobj --version-id "$OBJ_VER"


echo "Upload object version 1 and add tagging key=old"
V1=$(${AWS} s3api put-object --bucket ${BUCKET} --key obj --body ${OBJ_0} | jq -r '.VersionId')
if [ "$V1" == "null" ]; then
    V1=$(${AWS} s3api head-object --bucket ${BUCKET} --key obj | jq -r '.VersionId')
fi
${AWS} s3api put-object-tagging --bucket ${BUCKET} --key obj --version-id $V1 --tagging 'TagSet=[{Key=val,Value=old}]'

echo "Upload object version 2 and add tagging key=new"
V2=$(${AWS} s3api put-object --bucket ${BUCKET} --key obj --body ${OBJ_1} | jq -r '.VersionId')
if [ "$V2" == "null" ]; then
    V2=$(${AWS} s3api head-object --bucket ${BUCKET} --key obj | jq -r '.VersionId')
fi
${AWS} s3api put-object-tagging --bucket ${BUCKET} --key obj --version-id $V2 --tagging 'TagSet=[{Key=val,Value=new}]'

echo "Check tagging on object version 1"
DATA=$(${AWS} s3api get-object-tagging --bucket ${BUCKET} --key obj --version-id $V1)
VERSION=$(echo $DATA | jq -r '.VersionId')
TAGVAL=$(echo $DATA | jq -r '.TagSet[0].Value')
[ "$V1" -eq "$VERSION" ]
[ "$TAGVAL" == "old" ]

echo "Check tagging on object version 2"
DATA=$(${AWS} s3api get-object-tagging --bucket ${BUCKET} --key obj --version-id $V2)
VERSION=$(echo $DATA | jq -r '.VersionId')
TAGVAL=$(echo $DATA | jq -r '.TagSet[0].Value')
[ "$V2" -eq "$VERSION" ]
[ "$TAGVAL" == "new" ]

echo  "Deleting the object"
${AWS} s3api delete-object --bucket $BUCKET --key obj --version-id "$V1"
${AWS} s3api delete-object --bucket $BUCKET --key obj --version-id "$V2"

echo "*** Deleting the bucket ***"
${AWS} s3 rb "s3://${BUCKET}"

rm "$MULTI_FILE"
