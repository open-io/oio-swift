#!/bin/bash

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET="bucket-$RANDOM"

OBJ_0="/etc/magic"
OBJ_1="/etc/passwd"
OBJ_2="/etc/fstab"

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


echo "*** Deleting the bucket ***"
${AWS} s3 rb "s3://${BUCKET}"
