#!/bin/bash

# This script expects a namespace with unlimited versioning,
# and a swift gateway with hashedcontainer middleware.

export OIO_NS="${1:-OPENIO}"
export OIO_ACCOUNT="${2:-test_account}"

ETAG_REGEX='s/(Etag: )([[:alnum:]]*)(.*)/\2/p'
CONTENT_TYPE_REGEX='s/(Content-Type: )([[:print:]]*)(.*)/\2/p'
HTTP_STATUS_REGEX='s/(HTTP\/1.1 )([[:digit:]]*)(.*)/\2/p'

GW_NETLOC="http://127.0.0.1:5000/"
OBJ_SEED=$(mktemp -tu test-vers-XXXXXX)
OBJ_1_SRC="${OBJ_SEED}-1.dat"
OBJ_2_SRC="${OBJ_SEED}-2.dat"
OBJ_3_SRC="${OBJ_SEED}-3.dat"

set -e

echo "Preparing fixtures $OBJ_1_SRC $OBJ_2_SRC $OBJ_3_SRC"
cp "/etc/resolv.conf" "$OBJ_1_SRC"
cp "/etc/fstab" "$OBJ_2_SRC"
dd if=/dev/zero of="$OBJ_3_SRC" bs=1k count=2042

echo "Uploading one object"
curl -XPUT "${GW_NETLOC}${OBJ_1_SRC}" --data-binary "@${OBJ_1_SRC}"

echo "Finding it with openio CLI, checking MD5"
openio object show --auto "${OBJ_1_SRC}"
OBJ_1_CONTAINER=$(openio object show --auto "${OBJ_1_SRC}" -f value -c container)
OBJ_1_HASH=$(openio object show --auto "${OBJ_1_SRC}" -f value -c hash)
echo "$OBJ_1_HASH $OBJ_1_SRC" | md5sum -c

echo "Doing HEAD request, checking MD5"
OBJ_1_HASH=$(curl -s -I "${GW_NETLOC}${OBJ_1_SRC}" | sed -n -E -e "${ETAG_REGEX}")
echo "$OBJ_1_HASH $OBJ_1_SRC" | md5sum -c

echo "Overwriting it twice"
curl -XPUT "${GW_NETLOC}${OBJ_1_SRC}" --data-binary "@${OBJ_2_SRC}"
curl -XPUT "${GW_NETLOC}${OBJ_1_SRC}" --data-binary "@${OBJ_3_SRC}"

echo "Finding it with openio CLI, checking MD5"
openio object show --auto "${OBJ_1_SRC}"
OBJ_3_HASH=$(openio object show --auto "${OBJ_1_SRC}" -f value -c hash)
echo "$OBJ_3_HASH $OBJ_3_SRC" | md5sum -c

echo "Doing HEAD request, checking MD5"
OBJ_3_HASH=$(curl -s -I "${GW_NETLOC}${OBJ_1_SRC}" | sed -n -E -e "${ETAG_REGEX}")
echo "$OBJ_3_HASH $OBJ_3_SRC" | md5sum -c

echo "Checking number of versions"
OBJ_VERSIONS=$(openio object list --auto --versions --prefix "${OBJ_1_SRC}" -f value | wc -l)
[ "$OBJ_VERSIONS" -eq 3 ]

echo "Doing DELETE request"
curl -XDELETE "${GW_NETLOC}${OBJ_1_SRC}"

echo "Doing HEAD request, checking Content-Type"
OBJ_4_CT=$(curl -s -I "${GW_NETLOC}${OBJ_1_SRC}" | sed -n -E -e "${CONTENT_TYPE_REGEX}")
echo "$OBJ_4_CT" | grep -q "application/x-deleted"

echo "Doing DELETE request again"
curl -XDELETE "${GW_NETLOC}${OBJ_1_SRC}"

echo "Doing HEAD request, checking Content-Type"
OBJ_3_CT=$(curl -s -I "${GW_NETLOC}${OBJ_1_SRC}" | sed -n -E -e "${CONTENT_TYPE_REGEX}")
echo "$OBJ_3_CT" | grep -qv "application/x-deleted"

echo "Purging container $OBJ_1_CONTAINER, keeping 3 versions (should be noop)"
openio container purge "$OBJ_1_CONTAINER" --max-versions 3

echo "Checking number of versions"
OBJ_VERSIONS=$(openio object list --auto --versions --prefix "${OBJ_1_SRC}" -f value | wc -l)
[ "$OBJ_VERSIONS" -eq 3 ] && echo "OK"

echo "Purging container $OBJ_1_CONTAINER, keeping 2 versions"
openio container purge "$OBJ_1_CONTAINER" --max-versions 2

echo "Checking number of versions"
OBJ_VERSIONS=$(openio object list --auto --versions --prefix "${OBJ_1_SRC}" -f value | wc -l)
[ "$OBJ_VERSIONS" -eq 2 ] && echo "OK"

echo "Purging container $OBJ_1_CONTAINER, keeping 1 version"
openio container purge "$OBJ_1_CONTAINER" --max-versions 1

echo "Checking number of versions"
OBJ_VERSIONS=$(openio object list --auto --versions --prefix "${OBJ_1_SRC}" -f value | wc -l)
[ "$OBJ_VERSIONS" -eq 1 ] && echo "OK"

echo "Deleting last object version (explicitly, with openio CLI)"
OBJ_3_VERS=$(openio object show --auto "${OBJ_1_SRC}" -f value -c version)
openio object delete --auto --object-version "$OBJ_3_VERS" "${OBJ_1_SRC}"

echo "Doing HEAD request (expect 404)"
OBJ_STATUS=$(curl -s -I "${GW_NETLOC}${OBJ_1_SRC}" | sed -n -E -e "${HTTP_STATUS_REGEX}")
[ "$OBJ_STATUS" -eq "404" ] && echo "OK"

echo "Removing fixtures"
rm -f "$OBJ_1_SRC" "$OBJ_2_SRC" "$OBJ_3_SRC"
