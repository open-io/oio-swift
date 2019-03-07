#!/bin/bash

AWS="aws --endpoint-url http://localhost:5000"
BUCKET="bucket-${RANDOM}"

set -e

count() {
    local args=
    if [ "$1" != "" ]; then
        args="$args --start-after $1"
    fi
    count=$(${AWS} s3api list-objects-v2 --bucket ${BUCKET} $args | grep -c Key)
    echo $count
}

${AWS} s3 mb s3://$BUCKET

# create few items
${AWS} s3 cp /etc/magic s3://${BUCKET}/bb
${AWS} s3 cp /etc/magic s3://${BUCKET}/dd/dd
${AWS} s3 cp /etc/magic s3://${BUCKET}/ff

echo "Global listing"
[ $(count) -eq 3 ] || exit 1

echo "before first item"
[ $(count aa) -eq 3 ] || exit 1

echo "after first item"
[ $(count bb) -eq 2 ] || exit 1

echo "between first and second item"
[ $(count cc) -eq 2 ] || exit 1

echo "after second item"
[ $(count dd/dd) -eq 1 ] || exit 1

echo "between second and third item"
[ $(count ee) -eq 1 ] || exit 1

echo "after third item"
[ $(count zz) -eq 0 ] || exit 1

# cleanup
${AWS} s3 rm s3://${BUCKET}/bb
${AWS} s3 rm s3://${BUCKET}/dd/dd
${AWS} s3 rm s3://${BUCKET}/ff

${AWS} s3 rb s3://${BUCKET}
