#!/bin/bash

AWS="aws --endpoint-url http://localhost:5000"
BUCKET="bucket-${RANDOM}"

set -e
set -x

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


# test marker with prefix on object

for i in $(seq 1 21); do
    ${AWS} s3 cp /etc/magic s3://${BUCKET}/subdir/object-$i
done

echo "Recursive listing with default page-size"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10 and prefix with trailing /"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 --prefix subdir/ | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10 and prefix without /"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 --prefix subdir | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10, prefix with trailing / and delimiter /"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 --prefix subdir/ --delimiter / | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10, prefix without trailing / and delimiter /"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 --prefix subdir --delimiter / | grep -c '"Prefix"')
[ $objs -eq 1 ] || exit 1

# cleanup
for i in $(seq 1 21); do
    ${AWS} s3 rm s3://${BUCKET}/subdir/object-$i
done

# test marker with prefix on subdir

for i in $(seq 1 21); do
    ${AWS} s3 cp /etc/magic s3://${BUCKET}/subdir/subdir-$i/object-$i
done

echo "Recursive listing with default page-size"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10 and prefix with trailing /"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 --prefix subdir/ | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10 and prefix without trailing /"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 --prefix subdir | grep -c Key)
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10, prefix with trailing / and delimiter /"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 --prefix subdir/ --delimiter / | grep -c '"Prefix"')
[ $objs -eq 21 ] || exit 1

echo "Recursive listing with page-size 10, prefix without trailing / and delimiter /"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 --prefix subdir --delimiter / | grep -c '"Prefix"')
[ $objs -eq 1 ] || exit 1

# cleanup
for i in $(seq 1 21); do
    ${AWS} s3 rm s3://${BUCKET}/subdir/subdir-$i/object-$i
done

# test marker mixing subdir and object

for i in $(seq 1 21); do
    ${AWS} s3 cp /etc/magic s3://${BUCKET}/folder-$i/object-$i
done

for i in $(seq 1 21); do
    ${AWS} s3 cp /etc/magic s3://${BUCKET}/object-$i
done

for i in $(seq 1 21); do
    ${AWS} s3 cp /etc/magic s3://${BUCKET}/subdir-$i/object-$i
done

echo "Recursive listin with default page-size"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} | grep -c Key)
[ $objs -eq 63 ] || exit 1

echo "Recursive listing with page-size 10"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --page-size 10 | grep -c Key)
[ $objs -eq 63 ] || exit 1

echo "Non recursive listing with default page-size"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --delimiter '/' | grep -c '"Key"\|"Prefix"')
[ $objs -eq 63 ] || exit 1

echo "Non recursive listing with page-size 10"
objs=$(${AWS} s3api list-objects --bucket ${BUCKET} --delimiter '/' --page-size 10 | grep -c '"Key"\|"Prefix"')
[ $objs -eq 63 ] || exit 1

# cleanup
for i in $(seq 1 21); do
    ${AWS} s3 rm s3://${BUCKET}/folder-$i/object-$i
done

for i in $(seq 1 21); do
    ${AWS} s3 rm s3://${BUCKET}/object-$i
done

for i in $(seq 1 21); do
    ${AWS} s3 rm s3://${BUCKET}/subdir-$i/object-$i
done

${AWS} s3 rb s3://${BUCKET}
