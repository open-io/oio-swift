#!/bin/bash
set -e

OIO_ACCOUNT="AUTH_demo"
BUCKET_1=aaa${RANDOM}
SUBPATH=${RANDOM}
BUCKET_2=zzz${RANDOM}
AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"
REDIS_CLI="redis-cli"

${AWS} s3api create-bucket --bucket ${BUCKET_1}
${AWS} s3api create-bucket --bucket ${BUCKET_2}

# Listing limit is 1000, no need to simulate a lot more containers.
for i in ${BUCKET_1} ${BUCKET_1}%2F${SUBPATH}%2F{1..2000} ${BUCKET_2};
do
    echo ZADD containers:${OIO_ACCOUNT} 0 ${i};
    echo HSET container:${OIO_ACCOUNT}:${i} bytes 0;
    echo HSET container:${OIO_ACCOUNT}:${i} objects 0;
    echo HSET container:${OIO_ACCOUNT}:${i} dtime 0;
    echo HSET container:${OIO_ACCOUNT}:${i} name ${i};
    echo HSET container:${OIO_ACCOUNT}:${i} mtime 1551779213.78188;
done | ${REDIS_CLI} >/dev/null

set -x

OUT=$( ${AWS} s3 ls )
echo ${OUT} | grep ${BUCKET_1}
echo ${OUT} | grep ${BUCKET_2}
