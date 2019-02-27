#!/bin/bash

set -x
set -e
ACCOUNT="AUTH_demo"
BUCKET=bucket-$RANDOM
REDIS_CLI="redis-cli"

${REDIS_CLI} set "CS:${ACCOUNT}:${BUCKET}:cnt:v1/" 1
${REDIS_CLI} set "CS:${ACCOUNT}:${BUCKET}+segments:cnt:/" 1
${REDIS_CLI} set "CS:${ACCOUNT}:${BUCKET}:cnt:d1/d2/d3/d4/" 1
${REDIS_CLI} set "CS:${ACCOUNT}:${BUCKET}+segments:cnt:subdir/" 1
${REDIS_CLI} set "CS:${ACCOUNT}:${BUCKET}:cnt:directory 1/directory 2/" 1
${REDIS_CLI} set "CS:${ACCOUNT}:${BUCKET}:cnt:subdir/" 1
${REDIS_CLI} set "CS:${ACCOUNT}:${BUCKET}:cnt:dir1/dir2/" 1
${REDIS_CLI} set "CS:${ACCOUNT}:${BUCKET}:obj:key1/key2/dot:/1551344395/" 1

${REDIS_CLI} --eval tools/conversion_hierarchy_v2.lua run

${REDIS_CLI} type "CS:${ACCOUNT}:${BUCKET}:cnt" | grep hash
${REDIS_CLI} type "CS:${ACCOUNT}:${BUCKET}+segments:cnt" | grep hash
${REDIS_CLI} type "CS:${ACCOUNT}:${BUCKET}:obj" | grep hash

OUT=$( ${REDIS_CLI} hgetall "CS:${ACCOUNT}:${BUCKET}:cnt" )
echo ${OUT} | grep "/"
echo ${OUT} | grep "v1/"
echo ${OUT} | grep "d1/d2/d3/d4/"
echo ${OUT} | grep "directory 1/directory 2/"
echo ${OUT} | grep "subdir/"
echo ${OUT} | grep "dir1/dir2/"

OUT=$( ${REDIS_CLI} hgetall "CS:${ACCOUNT}:${BUCKET}:obj" )
echo ${OUT} | grep "key1/key2/dot:/1551344395/"

OUT=$( ${REDIS_CLI} hgetall "CS:${ACCOUNT}:${BUCKET}+segments:cnt" )
echo ${OUT} | grep "/"
echo ${OUT} | grep "subdir/"
