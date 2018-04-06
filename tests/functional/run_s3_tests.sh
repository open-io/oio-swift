#!/bin/bash

CURDIR="$( cd "$(dirname "$0")" ; pwd -P )"

# CREATE AWS CONFIGURATION
mkdir -p $HOME/.aws
cat <<EOF >$HOME/.aws/credentials
[default]
aws_access_key_id=demo:demo
aws_secret_access_key=DEMO_PASS
EOF

cat <<EOF >$HOME/.aws/config
[default]
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB
EOF

coverage run -a runserver.py ${CURDIR}/simple.cfg -v &
sleep 1
PID=$(jobs -p)

for i in $CURDIR/s3_*.sh; do
    bash $i
    if [ $? -ne 0 ]; then
        echo "Exiting with error"
        break
    fi
done

for pid in $PID; do
    kill $pid
    wait $pid
done


