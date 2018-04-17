#!/bin/bash

source tests/functional/common.sh

function run_sds() {
  export G_DEBUG_LEVEL=D PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  oio-reset.sh -v -v -N "$OIO_NS" \
    -f third_party/oio-sds/etc/bootstrap-preset-SINGLE.yml
}

function configure_aws() {
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
}

function configure_oioswift() {
    sed -i "s/USER/$(id -un)/g" "$1"
}


export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps
compile_sds
run_sds
configure_aws
configure_oioswift conf/s3_container_hierarchy.cfg

coverage run -p runserver.py conf/s3_container_hierarchy.cfg -v &
sleep 1
PID=$(jobs -p)

bash tests/functional/s3_container_hierarchy_v2.sh

for pid in $PID; do
    kill $pid
    wait $pid
done

# TODO(FVE): gridinit_cmd stop
