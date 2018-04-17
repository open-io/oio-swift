#!/bin/bash

source tests/functional/common.sh

function run_sds() {
  export G_DEBUG_LEVEL=D PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  if [ ! -f third_party/oio-sds/etc/bootstrap-option-versioning.yml ]
  then
    echo "config:" >> third_party/oio-sds/etc/bootstrap-option-versioning.yml
    echo "  meta2.max_versions: -1" >> third_party/oio-sds/etc/bootstrap-option-versioning.yml
  fi
  oio-reset.sh -v -v -N "$OIO_NS" \
    -f third_party/oio-sds/etc/bootstrap-preset-SINGLE.yml \
    -f third_party/oio-sds/etc/bootstrap-meta1-1digits.yml \
    -f third_party/oio-sds/etc/bootstrap-option-cache.yml \
    -f third_party/oio-sds/etc/bootstrap-option-versioning.yml
}

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps
compile_sds
run_sds

coverage run -a runserver.py conf/hashed-containers.cfg -v &
sleep 1
PID=$(jobs -p)

bash tests/functional/ns_wide_versioning_tests.sh "$OIO_NS" "$OIO_ACCOUNT"

for pid in $PID; do
    kill $pid
    wait $pid
done

# TODO(FVE): gridinit_cmd stop
