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
  openio cluster wait
}

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1

coverage run -p runserver.py conf/hashed-containers.cfg -v &
sleep 2
PID=$(jobs -p)

bash tests/functional/ns-wide-versioning-tests.sh "$OIO_NS" "$OIO_ACCOUNT"
RET=$?

for pid in $PID; do
    kill $pid
    wait $pid
done

# TODO(FVE): gridinit_cmd stop
exit $RET
