#!/bin/bash

source tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1

RET=0

run_functional_test swift-flatns-skip-metadata.cfg \
    swift-skip-metadata.sh \
    swift-healthcheck.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
