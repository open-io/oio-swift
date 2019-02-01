#!/bin/bash

source tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps
compile_sds
run_sds

RET=0

run_functional_test swift-flatns-skip-metadata.cfg swift-skip-metadata.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
