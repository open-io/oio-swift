#!/bin/bash

# TODO(FVE): merge this file with run-s3-tests.sh

source tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps
compile_sds
run_sds
configure_aws

RET=0

run_functional_test s3-versioning-encryption.cfg encryption-tests.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
