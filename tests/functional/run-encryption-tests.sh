#!/bin/bash

# TODO(FVE): merge this file with run-s3-tests.sh

source tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws

RET=0

run_functional_test s3-versioning-encryption.cfg encryption-tests.sh
run_functional_test s3-versioning-custom-encryption.cfg custom-encryption-tests.sh s3-versioning.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
