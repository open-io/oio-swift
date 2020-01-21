#!/bin/bash

source tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws
configure_s3cmd

# IAM
RULES_FILE="$PWD/conf/iam_rules.json"
sed -e "s#%RULES_FILE%#${RULES_FILE}#g" conf/s3-iam.cfg.in > conf/s3-iam.cfg
run_functional_test s3-iam.cfg s3-iam.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
