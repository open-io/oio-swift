#!/bin/bash

source tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps
compile_sds
run_sds
configure_aws

RET=0

run_functional_test s3_container_hierarchy.cfg s3_container_hierarchy_v2.sh
run_functional_test s3_container_sharding.cfg s3_container_hierarchy_v2.sh
run_functional_test s3_fastcopy.cfg s3-acl-metadata.sh
run_functional_test s3-default.cfg s3-acl-metadata.sh
run_functional_test s3-default.cfg s3-versioning.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
