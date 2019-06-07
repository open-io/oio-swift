#!/bin/bash

source tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws
configure_s3cmd

CH_VERSIONING=$(python -c "import oio, sys; print(oio.__version__ > '4.5.1')")

RET=0

run_functional_test s3-container-hierarchy.cfg s3_container_hierarchy_v2.sh s3-marker.sh
# run only CH versioning
if [ "${CH_VERSIONING}" == "True" ]; then
    run_functional_test s3-container-hierarchy.cfg s3-versioning.sh
fi

run_functional_test s3-container-hierarchy-key-v2.cfg s3_container_hierarchy_v2.sh s3-marker.sh
# run only CH versioning
if [ "${CH_VERSIONING}" == "True" ]; then
    run_functional_test s3-container-hierarchy-v2.cfg s3-versioning.sh
fi

run_functional_test s3-fastcopy.cfg s3-acl-metadata.sh s3-marker.sh
# Run all suites in the same environment.
# They do not share buckets so this should be OK.
run_functional_test s3-default.cfg s3-acl-metadata.sh s3-tagging.sh s3-multipart.sh s3-s3cmd.sh buckets-listing.sh s3-marker.sh s3-basic-test.py
run_script tests/functional/s3-conversion-container-hierarchy.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
