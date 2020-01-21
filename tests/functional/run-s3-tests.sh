#!/bin/bash

source tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws
configure_s3cmd

# Container Hierarchy supports VERSIONING from 4.6
CH_VERSIONING=$(python -c "import oio.common.constants as cnt; print(hasattr(cnt, 'FORCEVERSIONING_HEADER'))")

RET=0

# Launch test with container hierarchy with same configuration file
for key_format in v1 v2 v3; do
    for mask_empty_prefixes in false true; do

        # generate configuration file
        name=/tmp/s3-container-hierarchy-${key_format}-${mask_empty_prefixes}.cfg
        cp -v conf/s3-container-hierarchy.cfg $name
        sed -e "s/<key_format>/$key_format/g" -e "s/<mask_empty_prefixes>/$mask_empty_prefixes/g" -i $name

        run_functional_test $name s3_container_hierarchy_v2.sh s3-marker.sh s3-mpu.py

        # run only CH versioning
        if [ "${CH_VERSIONING}" == "True" ]; then
            if [ "$mask_empty_prefixes" == "true" ]; then
                run_functional_test $name s3-versioning.sh
            fi
            run_functional_test $name s3-versioning-container-hierarchy.sh
        fi
    done

     # only run conversion test on v1 keys
     if [ "$key_format" == "v1" ]; then
        run_script tests/functional/s3-conversion-container-hierarchy.sh
    fi
done

run_functional_test s3-fastcopy.cfg s3-acl-metadata.sh s3-marker.sh
# Run all suites in the same environment.
# They do not share buckets so this should be OK.
run_functional_test s3-default.cfg s3-acl-metadata.sh s3-tagging.sh s3-multipart.sh s3-s3cmd.sh buckets-listing.sh s3-marker.sh s3-basic-test.py s3-mpu.py

# TODO(FVE): gridinit_cmd stop
exit $RET
