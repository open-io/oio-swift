#!/bin/bash

export TEST_SUITE="${TEST_SUITE:-$1}"

if [ "$TEST_SUITE" = "unit" ]
then
  tests/unit/run_unit_tests.sh
elif [ "$TEST_SUITE" = "ns-wide-versioning" ]
then
  tests/functional/run_ns_wide_versioning_tests.sh $*
elif [ "$TEST_SUITE" = "s3" ]
then
  tests/functional/run_s3_tests.sh $*
else
  echo "Test suite '$TEST_SUITE' not implemented"
fi
