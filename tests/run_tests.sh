#!/bin/bash

set -e

export TEST_SUITE="${TEST_SUITE:-$1}"

if [ "$TEST_SUITE" = "unit" ]
then
  tests/unit/run_unit_tests.sh
else
  export LD_LIBRARY_PATH=/tmp/oio/lib:$LD_LIBRARY_PATH
  tests/functional/run-${TEST_SUITE}-tests.sh $*
  tests/unit/run_extra_unit_tests.sh
fi
