#!/bin/bash

set -e

export TEST_SUITE="${TEST_SUITE:-$1}"

if [ "$TEST_SUITE" = "unit" ]
then
  tests/unit/run_unit_tests.sh
else
  tests/functional/run-${TEST_SUITE}-tests.sh $*
  tests/unit/run_extra_unit_tests.sh
fi
