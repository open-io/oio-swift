#!/bin/bash

set -e

coverage run --source=oioswift,tests -p $(which nosetests) -v --with-timer \
    tests/unit/controllers \
    tests/unit/common/middleware/crypto \
    tests/unit/common/middleware/test_copy.py:TestOioServerSideCopyMiddleware \
    tests/unit/common/middleware/test_versioned_writes.py:OioVersionedWritesTestCase \
    tests/unit/common/middleware/test_container_hierarchy.py \
    tests/unit/common/middleware/test_regexcontainer.py

# These tests require liboiocore.so, which is not installed while running unit tests
#    tests/unit/common/middleware/test_hashedcontainer.py \


./oio-check-version.sh
