#!/bin/bash

set -e

coverage run --source=oioswift,tests -a $(which nosetests) -v \
    tests/unit/controllers \
    tests/unit/common/middleware/crypto \
    tests/unit/common/middleware/test_copy.py:TestOioServerSideCopyMiddleware \
    tests/unit/common/middleware/test_versioned_writes.py:OioVersionedWritesTestCase \
    tests/unit/common/middleware/test_container_hierarchy.py \
    tests/unit/common/middleware/test_container_sharding.py \
    tests/unit/common/middleware/test_regexcontainer.py

./oio-check-version.sh
