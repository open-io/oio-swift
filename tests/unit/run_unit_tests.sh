#!/bin/bash

set -e

coverage run --source=oioswift -a $(which nosetests) -v \
    tests/unit/controllers \
    tests/unit/common/middleware/test_copy.py:TestOioServerSideCopyMiddleware \
    tests/unit/common/middleware/test_versioned_writes.py:OioVersionedWritesTestCase \
    tests/unit/common/middleware/test_container_hierarchy.py

./oio-check-version.sh
