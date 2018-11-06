#!/bin/bash
# Run tests that require and installed version of oio-sds libraries

set -e

coverage run --source=oioswift,tests -a $(which nosetests) -v --with-timer \
    tests/unit/common/middleware/test_hashedcontainer.py  # requires liboiocore.so
