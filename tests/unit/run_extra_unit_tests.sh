#!/bin/bash
# Run tests that require and installed version of oio-sds libraries

set -e

coverage run --source=oioswift,tests -p $(which nosetests) -v \
    --with-timer --timer-ok=100ms --timer-warning=1s \
    tests/unit/common/middleware/test_hashedcontainer.py  # requires liboiocore.so
