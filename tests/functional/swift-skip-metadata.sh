#!/bin/bash

RET=0
set -e

ACCOUNT=$(openio cluster list account -c Addr -f value)
openio cluster lock account ${ACCOUNT}
sleep 5

# prepare object
curl -XPUT http://localhost:5000/example/pass --data-binary @/etc/magic

# read object
curl -XGET http://localhost:5000/example/pass

# overwrite object
curl -XPUT http://localhost:5000/example/pass --data-binary @/etc/magic

# check in journal that "found only 0 services matching the criteria" is not present
if grep "found only 0 services matching the criteria" /tmp/journal.log; then
    echo "Account was still used by swift"
    RET=1
fi

openio cluster unlock account ${ACCOUNT}
sleep 5

exit $RET
