#!/bin/bash

echo "# Running tests against the custom healthcheck middleware"

set -e
DATA=$(curl -s http://localhost:5000/_status)
WORKERS=$(echo "$DATA" | jq -r '."stat.workers"')
CUR_REQS=$(echo "$DATA" | jq -r '."stat.cur_reqs"')
echo "healthcheck is reporting $WORKERS workers and $CUR_REQS requests"
echo "OK"
