#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NO_COLOR='\033[0m'

function install_deps() {
  if [ -n "${SKIP_BUILD}" ]; then
    return
  fi
  echo "travis_fold:start:install_deps"
  sudo apt-get install -y --force-yes \
    apache2 apache2-dev libapache2-mod-wsgi \
    beanstalkd \
    bison \
    curl libcurl4-gnutls-dev \
    flex \
    libapreq2-dev \
    libattr1-dev \
    liberasurecode-dev \
    libevent-dev \
    libglib2.0-dev \
    libjson-c-dev \
    liblzo2-dev \
    libsqlite3-dev \
    libzmq3-dev \
    libzookeeper-mt-dev \
    openio-gridinit openio-asn1c \
    python-all-dev python-virtualenv
  echo "travis_fold:end:install_deps"
}

function compile_sds() {
  if [ -n "${SKIP_BUILD}" ]; then
    return
  fi
  cd third_party/oio-sds || return
  echo "travis_fold:start:compile_deps"
  cmake \
    -DCMAKE_INSTALL_PREFIX="/tmp/oio" \
    -DLD_LIBDIR="lib" \
    -DCMAKE_BUILD_TYPE="Debug" \
    -DZK_LIBDIR="/usr/lib" \
    -DZK_INCDIR="/usr/include/zookeeper" \
    -DAPACHE2_LIBDIR="/usr/lib/apache2" \
    -DAPACHE2_INCDIR="/usr/include/apache2" \
    -DAPACHE2_MODDIR="/tmp/oio/lib/apache2/module" \
    .
  make all install
  export PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  echo "travis_fold:end:compile_deps"
  cd ../.. || return
}

function run_sds() {
  export G_DEBUG_LEVEL=D PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  oio-reset.sh -v -v -N "$OIO_NS" \
    -f third_party/oio-sds/etc/bootstrap-preset-SINGLE.yml \
    -f third_party/oio-sds/etc/bootstrap-meta1-1digits.yml \
    -f third_party/oio-sds/etc/bootstrap-option-cache.yml
  openio cluster wait || (openio cluster list --stats; gridinit_cmd -S ~/.oio/sds/run/gridinit.sock status2; sudo tail -n 100 /var/log/syslog; return 1)
}

function configure_aws() {
  # CREATE AWS CONFIGURATION
  mkdir -p "$HOME/.aws"
  cat <<EOF >"$HOME/.aws/credentials"
[default]
aws_access_key_id=demo:demo
aws_secret_access_key=DEMO_PASS

[user1]
aws_access_key_id=demo:user1
aws_secret_access_key=USER_PASS

[a2adm]
aws_access_key_id=account2:admin
aws_secret_access_key=ADMIN_PASS

[a2u1]
aws_access_key_id=account2:user1
aws_secret_access_key=USER_PASS
EOF

  cat <<EOF >"$HOME/.aws/config"
[default]
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB

[profile user1]
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB

[profile a2adm]
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB

[profile a2u1]
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB
EOF
}

function configure_s3cmd() {
    cat <<EOF >"$HOME/.s3cfg"
[default]
access_key = demo:demo
bucket_location = us-east-1
default_mime_type = binary/octet-stream
host_base = localhost:5000
host_bucket = no
multipart_chunk_size_mb = 5
multipart_max_chunks = 10000
preserve_attrs = True
progress_meter = False
secret_key = DEMO_PASS
signature_v2 = True
signurl_use_https = False
use_https = False
verbosity = WARNING
EOF
}

function configure_oioswift() {
    sed -i "s/%USER%/$(id -un)/g" "$1"
}

function run_script() {
  if "$1"; then
    printf "${GREEN}\n${1}: OK\n${NO_COLOR} ($2)"
    return 0
  else
    RET=1
    printf "${RED}\n${1}: FAILED\n${NO_COLOR} ($2)"
    return 1
  fi
}

function run_functional_test() {
    local conf
    if [ -f "conf/$1" ]; then
        conf="conf/$1"
    else
        conf="$1"
    fi
    shift

    local test_suites=$(for suite in $*; do echo "tests/functional/${suite}"; done)
    configure_oioswift $conf

    coverage run -p runserver.py $conf -v >/tmp/journal.log 2>&1 &
    export GW_CONF=$(readlink -e $conf)
    sleep 1
    PID=$(jobs -p)

    for suite in $test_suites
    do
      run_script "$suite" "$conf"
      if [ $? -ne 0 ]; then
        echo "LOG"
        tail -n100 /tmp/journal.log
      fi
    done

    for pid in $PID; do
        kill $pid
        wait $pid
    done
}
