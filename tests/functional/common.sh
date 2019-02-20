#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NO_COLOR='\033[0m'

function install_deps() {
  if [ -n "${SKIP_BUILD}" ]; then
    return
  fi
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
}

function compile_sds() {
  if [ -n "${SKIP_BUILD}" ]; then
    return
  fi
  cd third_party/oio-sds || return
  cmake \
    -DCMAKE_INSTALL_PREFIX="/tmp/oio" \
    -DLD_LIBDIR="lib" \
    -DCMAKE_BUILD_TYPE="Debug" \
    -DSTACK_PROTECTOR=1 \
    -DZK_LIBDIR="/usr/lib" \
    -DZK_INCDIR="/usr/include/zookeeper" \
    -DAPACHE2_LIBDIR="/usr/lib/apache2" \
    -DAPACHE2_INCDIR="/usr/include/apache2" \
    -DAPACHE2_MODDIR="/tmp/oio/lib/apache2/module" \
    .
  make all install
  export PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  cd ../.. || return
}

function run_sds() {
  export G_DEBUG_LEVEL=D PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  oio-reset.sh -v -v -N "$OIO_NS" \
    -f third_party/oio-sds/etc/bootstrap-preset-SINGLE.yml \
    -f third_party/oio-sds/etc/bootstrap-meta1-1digits.yml \
    -f third_party/oio-sds/etc/bootstrap-option-cache.yml
  openio cluster wait
}

function configure_aws() {
  # CREATE AWS CONFIGURATION
  mkdir -p "$HOME/.aws"
  cat <<EOF >"$HOME/.aws/credentials"
[default]
aws_access_key_id=demo:demo
aws_secret_access_key=DEMO_PASS
EOF

  cat <<EOF >"$HOME/.aws/config"
[default]
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
    sed -i "s/USER/$(id -un)/g" "$1"
}

function run_functional_test() {
    local conf="conf/$1"
    shift
    local test_suites=$(for suite in $*; do echo "tests/functional/${suite}"; done)
    configure_oioswift $conf

    coverage run -p runserver.py $conf -v &
    sleep 1
    PID=$(jobs -p)

    for suite in $test_suites
    do
      if bash "$suite"; then
        printf "${GREEN}\n${suite}: OK\n${NO_COLOR}"
      else
        RET=1
        printf "${RED}\n${suite}: FAILED\n${NO_COLOR}"
      fi
    done

    for pid in $PID; do
        kill $pid
        wait $pid
    done
}
