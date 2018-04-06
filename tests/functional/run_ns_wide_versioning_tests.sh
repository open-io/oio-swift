#!/bin/bash

function install_deps() {
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
    libleveldb1 libleveldb-dev \
    liblzo2-dev \
    libsqlite3-dev \
    libzmq3-dev \
    libzookeeper-mt-dev \
    openio-gridinit openio-asn1c \
    python-all-dev python-virtualenv
}

function compile_sds() {
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
  cd ../.. || return
}

function run_sds() {
  export G_DEBUG_LEVEL=D PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  if [ ! -f third_party/oio-sds/etc/bootstrap-option-versioning.yml ]
  then
    echo "config:" >> third_party/oio-sds/etc/bootstrap-option-versioning.yml
    echo "  meta2.max_versions: -1" >> third_party/oio-sds/etc/bootstrap-option-versioning.yml
  fi
  oio-reset.sh -v -v -N "$OIO_NS" \
    -f third_party/oio-sds/etc/bootstrap-preset-SINGLE.yml \
    -f third_party/oio-sds/etc/bootstrap-meta1-1digits.yml \
    -f third_party/oio-sds/etc/bootstrap-option-cache.yml \
    -f third_party/oio-sds/etc/bootstrap-option-versioning.yml
}

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps
compile_sds
run_sds

coverage run -a runserver.py conf/hashed-containers.cfg -v &
sleep 1
PID=$(jobs -p)

bash tests/functional/ns_wide_versioning_tests.sh "$OIO_NS" "$OIO_ACCOUNT"

for pid in $PID; do
    kill $pid
    wait $pid
done

# TODO(FVE): gridinit_cmd stop
