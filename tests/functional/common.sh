#!/bin/bash

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
    libleveldb1 libleveldb-dev \
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
  cd ../.. || return
}
