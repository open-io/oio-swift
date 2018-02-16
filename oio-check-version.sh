#!/bin/bash

# https://stackoverflow.com/a/4024263/537768
verlte() {
  [  "$1" = "$(echo -e "$1\n$2" | sort -V | head -n1)" ]
}

PROJECT='oio-swift'

# This will work in the main repository, but not in forks
LATEST_TAG=$(git fetch --tags && git describe --tags)
if [ -z "$LATEST_TAG" ]
then
  echo "No tag, cannot check"
  exit 0
fi

VERSION_REGEX='s/[^[:digit:]]*(([[:digit:]]+\.){2})([[:digit:]]+).*$/\1\3/p'

echo "$PROJECT pre-release version is   $LATEST_TAG"
export LATEST_TAG
TAG_VERSION=$(echo "$LATEST_TAG" | sed -E -n -e "$VERSION_REGEX")
CODE_VERSION=$(sed -E -n -e "$VERSION_REGEX" oioswift/__init__.py)

echo "$PROJECT latest tagged version is $TAG_VERSION"
echo "$PROJECT version from code is     $CODE_VERSION"

# Ensure pkg-config version is up-to-date
if verlte "$TAG_VERSION" "$CODE_VERSION"
then
  echo "OK"
else
  echo "KO"
  exit 1
fi
