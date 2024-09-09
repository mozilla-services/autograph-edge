#!/bin/sh
SRCDIR=$(dirname $0)

if [ -d ${SRCDIR}/.git ]; then
  VERSION_COMMIT_HASH=${VERSION_COMMIT_HASH:=$(git -C ${SRCDIR} rev-parse HEAD)}
  VERSION_SOURCE_URL=${VERSION_SOURCE_URL:=$(git -C ${SRCDIR} remote get-url origin)}
fi
if [ -z "${VERSION_SOURCE_URL}" ]; then
  VERSION_SOURCE_URL="https://github.com/mozilla-services/autograph-edge.git"
fi

cat << EOF > ${SRCDIR}/version.json
{
  "source": "${VERSION_SOURCE_URL}",
  "commit": "${VERSION_COMMIT_HASH}",
  "version: "${VERSION_TAG_NAME}",
  "build: "${VERSION_BUILD_URL}",
}
EOF
