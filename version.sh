#!/bin/bash
SRCDIR=$(dirname $0)

if [ -n "$GITHUB_SHA" ]; then
  # We are probably running in a Github workflow.
  VERSION_SOURCE_URL="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY"
  VERSION_COMMIT_HASH="$GITHUB_SHA"
  VERSION_BUILD_URL="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
  if [[ "$GITHUB_REF" =~ ^refs/tags/ ]]; then
    VERSION_TAG_NAME="$GITHUB_REF_NAME"
  fi
elif [ -n "$CIRCLE_SHA1" ]; then
  # We are running in a CircleCI job.
  VERSION_SOURCE_URL="https://github.com/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME"
  VERSION_COMMIT_HASH="$CIRCLE_SHA1"
  VERSION_BUILD_URL="$CIRCLE_BUILD_URL"
  VERSION_TAG_NAME="$CIRCLE_TAG"
elif [ -d ${SRCDIR}/.git ]; then
  # Otherwise, try to grab version information from the git repository.
  VERSION_COMMIT_HASH=$(git -C ${SRCDIR} rev-parse HEAD)
  VERSION_SOURCE_URL=$(git -C ${SRCDIR} remote get-url origin)
  VERSION_TAG_NAME=$(git -C ${SRCDIR} describe --tags --always)
fi

# Redirect to a file if provided as an argument.
if [ $# -ge 1 ]; then
  exec > $1
fi

cat << EOF
{
  "source": "${VERSION_SOURCE_URL}",
  "commit": "${VERSION_COMMIT_HASH}",
  "version": "${VERSION_TAG_NAME}",
  "build": "${VERSION_BUILD_URL}"
}
EOF
