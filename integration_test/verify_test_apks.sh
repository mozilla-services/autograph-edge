#!/usr/bin/env bash

set -e  # bail on error

# submits and verifies a test APK to autograph edge stage and prod
#
# requires env vars (client_token value):
#
# STAGE_EDGE_APK_API_KEY a stage autograph edge API key 
# STAGE_EDGE_APK_V3_API_KEY a stage autograph edge API key for an APK v3 signer
# PROD_EDGE_APK_API_KEY a prod autograph edge API key
# PROD_EDGE_APK_V3_API_KEY a stage autograph edge API key for an APK v3 signer
# AUTOGRAPH_DIR an absolute path to an autograph clone e.g. /home/gguthe/autograph
# VERBOSE set to non-empty if you want to debug. Otherwise results only.
#
# example usage:
# STAGE_EDGE_APK_API_KEY=<redacted> PROD_EDGE_APK_API_KEY=<redacted> AUTOGRAPH_DIR=~/autograph ./test_autograph_edge.sh
#
# in a container (if you don't have the autograph repo cloned and apksigner installed):
#
#   docker pull mozilla-autograph
#   
#   # leading spaces below to avoid putting in history
#     export PROD_EDGE_APK_API_KEY=<redacted>
#     export PROD_EDGE_APK_V3_API_KEY=<redacted>
#     export STAGE_EDGE_APK_API_KEY=<redacted>
#     export STAGE_EDGE_APK_V3_API_KEY=<redacted>
#   docker run --rm -it \
#     -v $(pwd):/host \
#     -e STAGE_EDGE_APK_API_KEY \
#     -e STAGE_EDGE_APK_V3_API_KEY \
#     -e PROD_EDGE_APK_API_KEY \
#     -e PROD_EDGE_APK_V3_API_KEY \
#     mozilla/autograph \
#       /bin/bash -c 'AUTOGRAPH_DIR=/app/src/autograph/ /host/verify_test_apks.sh'


# Hide output unless VERBOSE is defined
VERBOSE=${VERBOSE:-""}
if [[ -n "$VERBOSE" ]]; then
  curl_options="-v"
  verify_options="--print-certs --verbose"
else
  curl_options="--silent"
  verify_options=""
fi


if [[ -n "$STAGE_EDGE_APK_API_KEY" ]]; then
  rm -f stage-signed.apk
  curl $curl_options -F "input=@${AUTOGRAPH_DIR}/signer/apk2/aligned-two-files.apk" -o stage-signed.apk -H "Authorization: $STAGE_EDGE_APK_API_KEY" https://edge.stage.autograph.services.mozaws.net/sign
  echo "verifying stage signed apk"
  apksigner verify $verify_options stage-signed.apk
else
  echo "skipping test of STAGE_EDGE_APK_API_KEY"
fi

if [[ -n "$STAGE_EDGE_APK_V3_API_KEY" ]] ; then
  rm -f stage-signed-v3.apk
  curl $curl_options -F "input=@${AUTOGRAPH_DIR}/signer/apk2/aligned-two-files.apk" -o stage-signed-v3.apk -H "Authorization: $STAGE_EDGE_APK_V3_API_KEY" https://edge.stage.autograph.services.mozaws.net/sign
  echo "verifying stage signed apk v3"
  apksigner verify $verify_options stage-signed-v3.apk
else
  echo "skipping test of STAGE_EDGE_APK_V3_API_KEY"
fi

if [[ -n "$PROD_EDGE_APK_API_KEY" ]]; then
  rm -f prod-signed.apk
  curl $curl_options -F "input=@${AUTOGRAPH_DIR}/signer/apk2/aligned-two-files.apk" -o prod-signed.apk -H "Authorization: $PROD_EDGE_APK_API_KEY" https://edge.prod.autograph.services.mozaws.net/sign
  echo "verifying prod signed apk"
  apksigner verify $verify_options prod-signed.apk
else
  echo "skipping test of PROD_EDGE_APK_API_KEY"
fi

if [[ -n "$PROD_EDGE_APK_V3_API_KEY" ]]; then
  rm -f prod-signed-v3.apk
  curl $curl_options -F "input=@${AUTOGRAPH_DIR}/signer/apk2/aligned-two-files.apk" -o prod-signed-v3.apk -H "Authorization: $PROD_EDGE_APK_V3_API_KEY" https://edge.prod.autograph.services.mozaws.net/sign
  echo "verifying prod signed apk v3"
  apksigner verify $verify_options prod-signed-v3.apk
else
  echo "skipping test of PROD_EDGE_APK_V3_API_KEY"
fi

# if we're here, everything passed
echo ""
echo "GREEN - all tests passed"
echo ""
