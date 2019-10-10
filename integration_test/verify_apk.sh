#!/usr/bin/env bash

set -ev

apk_file=$1
/opt/android/sdk/build-tools/27.0.3/apksigner verify --verbose "$apk_file"
