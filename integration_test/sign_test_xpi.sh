#!/usr/bin/env bash

set -ev

host=$1
port=$2

while ! nc -z "$host" "$port"; do
  echo -n "."
  sleep 1 # wait for a sec before checking again
done
curl -F "input=@test.xpi" -o /tmp/signed-default.xpi \
  -H "Authorization: c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547" \
  "http://$host:$port/sign"
curl -F "input=@test.xpi" -o /tmp/signed-PKCS7-SHA256-COSE-ES256.xpi \
  -H "Authorization: b8c8c00f310c9e160dda75790df6be106e29607fde3c1092287d026c014be880" \
  "http://$host:$port/sign"
