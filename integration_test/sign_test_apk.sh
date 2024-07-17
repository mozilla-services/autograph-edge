#!/usr/bin/env bash

set -ev

host=$1
port=$2

while ! nc -z "$host" "$port"; do
  echo -n "."
  sleep 1 # wait for a sec before checking again
done
curl -F "input=@test.apk" -o /app/signed.apk \
  -H "Authorization: dd095f88adbf7bdfa18b06e23e83896107d7e0f969f7415830028fa2c1ccf9fd" \
  "http://$host:$port/sign"
