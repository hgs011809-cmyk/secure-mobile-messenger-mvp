#!/bin/sh
set -eu
# Generate only on the authenticated server. Never print private key material.
image="${1:-secure-msg-auth:push-v1}"
if [ -s secrets/vapid_private_key ] && [ -s secrets/vapid_public_key ]; then exit 0; fi
if [ -e secrets/vapid_private_key ] || [ -e secrets/vapid_public_key ]; then
  echo 'Incomplete VAPID key pair. Stop and repair without overwriting keys.' >&2
  exit 1
fi
mkdir -p secrets
chmod 700 secrets
docker run --rm --user 0:0 --entrypoint node -v "$(pwd)/secrets:/secrets" "$image" --input-type=module -e 'import fs from "node:fs"; import webpush from "web-push"; const keys=webpush.generateVAPIDKeys(); for(const [name,value] of [["vapid_public_key",keys.publicKey],["vapid_private_key",keys.privateKey]])fs.writeFileSync("/secrets/"+name,value+"\n",{mode:0o600,flag:"wx"});'
chown root:root secrets/vapid_public_key secrets/vapid_private_key
chgrp 4242 secrets/vapid_public_key secrets/vapid_private_key
chmod 640 secrets/vapid_public_key secrets/vapid_private_key
