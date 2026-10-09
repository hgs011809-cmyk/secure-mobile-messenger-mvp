#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets

for name in turn_shared_secret admin_secret; do
  target="secrets/$name"
  if [ -e "$target" ]; then
    echo "$target already exists; refusing to overwrite" >&2
    exit 1
  fi
  openssl rand -hex 32 > "$target"
  chmod 600 "$target"
done

echo 'Generated TURN and admin secrets with mode 0600.'
