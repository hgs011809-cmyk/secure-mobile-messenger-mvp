#!/bin/sh
set -eu

secret_file=${TURN_SECRET_FILE:-./secrets/turn_shared_secret}
ttl=${TURN_TTL_SECONDS:-3600}
subject=${1:-pilot-device}

if ! printf '%s' "$ttl" | grep -Eq '^[0-9]+$' || [ "$ttl" -lt 60 ] || [ "$ttl" -gt 86400 ]; then
  echo 'TURN_TTL_SECONDS must be between 60 and 86400' >&2
  exit 1
fi
if ! printf '%s' "$subject" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'; then
  echo 'Subject must be 1-64 characters using letters, numbers, dot, underscore, or hyphen' >&2
  exit 1
fi
if [ ! -r "$secret_file" ]; then
  echo "Cannot read $secret_file" >&2
  exit 1
fi
secret=$(tr -d '\r\n' < "$secret_file")
expiry=$(( $(date +%s) + ttl ))
username="${expiry}:${subject}"
credential=$(printf '%s' "$username" | openssl dgst -sha1 -hmac "$secret" -binary | openssl base64 -A)

printf '{"username":"%s","credential":"%s","expiresAt":%s}\n' "$username" "$credential" "$expiry"
