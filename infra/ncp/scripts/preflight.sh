#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

for command_name in docker openssl grep stat id; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo 'Docker Compose v2 is required' >&2
  exit 1
fi
if [ ! -f .env ] || [ -L .env ]; then
  echo 'Copy .env.example to a regular .env file and replace every placeholder' >&2
  exit 1
fi
if [ "$(stat -c '%a' .env)" != '600' ]; then
  echo '.env permissions must be 0600' >&2
  exit 1
fi
if grep -Eq 'example\.com|203\.0\.113\.10|192\.0\.2\.10' .env; then
  echo '.env still contains example values' >&2
  exit 1
fi
secret_file=secrets/turn_shared_secret
if [ ! -f "$secret_file" ] || [ -L "$secret_file" ] || [ ! -r "$secret_file" ]; then
  echo 'Generate a regular secrets/turn_shared_secret file before deployment' >&2
  exit 1
fi
if [ "$(stat -c '%a' "$secret_file")" != '600' ]; then
  echo 'TURN shared secret permissions must be 0600' >&2
  exit 1
fi
secret_owner=$(stat -c '%u' "$secret_file")
current_user=$(id -u)
if [ "$secret_owner" != "$current_user" ] && [ "$secret_owner" != '0' ]; then
  echo 'TURN shared secret must be owned by the deploy user or root' >&2
  exit 1
fi
secret=$(tr -d '\r\n' < "$secret_file")
if ! printf '%s' "$secret" | grep -Eq '^[A-Fa-f0-9]{64,}$'; then
  echo 'TURN shared secret must be at least 32 random bytes encoded as hexadecimal' >&2
  exit 1
fi

docker compose config --quiet
echo 'Preflight checks passed.'
