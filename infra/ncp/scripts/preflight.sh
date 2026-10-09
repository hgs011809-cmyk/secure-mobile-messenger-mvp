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
current_user=$(id -u)
for secret_file in secrets/turn_shared_secret secrets/admin_secret; do
  if [ ! -f "$secret_file" ] || [ -L "$secret_file" ] || [ ! -r "$secret_file" ]; then
    echo "Generate a regular $secret_file file before deployment" >&2
    exit 1
  fi
  if [ "$(stat -c '%a' "$secret_file")" != '600' ]; then
    echo "$secret_file permissions must be 0600" >&2
    exit 1
  fi
  secret_owner=$(stat -c '%u' "$secret_file")
  if [ "$secret_owner" != "$current_user" ] && [ "$secret_owner" != '0' ]; then
    echo "$secret_file must be owned by the deploy user or root" >&2
    exit 1
  fi
  secret=$(tr -d '\r\n' < "$secret_file")
  if ! printf '%s' "$secret" | grep -Eq '^[A-Za-z0-9_-]{43,}$|^[A-Fa-f0-9]{64,}$'; then
    echo "$secret_file must contain at least 32 random bytes in base64url or hexadecimal" >&2
    exit 1
  fi
done

docker compose config --quiet
echo 'Preflight checks passed.'
