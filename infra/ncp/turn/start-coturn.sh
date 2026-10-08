#!/bin/sh
set -eu

: "${PUBLIC_IP:?PUBLIC_IP is required}"
: "${RELAY_IP:?RELAY_IP is required}"
: "${TURN_REALM:?TURN_REALM is required}"
: "${TURN_MIN_PORT:=49160}"
: "${TURN_MAX_PORT:=49200}"

valid_ipv4() {
  candidate=$1
  old_ifs=$IFS
  IFS=.
  set -- $candidate
  IFS=$old_ifs
  [ "$#" -eq 4 ] || return 1
  for octet in "$@"; do
    case "$octet" in
      ''|*[!0-9]*) return 1 ;;
    esac
    [ "$octet" -le 255 ] || return 1
  done
}

for value_name in PUBLIC_IP RELAY_IP; do
  eval "value=\${$value_name}"
  if ! valid_ipv4 "$value"; then
    echo "$value_name must be a valid IPv4 address" >&2
    exit 1
  fi
done

if ! printf '%s' "$TURN_REALM" | grep -Eq '^[A-Za-z0-9.-]+$'; then
  echo 'TURN_REALM contains invalid characters' >&2
  exit 1
fi
if ! printf '%s' "$TURN_MIN_PORT:$TURN_MAX_PORT" | grep -Eq '^[0-9]+:[0-9]+$'; then
  echo 'TURN port range must be numeric' >&2
  exit 1
fi
if [ "$TURN_MIN_PORT" -lt 1024 ] || [ "$TURN_MAX_PORT" -gt 65535 ] || [ "$TURN_MIN_PORT" -gt "$TURN_MAX_PORT" ]; then
  echo 'TURN port range is invalid' >&2
  exit 1
fi

secret_file=/run/secrets/turn_shared_secret
if [ ! -r "$secret_file" ]; then
  echo 'TURN shared secret file is missing' >&2
  exit 1
fi
secret=$(tr -d '\r\n' < "$secret_file")
if ! printf '%s' "$secret" | grep -Eq '^[A-Fa-f0-9]{64,}$'; then
  echo 'TURN shared secret must be at least 32 random bytes encoded as hexadecimal' >&2
  exit 1
fi

umask 077
cat > /tmp/turnserver.conf <<EOF
listening-port=3478
listening-ip=${RELAY_IP}
relay-ip=${RELAY_IP}
external-ip=${PUBLIC_IP}/${RELAY_IP}
min-port=${TURN_MIN_PORT}
max-port=${TURN_MAX_PORT}
fingerprint
use-auth-secret
static-auth-secret=${secret}
realm=${TURN_REALM}
stale-nonce=600
total-quota=200
user-quota=4
max-bps=262144
bps-capacity=10485760
no-cli
no-tls
no-dtls
no-ipv6
no-loopback-peers
no-multicast-peers
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.0.2.0-192.0.2.255
denied-peer-ip=192.88.99.0-192.88.99.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=198.51.100.0-198.51.100.255
denied-peer-ip=203.0.113.0-203.0.113.255
denied-peer-ip=224.0.0.0-255.255.255.255
no-stdout-log
log-file=/dev/null
EOF

exec turnserver -c /tmp/turnserver.conf
