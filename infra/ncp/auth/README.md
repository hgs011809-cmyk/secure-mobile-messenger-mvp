# Auth service

Node 22 built-ins only. This service registers a browser-held P-256 public key with a one-time invite, verifies a fresh signature for each session, issues a single-use PeerJS admission token, and returns short-lived coturn REST credentials.

## Security model

- The browser's ECDSA private key remains non-exportable in IndexedDB.
- An invite is random, stored only as SHA-256, expires, and is consumed atomically once.
- The durable server record contains `deviceId`, fixed `peerId`, public key, fingerprint, and creation time. It contains no chat body or conversation history.
- A challenge is short-lived and single-use. Invalid signature attempts also consume it.
- A signaling token is opaque, peer-bound, short-lived, held only in memory, and consumed by Caddy `forward_auth` on the WebSocket handshake.
- TURN credentials use coturn's `static-auth-secret` HMAC-SHA1 mechanism and expire after 10 minutes by default.
- API responses and logs never include secrets beyond the one-time values intentionally returned to the authenticated client or local admin CLI.

This does not add app-layer E2EE. WebRTC DTLS and manual safety-code verification remain the current message protection boundary.

## Public API

All `/v1/*` requests accept JSON and enforce the exact `ALLOWED_ORIGIN` CORS origin.

- `POST /v1/register`
  - request: `{ "invite", "peerId", "publicKey" }`
  - response: `{ "deviceId", "peerId", "createdAt" }`
- `POST /v1/challenge`
  - request: `{ "deviceId", "peerId" }`
  - response: `{ "challengeId", "challengeText", "expiresAt" }`
- `POST /v1/session`
  - request: `{ "deviceId", "peerId", "challengeId", "signature" }`
  - response: `{ "signalToken", "expiresAt", "iceServers", "turnExpiresAt", "signaling" }`

`publicKey` is base64url SPKI for ECDSA P-256. `signature` is the browser WebCrypto base64url raw P-256 signature over `challengeText`.

## Internal API

These ports are never published by Compose.

- `GET /internal/verify-signal`: Caddy forward-auth target. Reads PeerJS `id` and `token` from `X-Forwarded-Uri`.
- `POST /internal/admin/invites`: creates one invite, protected by `X-Admin-Secret`.
- `GET /internal/admin/devices`: lists non-secret device metadata.
- `POST /internal/admin/devices/revoke`: revokes `{ "deviceId" }`.

## Admin CLI

Run inside the already-running auth container so the internal API and Docker secret are available:

```sh
docker compose exec auth node src/cli.js create-invite
docker compose exec auth node src/cli.js create-invite 86400
docker compose exec auth node src/cli.js list-devices
docker compose exec auth node src/cli.js revoke-device DEVICE_ID
```

The invite code is displayed once. Deliver it over a separate trusted channel.

## Tests

```sh
TEST_TMP_DIR=/tmp/auth-tests node --test test/unit.test.js test/integration.test.js
```
