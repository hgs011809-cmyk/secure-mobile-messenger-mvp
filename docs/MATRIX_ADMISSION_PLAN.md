# Matrix admission and application integration gate

Design only. NOT implemented, NOT deployed, and NOT a security sign-off. Existing app/auth/NCP services stay unchanged. The synthetic CI does not replace Android acceptance or hosting approval.

## Existing authenticated boundary

`infra/ncp/auth/src/server.js` currently enrolls a device through `/v1/register`, preserving `deviceId`, `peerId`, `publicKeySpkiB64` and its SHA-256 fingerprint. `/v1/challenge` produces a short-lived one-time `direct-auth-v1` challenge bound to device and peer. `/v1/session` deletes the challenge before verifying the enrolled P-256 signature and then issues separate signaling/push tokens. `/internal/verify-signal` consumes the signaling token and checks current enrollment. Matrix must not reuse these tokens or weaken these checks.

A future optional Matrix broker belongs only after successful device signature verification. It must be explicitly disabled by default and leave existing session responses/behavior unchanged while disabled. No Matrix credentials currently exist in this auth service.

## Required broker contract, still unverified

1. Map the stable enrolled `deviceId` to one persisted opaque Matrix user ID and one allowed Matrix device ID. Do not accept a client-supplied replacement user/device as authority. Verify current enrollment before every grant. Keep Matrix admin access and any server-generated account passwords server-side, never in frontend builds, GitHub logs, chat, or URL query strings.
2. Use only the selected Synapse version's supported provisioning/login/revocation APIs, after checking exact device-binding and lifetime behavior. Browser receives only its own bounded session. Separate this from signal/push token issuance; fail closed for Matrix while preserving the legacy path when Matrix is disabled.
3. Signup-off and observing two devices are NOT an enforcement mechanism. Reject unauthorized accounts, extra devices, token-derived login paths, and device replacement at the server/admission boundary. Inventory all selected-version session/device creation endpoints, including token login and optional dehydration. Do not assume broker-only login prevents direct Matrix client APIs from minting another session.
4. Establish one private unfederated encrypted room for the permitted pair. The trusted policy must prevent additional membership, public joins/aliases, encryption removal and unauthorized state changes, not merely rely on honest UI. For room version 12 the creator is implicitly infinitely privileged and must not be placed in the power-level `users` map. Validate unilateral `redact:0` behavior for both ordinary enrolled identities.
5. Revocation must invalidate Matrix sessions/device access and remove or otherwise deny the revoked identity at the room boundary. Deny re-provisioning while the old app record is revoked. Device loss/replacement needs fresh admission and verification; do not silently transfer the old identity's keys. Do not claim existing client-held keys/copies become unrecoverable through server revocation.

## Key verification is separate from enrollment

The existing P-256 safety code authenticates the previous identity flow; it is NOT Matrix device verification. A successful broker login must not automatically mark remote encryption keys verified. Use the SDK's standard Matrix device verification/SAS flow with explicit user confirmation of the exact counterpart device. Unexpected device IDs or changed keys block sends and record rendering until reviewed. Keep unverified-device blocking and cross-signed-device automatic trust disabled in this pilot. The CI's public-key exchange between isolated synthetic workers is a test fixture, not an end-user trust UX. Receive/render gates must also reject unencrypted events in the encrypted room, failed/tampered ciphertext and unknown/untrusted sender devices using the selected SDK's authenticated-event metadata. A successful decryption alone is not a substitute for sender verification. These negative application-layer cases still need implementation and tests.

## Client lifecycle and history

- Keep Matrix access tokens in memory. Restore the SAME Matrix device/private keys through durable Rust crypto storage when the application reopens; renew the session through enrolled-device authentication. Do not accidentally register a new Matrix device on every reload.
- Use the SDK MemoryStore without localStorage for room/events/local echoes in this experiment. Crypto keys and deletion metadata alone are durable. Fetch encrypted history from the server after reconnect. Network-free access to prior local history and a durable offline-sender outbox are NOT implemented. A future local cache must retain only reviewed wire ciphertext/metadata, never decrypted bodies, previews, search copies or optimistic plaintext echoes.
- The current browser CI verifies WASM initialization, SDK stop/recreate, page reload key continuity and absence of the SDK event IndexedDB store. It does NOT prove cold browser reopen delivery/decryption of actual room sessions, Android behavior, or recovery after crypto storage loss. Those remain acceptance gates.
- Wire live/redaction/decrypted SDK events into the UI only after deletion metadata is loaded. Never render a known deleted event before server reconciliation. Clear visible plaintext and SDK-held references on logout/reconciliation; do not describe JavaScript garbage collection as forensic memory erasure.
- Do not fallback silently to the old P2P text transport when Matrix initialization, key trust or encryption fails. Show which protocol is active. Old ephemeral messages cannot be reconstructed retroactively.
- Existing generic Web Push contains no message body. Any later Matrix push bridge must retain this rule, mutual recipient permission, sender authorization and limits. No automatic Matrix push integration is present now.

## Rollout gates

- Android pair: fresh admission, exact device verification, restart/reload continuity, recipient fully closed during send, subsequent decrypt, one-side delete without other approval, deleting while the other is closed, next-open deletion reconciliation, changed-key/third-device/revoked-device rejection.
- Server: API logical redaction separate from active-row ciphertext rewrite. Measure multiple job phases, load and restarts, reporting sample count/p50/p95/max and >300s failures. A single synthetic <=300s result is not a guarantee. WAL/backups/snapshots/free pages/attachments/independent copies remain separately scoped.
- Resource/hosting: CI's 2 CPU/2 GB limits and one memory snapshot do NOT validate safe cohosting on the current NCP 1 CPU/1 GB/10 GB machine. Validate peaks, growth, disk limits and impact on current services separately. No server increase, extra cost or operational migration before explicit approval.
- Actual notification click/reopen and reconnect on both Android devices remains unverified.
