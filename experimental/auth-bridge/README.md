# Disabled-by-default Matrix admission lab

Standalone development code only. No production auth import, HTTP route, frontend integration, NCP deployment or capacity purchase. Existing P2P/push behavior is unchanged. Not a security sign-off.

## New prevention stage

See [PREVENTION.md](PREVENTION.md) for the supported pre-login device veto, no-published-port private backend, default-deny read-only client ingress, latest-session lease and dedicated durable revocation coordinator. Current workflow selects `ci-policy.mjs`; historical `ci.mjs` remains the previous reactive-only fixture. Full Matrix key/message/SAS routes and production HTTP wiring are still closed/not implemented. New server CI must be checked separately before claiming prevention success.

## Initial implemented scope

- `MatrixAdmissionBroker` defaults to disabled. An enabled lab requires exactly two operator-selected enrolled device IDs and `matrix.lab` or `matrix.ci` server name.
- Fresh one-use `direct-matrix-auth-v1` challenge binds enrolled P-256 public-key fingerprint, device and peer. Reuses the existing auth cryptographic verifier, NOT legacy signal/push credentials or challenges.
- Private atomic store commits opaque Matrix user ID, fixed Matrix device ID and server-only provisioning password BEFORE network provisioning. Broker restart reuses that identity. Store is for ONE broker/store/process only, with POSIX file mode 0600; Windows ACL protection and crash/power-loss directory-fsync guarantees are not validated.
- Ordinary non-admin account creation plus password login with fixed device ID. No administrator impersonation login: v1.162.0 documentation explicitly says that API creates no device.
- Session grants require actual positive bounded `expires_in_ms`, matching login + whoami user/device and exactly the one expected Matrix device. Deadline is conservatively anchored before the login request, not extended by later validation work. Missing/indefinite expiry fails closed. Account provisioning preserves existing device sessions (`logout_devices:false`).
- Response contains only own user ID/device ID/access token/deadline and `keyVerified:false`; account password and administrator token stay server-side. Token must stay in client memory and must never be logged.
- Revocation first persists a deny/tombstone, then deactivates the mapped account. Failures leave cleanup pending and grants blocked; retry is internal/operator-only. Deactivation is token/device access revocation, NOT erasure of messages, local keys or copies.
- Unexpected Matrix device discovery quarantines the account and requests full account-session revocation. This is REACTIVE DETECTION, NOT prevention of direct Matrix extra-session/device creation.

## Historical phase-one tests and disposable server CI

Current Node suite: `node --test experimental/auth-bridge/broker.spec.mjs experimental/auth-bridge/issuer.spec.mjs experimental/auth-bridge/policy.spec.mjs`. Native module tests run inside the pinned Synapse container.

35 unit tests cover enrollment/signature/purpose/device binding, nonce replay/expiry, fixed identity across restart, durable provisioning intent, password omission, bounded lifetime, latency, unexpected devices, revoked enrollment, cleanup retry and concurrent challenge capacity. These unit tests use synthetic fake issuers, not Synapse or real Android.

`Matrix admission lab` starts the existing digest-pinned Synapse v1.162.0 internal-network fixture with **CI-only 1 CPU / 512 MiB** override and 10-minute session lifetime. Real server gates use the ORIGINAL auth Store's hashed 8-digit 30-minute one-use invitation enrollment, fresh P-256 proofs, fixed-device login, bounded expiry, restart identity continuity, non-admin accounts, extra-device reactive quarantine and all-token revocation. Logs expose only fixed gate labels/statuses; generated credentials/runtime are removed and never uploaded as artifacts.

Observed real-Synapse run #1 succeeded on 2026-10-11 Asia/Seoul at commit `a4e84a8`: https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38086157931 . All seven listed admission/revocation gates passed; the 35 unit tests passed locally and in this workflow. Resource observation was 139.3 MiB / 512 MiB, CPU 0.78%, OOM=false at ONE sampled instant, not a peak/load/soak/cohosting measurement. The published loopback probe failed; only the inspected private internal Docker bridge returned 200 and carried these server tests. This fixture does NOT wire production `/v1/register`, `/v1/challenge`, `/v1/session` HTTP routes, implement Matrix E2EE/SAS, or test cold message reopen. The published loopback path may still fail and the readiness helper may use the inspected private internal Docker bridge.

## Mandatory remaining gates

1. Server-side prevention of ALL unauthorized accounts/devices/session/token-login/dehydration/re-registration paths; signup-off or this broker's two-ID allowlist alone is not enforcement. Coordinate enrollment revocation + Matrix revocation under a durable shared lifecycle boundary; standalone callbacks are not a distributed atomic guarantee. Add bounded private cleanup retries and request/rate limits before exposing HTTP routes.
2. Trusted two-member encrypted room provisioning/policy and explicit Matrix SAS/key verification. Existing P-256 safety code is not Matrix verification. Receive/render reject untrusted/unknown sender devices, unencrypted events and tampered ciphertext. No silent P2P fallback.
3. Real browser cold close/reopen + actual room key/session decryption, offline delivery, deletion reconciliation, storage loss/new-device handling and both Android acceptance.
4. Repeated deletion/load/restart measurements and WAL/backup/snapshot/attachment policy. Prior ~296-second single active-row rewrite is not a 300-second guarantee.
5. Resource peaks/disk growth/current-service impact on the 1 CPU/1 GiB/10 GiB NCP host and explicit rollout approval. A constrained synthetic auth fixture is NOT safe cohosting proof.

Official pinned reference: https://github.com/element-hq/synapse/blob/v1.162.0/docs/admin_api/user_admin_api.md (ordinary user create/update, device deletion token invalidation, account deactivation, administrator login without a device). Session binding/expiry must be established from real selected-version behavior, not assumed from the documentation.
