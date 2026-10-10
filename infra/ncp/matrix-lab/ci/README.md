# Synthetic real-server CI, not deployment

Status: authored and statically checked; NO real-server result obtained locally. New workflow only. Earlier lab and production/development workflows are unchanged.

The GitHub Ubuntu runner pulls official `matrixdotorg/synapse:v1.162.0`. Parent verified release v1.162.0, released 2026-09-29, through https://api.github.com/repos/element-hq/synapse/releases/latest. The workflow must still prove that this official registry tag pulls. Only its public RepoDigest is emitted by the pull step. The tag is NOT a measured digest pin: no digest value was invented or committed. Dependencies use the existing experimental package, exact matrix-js-sdk 43.0.0, Node22.

Server is bound only to host 127.0.0.1:18008 on an internal Docker network, with 2 CPU / 2GB limits appropriate to an ephemeral runner, not proof of production capacity. Synthetic shared-registration secret/passwords/macaroons/form secrets are random, never output. Runtime directory/config files are owner-only and ignored, container runs under the runner UID/GID. App logging, access logging, Docker log retention and worker SDK logs are discarded. SDK errors are reported only by fixed gate labels. No secrets context, cloud identity, SSH/NCP configuration or deployment actions are used. Checkout does not retain credentials. Package/image downloads in CI are intentional; no locally initiated CI run or deployment is part of this change.

## Assertions implemented, results required from CI

- Server becomes ready; both synthetic users are confirmed non-admin by read-only DB query.
- One device per user; direct out-of-band Ed25519 and Curve25519 public keys captured from each worker's `getOwnDeviceKeys()` are compared against the exact user/device from `getUserDeviceInfo()` before `setDeviceVerified()`. Unexpected devices or mismatched keys fail. Unverified devices are blacklisted, cross-signature trust disabled. This is synthetic in-process OOB verification ONLY, not SAS UX, production P256 trust, or arbitrary-device auto-verification.
- Private invite-only room, `m.federate:false`, joined history, Megolm encryption, guest access forbidden. Both ordinary users have room-level redaction permission (`redact:0`); only creator controls state/invites. Bob is neither server admin nor room admin and may redact Alice's message without sender approval. Reciprocal Alice redaction is also asserted.
- Recipient subprocess is actually SIGSTOPped (Linux `/proc` reports stopped state), encrypted message is sent while it cannot run or sync, SIGCONT resumes it, next sync receives/decrypts the message. Ciphertext is independently checked through server API and active SQLite row.
- Alice subprocess is then stopped; Bob redacts Alice's event. Immediate API logical redaction is checked separately. Alice resumes and removes the event's visible body after next sync; Bob also observes redaction.
- Read-only SQLite probe polls the active `event_json.json` row every 500ms until encrypted content becomes `{}`, failing if missing/unexpected or elapsed time exceeds 300s since successful redaction acknowledgement. Probe emits only encrypted/scrubbed/error flags, never JSON, message bodies, identifiers, keys or tokens. Successful result emits fixed gate names/timing/count only.
- Job <=15 minutes, integration step <=11 minutes, internal hard deadline 650 seconds. Workers are continued/terminated in finally. `always()` cleanup stops/removes Compose resources and deletes only fixed CI runtime directory. Hard runner termination can prevent cleanup steps; GitHub ephemeral runner destruction is the fallback, not physical erasure evidence.
- One resource snapshot reports container memory/CPU/block I/O, OOM state, synthetic directory size and available runner disk. It is NOT peak tracking, sustained load evidence or NCP sizing.

## Critical stopped-client limitation

SDK43 `stopClient()` stops the Rust backend and closes its OlmMachine. With `useIndexedDB:false`, recreating the client loses device private keys and crypto state. This test therefore uses genuine operating-system process suspension/resume while preserving memory; it DOES NOT claim `stopClient()` followed by cold recreate/page reload, persistent-device continuity, or a production offline-client lifecycle. SDK `stopClient()` occurs on final cleanup only. No room-key export/import cheat or key injection is used to pass decryption. Browser IndexedDB stop/recreate/reload testing is separately owned by the frontend harness. Actual room-session delivery/decryption after browser cold reopen remains a separate gate.

## Deletion scope and untested gates

`redaction_retention_period:0` requests background replacement at the documented roughly five-minute cadence. Retention purge jobs are a different mechanism and remain disabled. This is a single <=300s sample, not a latency SLA: heavy load, backlog/restarts and phase alignment can exceed the target. CI must report the measured timing; boundary failures must remain failures, not be softened to a guarantee.

API logical redaction can precede stored row replacement. The DB check verifies active logical row rewrite, NOT forensic physical erasure: old ciphertext may remain in SQLite WAL/journals/free pages, snapshots, backups, replicas, media blobs, client caches/exports or captured notifications. No backups/media or production database are used. Encrypted backup retention/destruction, restores with redaction replay, attachment deletion, PostgreSQL WAL/PITR and production client cache clearing require independent design and tests.

Still untested until actual CI: image pull/digest, server startup/config settings, SDK runtime/decryption, device publication timing, shared-secret inhibit_login behavior, actual redaction authorizations, API behavior, active row scrubbing <=300s, resume sync and effective logging/isolation. Only loopback publication and internal-network settings are structurally checked; no LAN/federation/egress penetration test is claimed. Two-device counts here do NOT enforce production third-device rejection. Persistent cold reopen, secure enrollment/revocation, load p50/p95/max, production sizing, attachment/backup deletion and NCP hosting are out of scope.

Local static checks: Docker Compose `config --quiet` passed without starting containers; Node22 `--check` passed for both .mjs files. Python execution/syntax compilation and workflow execution were not performed locally. Do not run this workflow automatically against real services or add secrets.

## Official references

- https://github.com/element-hq/synapse/blob/v1.162.0/docker/README.md
- https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html
- https://element-hq.github.io/synapse/latest/admin_api/register_api.html
- https://github.com/element-hq/synapse/blob/v1.162.0/synapse/rest/admin/users.py
- https://github.com/matrix-org/matrix-js-sdk/blob/v43.0.0/src/client.ts
- https://github.com/matrix-org/matrix-js-sdk/blob/v43.0.0/src/crypto-api/index.ts
- https://github.com/matrix-org/matrix-js-sdk/blob/v43.0.0/src/rust-crypto/rust-crypto.ts
- https://github.com/matrix-org/matrix-js-sdk/blob/v43.0.0/src/models/device.ts
- https://spec.matrix.org/latest/client-server-api/
- https://sqlite.org/wal.html

## Readiness diagnosis follow-up

Parent reported real-server run 38053498391 failed at readiness after ~90s while container remained alive (126.6MiB, no OOM, synthetic directory 3296KiB). Those observations do NOT prove endpoint availability or networking cause. The next revision probes the exact unauthenticated `/_matrix/client/versions` endpoint independently at runner loopback and container-local loopback, emitting ONLY HTTP status and allowlisted connection error codes. No response bodies, raw exceptions, headers or server logs are emitted.

Official v1.162.0 `synapse/rest/client/versions.py` matches `^/_matrix/client/versions$`; `synapse/app/homeserver.py` wires it under the `client` listener resource. The existing client-only listener configuration is therefore not changed speculatively.

Only if container-local endpoint returns 200 and published host-loopback does not, the harness inspects this job's exact `matrix-server-integration_offline` network, requires `Internal=true` and `Driver=bridge`, obtains this service's RFC1918 IPv4 address, and separately probes it from the runner. If that also returns 200, both harness and SDK workers use the host-reachable private bridge path. Docker's official bridge documentation describes host access to its own user-defined bridge containers: https://docs.docker.com/engine/network/drivers/bridge/ . No network is added, internal isolation is not disabled, and no new public port/bind is created. No arbitrary URL override is accepted by the transport selector.

This fallback is evidence-driven in that CI run, not a claim that Docker networking caused the first failure. Its report explicitly marks `loopbackPublicationVerified:false`, prints `loopback_publication_gate=FAILED`, and labels transport as private internal bridge. Passing message/redaction gates through that path must not be reported as passing published-loopback reachability. If container-local status is not 200, there is no transport fallback. If both host paths fail, readiness remains blocked with sanitized diagnostic output. Effective LAN/egress isolation and the original failed-run root cause remain unverified.
