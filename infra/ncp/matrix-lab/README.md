# Standalone Matrix lab (NOT TESTED AT RUNTIME)

Development scaffold only, not a deployment or application migration. No existing compose, Caddy, authentication, app, or cloud configuration is used or changed. Run only on an isolated local development machine with Docker Linux containers and PowerShell 7. Never run this on the existing NCP 1 CPU / 1 GB RAM / 10 GB disk host: safe cohosting of Synapse is unproven. Limits here are guardrails, not evidence that 768 MB is adequate. Docker images/data can exhaust 10 GB. No cloud resources, paid services, TLS/DNS setup, or automatic downloads are involved.

## Version-selection gate (required)

No image version is claimed verified or pinned in this scaffold. Before execution, inspect the official [stable releases](https://github.com/element-hq/synapse/releases) and [official registry](https://hub.docker.com/r/matrixdotorg/synapse/tags). Select a supported non-prerelease vX.Y.Z tag, check its platform support and security notes, and record its matching registry SHA256 digest and verification date privately. Recheck all settings against that release's official docs/source. Copy .env.example to .env and replace the placeholders with matrixdotorg/synapse:vX.Y.Z@sha256:<64 lowercase hex digits>. The bootstrap rejects latest, RC, unpinned, and placeholder values. Compose requires a value but does not itself validate stable provenance; run bootstrap first. Do not bypass the gate.

Image must already be cached on the local workstation. If not, an operator may explicitly download the verified image after reviewing network/disk costs; these scripts never pull (pull_policy: never / --pull never). Offline operation assumes this cache is available. Official Synapse Docker documentation describes this image repository and generate mode; it does not establish a current stable tag for this artifact.

## Generate only

From this folder:

~~~powershell
Copy-Item .env.example .env
# Privately edit .env after the version-selection gate.
pwsh -NoProfile -File ./bootstrap.ps1
~~~

Bootstrap only runs the official image's generate command with no network, no ports and no Docker logging, then renders the bounded configuration and random secrets in ignored generated/. It refuses an existing generated/ directory, never starts Synapse, never creates accounts, and never prints generated secrets. A failed run can leave generated files; do not blindly rerun or delete actual lab data. Original generator output may include an unused matrix.lab.log.config; only /data/log.config is referenced. Protect generated/ with local filesystem permissions/ACLs, keep out of sync folders/backups unless explicitly managed, and do not commit it. Secrets are not supplied on command lines. Host ACLs and Docker bind-mount ownership (991:991) require verification on the chosen workstation.

## Manual validation and local start (not performed here)

~~~powershell
docker compose --env-file .env -f compose.yaml config --quiet
# Validate without starting a server. Output is deliberately suppressed.
docker compose --env-file .env -f compose.yaml run --rm --no-deps --entrypoint python synapse -m synapse.config -c /data/homeserver.yaml *> $null
if ($LASTEXITCODE -ne 0) { throw 'Synapse config validation failed; inspect privately without dumping secrets.' }
docker compose --env-file .env -f compose.yaml up -d --pull never
Invoke-RestMethod http://127.0.0.1:18008/_matrix/client/versions
docker compose --env-file .env -f compose.yaml ps
# Later stop, without deleting data:
docker compose --env-file .env -f compose.yaml down
~~~

Only host 127.0.0.1:18008 is published. Container 0.0.0.0:8008 is needed for port forwarding and is not a public host bind. The internal Docker network is an additional egress barrier, not an audited sandbox: test actual egress and LAN denial on the chosen Docker platform; host/local processes and an administrator can still access the lab. No federation listener, host networking, external networks, proxy, public endpoint, or 8448 port is configured. Do not expose the local HTTP port or tunnel it publicly. Physical phones cannot access host loopback: real two-phone validation needs a separately reviewed HTTPS/private-network staging design, not a changed lab bind.

Public signup and guests are disabled. For local synthetic accounts only, use the official interactive operator tool (password prompt, never -p or a real reused password):

~~~powershell
docker compose --env-file .env -f compose.yaml exec synapse register_new_matrix_user -c /data/homeserver.yaml http://localhost:8008
~~~

The generated registration_shared_secret enables privileged operator registration despite public signup being disabled. Do not share it. After provisioning only the intended test accounts, remove that single line from the ignored generated/homeserver.yaml and restart Synapse. No account or password is provisioned by bootstrap.

## Verified settings and boundaries

Official current [configuration manual](https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html) and [Docker instructions](https://github.com/element-hq/synapse/blob/develop/docker/README.md) were inspected while authoring. They are rolling references, not proof of selected-image runtime compatibility.

| Concern | Lab setting / meaning |
| --- | --- |
| Public signup | enable_registration: false; enable_registration_without_verification: false; allow_guest_access: false. Operator shared-secret registration is a separate bypass, as documented. |
| Federation | federation_domain_whitelist: [] is the documented recommended federation disable setting. A client-only listener excludes federation resource routes. trusted_key_servers: [] prevents default trusted-key-service use, but by itself is not a federation disable switch. Isolated network is defense in depth. |
| Invite-only | Federation off is NOT invite-only membership. Create room with visibility: private, preset: private_chat, creation_content: {"m.federate": false}, and m.room.join_rules content {"join_rule":"invite"}; verify state. Do not publish aliases/directories or permit guest joins. Set invite power level to room-admin-only if needed. |
| Two devices | This scaffold does NOT enforce a two-device limit. Preserve the approved app enrollment/revocation policy during future integration; server signup-off and room invites do not cap Matrix device IDs or sessions. A third-device rejection test is a mandatory blocker before rollout. No existing auth/app policy was changed. |
| Logging | log_config points to Python logging NullHandler with propagation disabled for synapse/access/twisted and no console/file handlers. Docker driver none discards stdout/stderr retention too. No access logs or verbose/sensitive/debug logging. Operational visibility is intentionally absent; test selected-image startup and subprocess logging before calling privacy verified. |
| Storage | SQLite is dev-only; official docs recommend PostgreSQL for production. No PostgreSQL production topology or credentials are created here. |
| Redaction | redaction_retention_period: 0 requests replacing unredacted event JSON with its redacted form in live DB at next background pass, documented every five minutes. It is not deletion of the event envelope, room state, backups, media or clients. |
| Purge cadence | retention.purge_jobs schedules expiry-based message-retention purges, a DIFFERENT mechanism. retention is disabled; setting interval: 5m there would not tune redaction processing. No undocumented redaction-job interval setting was invented. |

Default E2EE is not established by this server scaffold. Create the lab room with m.room.encryption {"algorithm":"m.megolm.v1.aes-sha2"} and verify client encryption/key trust before sending synthetic messages. Invite-only room membership is independent of encryption. Official [Matrix client/server spec](https://spec.matrix.org/latest/client-server-api/) documents room creation, invite join rules, encryption, redactions, device management and sync.

## Approved deletion semantics and required measurement

Immediate logical redaction means after an authorized redaction has been accepted and propagated, not an instantaneous distributed guarantee. Online clients process redactions on sync; offline clients reconcile on their next successful sync. The application must remove decrypted text, local caches, notification previews, search copies and attachment references on reconciliation. It cannot retroactively erase screenshots, exports, malicious clients or independently copied content.

Target: live-server ciphertext content cleanup <= 5 minutes after accepted redaction. This is a measurement target, NOT a guaranteed SLA. Synapse documents a five-minute background check even at zero retention; queueing, stalled jobs, load, restart, clock skew and database transactions can exceed the target. Retention purge jobs do not fix this. Do not change Synapse internals in this scaffold.

Required acceptance test using synthetic E2EE events and no secrets/body logging:

1. Verify signup/guest rejection; confirm client versions responds, federation route is unavailable, remote membership fails, LAN endpoint inaccessible and container cannot egress. Verify room invite-only/unfederated/encrypted state, unauthorized join rejection and only intended identities/devices. Confirm third-device policy through future app enforcement.
2. Run two clients, leave one offline, send an encrypted event, record only synthetic event identifier and timing locally. Confirm storage is m.room.encrypted, not plaintext.
3. Redact with the authorized sender/admin. Timestamp successful server acknowledgement and online client hiding. Verify content is redacted via event/history reads; verify unauthorized redaction rejection separately.
4. Using a private read-only DB connection, poll the synthetic event's event_json.json content to measure when encrypted payload fields disappear from live logical storage. Report elapsed duration only, not tokens/keys/ciphertext/body. Match schema and redacted-field behavior to the selected release's source. An API read alone cannot prove database cleanup because Synapse may redact on read before stored JSON replacement. Do not mutate live DB or dump entire tables.
5. Repeat across background-job phases, idle/load/restarts and enough events to report sample count, p50/p95/max and failures >300s. Document offline duration, reconnect, and removal of decrypted local caches after next sync. Media/attachments require separate deletion and measurements, not just event redaction.
6. Measure CPU/RAM/disk growth and OOM/job delays on a separate environment. No production/cohosting recommendation until this evidence and independent privacy/security review exist.

## Not forensic erasure; backup policy required

Redaction does not erase historical backups, snapshots, replicas, client databases, exported logs, crash dumps, media blobs, disk free pages, SQLite rollback journals or WAL copies. SQLite WAL is a separate persistent history of changed database pages: [official WAL documentation](https://sqlite.org/wal.html). Do not delete a live WAL manually; it can be required for database correctness. PostgreSQL WAL/archives and PITR backups have the same separately managed retention concern; see [official PostgreSQL continuous archiving](https://www.postgresql.org/docs/current/continuous-archiving.html).

No backups are configured here. Before any production use, define encrypted backup/replica lifecycle, access control, retention/deletion SLAs, restore procedure that replays pending redactions before serving data, and test expired-copy destruction including snapshot/WAL archival copies. Live DB replacement <=5m does not promise backup or physical-sector erasure. Use disposable synthetic data only in this lab. Separate attachment deletion, crypto-key/cross-signing backup handling and client cache cleanup need explicit design. No automatic purge/destructive cleanup command is provided.

## Actual validation status / blockers

Only authoring-time static checks were performed: official docs/source inspection; PowerShell AST parsing; content/boundary checks. Docker is unavailable here, so no image was fetched, no bootstrap/Compose/Synapse config parser ran, no server started, no accounts or real credentials were generated, and no networking/redaction timing/resource behavior was measured. The image-selection gate remains open. Runtime compatibility, bind permissions, effective logging/network isolation, E2EE clients, two-device enforcement, media/backups, <=5m measurements, PostgreSQL production sizing and separate hosting remain blockers. This is not release-ready and does not migrate the current app.
