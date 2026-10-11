# Inactive cleanup scheduler candidate

The source-policy module is pure and default-disabled. The separate runtime pilot explicitly opts in only inside disposable GitHub Actions fixtures; no production app or deployment integration. The existing stock retention failure remains a failure.

source-policy.mjs requires explicit synthetic opt-in, exact base-image digest and full official source SHA256. It changes only the pinned censorship scheduler from a delayed five-minute call to an immediate first call and thirty-second cadence, preserving all native validity/index checks and the 100-row cap. This private customization is not a supported configuration option or a 5-minute SLA.

source-policy.spec.mjs has nine source-integrity cases. The separate matrix-cleanup-source-check workflow extracts the source from the pinned image with no network inside the container, runs tests on Node22/Linux, generates only a temporary candidate file and parses its Python syntax. It does not execute that candidate or start Synapse. Source drift, failed extraction, tests or syntax are failures without fallback.

Local Windows Node26 module resolution was blocked by ancestor-path EPERM. Linux CI is a separate authorized environment, not expanded local filesystem permission. Local attempts never reached TAP; no local pass is claimed.

Runtime startup/index safety, native redaction authorization, 100/101-row load, restart latency, cache/API consistency and operational capacity remain unverified. See ../../docs/MATRIX_RESTART_CLEANUP_PLAN.md.

## Bounded runtime pilot (not yet run)

Candidate.Dockerfile verifies the original module hash again and reversibility of the single scheduler substitution. The image is built without network and never pushed. Runtime CI reuses the unchanged private internal network, ordinary accounts, memory-only SDK, exact synthetic-key verification, fail-closed room checks, suppressed service logs and read-only SQLite probe. A runtime hash confirms the installed source matches the generated candidate.

Two fresh-fixture jobs run three reciprocal samples each. The restart job requires the selected ciphertext row to remain encrypted before each clean service restart, retains the original request/ack clocks and checks API hiding after restart. These are three separate pending-event restart cycles, not multiple rapid restarts of the same event or a power-loss test. Both jobs check a nonmember request is rejected and an untouched/cross-room-target sentinel retains identical ciphertext and remains decryptable after native ticks. A cross-room request may be accepted as an event while leaving its target unchanged; acceptance is not reported as rejection.

The existing 300000ms conservative acceptance target is unchanged. A separate 90000ms per-sample functional observation budget fails early if still pending; that is NOT evidence of a confirmed 5-minute miss. The job deadline is bounded. Source tests and probe/clock regressions run before any server starts. Private files and public build files are always removed, with no trace, screenshots, credential logs or artifact uploads.

This pilot cannot establish fresh-index not-ready branches, 100/101 batching, sustained load, WAL/backup/physical erasure, Android, human OOB verification, production ingress/admission or NCP capacity. The stock retention failure remains unchanged. No runtime pass is claimed until the separate CI result is inspected.
