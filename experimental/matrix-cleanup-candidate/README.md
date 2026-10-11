# Inactive cleanup scheduler candidate

Pure source transformation only. No homeserver, database, network, production app or deployment integration. The existing stock retention failure remains a failure.

source-policy.mjs requires explicit synthetic opt-in, exact base-image digest and full official source SHA256. It changes only the pinned censorship scheduler from a delayed five-minute call to an immediate first call and thirty-second cadence, preserving all native validity/index checks and the 100-row cap. This private customization is not a supported configuration option or a 5-minute SLA.

source-policy.spec.mjs has nine source-integrity cases. The separate matrix-cleanup-source-check workflow extracts the source from the pinned image with no network inside the container, runs tests on Node22/Linux, generates only a temporary candidate file and parses its Python syntax. It does not execute that candidate or start Synapse. Source drift, failed extraction, tests or syntax are failures without fallback.

Local Windows Node26 module resolution was blocked by ancestor-path EPERM. Linux CI is a separate authorized environment, not expanded local filesystem permission. Local attempts never reached TAP; no local pass is claimed.

Runtime startup/index safety, native redaction authorization, 100/101-row load, restart latency, cache/API consistency and operational capacity remain unverified. See ../../docs/MATRIX_RESTART_CLEANUP_PLAN.md.
