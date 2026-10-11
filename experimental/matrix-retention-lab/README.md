# Synthetic deletion repetition, bounded burst and server restart

Status: implemented; GitHub Actions measurement pending. No production/NCP changes or approval.

## Fixed scope

`.github/workflows/matrix-retention-lab.yml` runs two separate ephemeral Ubuntu fixtures with pinned Synapse v1.162.0, SDK43 and the existing zero-redaction-retention configuration. Trial 1 is a no-restart control; trial 2 cleanly restarts Synapse on the SAME SQLite runtime volume after the predefined final cohort is still ciphertext-pending. Memory-only SDK workers remain alive. This is not Android/cold-client testing, broker admission, human SAS or an OS kill/power-loss test.

Each trial has 36 planned samples: three reciprocal single-message repetitions, a bounded 24-message burst with send concurrency four, and nine final control/restart-pending messages. The 24-message burst is modest characterization, not production load/capacity proof. Most peer redactions are by the non-admin, non-creator recipient; one reciprocal creator redaction is separate permission evidence. Every sample is real SDK Megolm ciphertext checked through API and active DB BEFORE ordinary peer redaction, followed by immediate empty-content/redaction-metadata API verification and SDK visible-body removal. Trial 2 requires all nine predeclared restart-cohort rows still pending before restart; no resampling or convenient cohort replacement is allowed. All 36 API events must remain redacted after restart.

Samples within a trial share a server timer and are correlated. These are not 72 independent latency trials, random phase coverage, multiple background cleanup cycles, or an operational SLA population. The new test does not replace the separately passed SAS/admission composition gates.

## Conservative clocks and strict outcomes

- Each sample records a monotonic timestamp BEFORE sending its redaction and another after worker HTTP/IPC acknowledgement returns. The former gives a conservative request-to-first-observed-scrub upper bound; the latter is a conservative acknowledgement bound for confirmed exceedance evidence.
- A fresh read-only SQLite snapshot queries all requested unique IDs in one batch. Ordered labels only are returned; no IDs, bodies, JSON, tokens or keys leave the probe. Missing rows, malformed/absent content, wrong types, empty ciphertext, truncated output and unknown statuses fail closed, never masquerade as scrubbed. No checkpoint, VACUUM, DB copy or mutation is used.
- The probe start is a conservative lower time for an observed encrypted row; the probe completion is the upper time for observed scrub. A completed upper bound <=300000ms proves this sample within the target. An encrypted observation at least 300000ms after coordinator-observed acknowledgement confirms a miss. Late scrub without such a lower-bound witness is boundary-not-proven, not a claimed exact breach.
- Compare unrounded raw durations. Poll approximately every second. Restart downtime/readiness/probe delays count; never reset sample clocks. All samples must be complete AND demonstrated within 300000ms to pass. Eventual scrub cannot turn an earlier confirmed miss into a pass.
- Observation may continue to 390 seconds after the last acknowledgement for diagnostics, but the acceptance target stays 300 seconds. Timings summarize completed upper bounds only; pending/censored/confirmed-miss counts are explicit and must be read alongside percentiles. They are not production p95 estimates.

Synapse documentation describes a roughly five-minute background check even with `redaction_retention_period:0`: https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#redaction_retention_period . A restart could shift background scheduling; this test measures behavior without presuming the outcome or changing the interval to obtain a green result.

## Privacy, cleanup and remaining blocks

Pure clock regressions and strict Python probe regressions run first. The job reports only fixed gate/scenario labels, counts, bounded flags, timings and transport class. SDK/private exceptions, HTTP bodies, event/user/device identifiers, credentials, traces and screenshots are suppressed. No sensitive artifact uploads, GitHub secrets context, cloud/SSH credentials, deployment actions or NCP access. Runtime/config/profiles remain CI-local and cleanup always tears down the fixture; ephemeral-runner destruction is the fallback, not physical erasure evidence. Two jobs run in parallel, each bounded to 18 minutes; driver bounded to 850 seconds.

The measured property is active logical SQLite `event_json` rewrite ONLY. WAL/journals/free pages, disks, backups/snapshots/replicas, restore/redaction replay, media attachments, client exports/captures and notifications are not physically erased or validated here. A positive result still cannot authorize rollout. A target failure must remain a failure and hold the 5-minute operation gate. Public HTTPS, real Android two-phone/human SAS, attachment/WAL/backup policy and safe 1-vCPU/1-GB NCP cohosting remain blocked. No capacity purchase or production wiring is authorized.
