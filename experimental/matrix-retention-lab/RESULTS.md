# Deletion retention result: rollout blocked

## Evidence

[Actions run 38109336061](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38109336061), commit 46f8ad7. Overall result: FAILED.

| Separate synthetic fixture | Samples | Within 300000ms | Confirmed misses | Eventually scrubbed | Observed upper-bound range |
| --- | ---: | ---: | ---: | ---: | --- |
| No-restart control | 36 | 36 | 0 | 36 | 95.496–296.960 seconds |
| Clean Synapse restart, same SQLite volume | 36 | 0 | 36 | 36 | 343.659–545.165 seconds |

Control upper-bound median: 180.354s; p95: 295.902s. Restart upper-bound median: 428.190s; p95: 544.191s. These are descriptive statistics for correlated samples, not population SLA estimates or exact scrub timestamps. Both fixtures have zero pending and zero boundary-not-proven outcomes.

The restart fixture passed ciphertext prechecks, ordinary peer redaction/API hiding, same-volume restart with all nine predeclared restart-cohort rows pending, and API hiding for all 36 events after restart. Downtime was 4341ms and counted in the original clocks. Confirmed misses require ciphertext observations at least 300000ms after acknowledgement; eventual cleanup cannot reverse them. Only the final nine rows were required pending immediately before restart, not all 36.

Both jobs used the job-owned private internal bridge after loopback publication failed. This does not validate public HTTPS or production ingress. No cleanup interval, acceptance threshold, or security policy was relaxed.

## Decision and limits

The 5-minute active-row cleanup gate remains BLOCKED. API hiding survived this clean restart, but that does not establish universal immediate blocking or a production SLA. A timer shift is a hypothesis, not a confirmed sole cause. Investigate restart-resilient cleanup in the synthetic lab before any operational proposal.

This measures logical active SQLite event_json rewrite only. Physical media, WAL/journals/free pages, backups/snapshots/replicas, restore/replay, attachments, exports/captures and Android remain unverified. No NCP changes, resource purchase, production wiring or rollout approval.

## Interrupted local execution and separate browser regression

One local shell call was explicitly interrupted by an execution-tool server restart. The later regression command returned exit code 1223 with no test output; the cancellation source is not established. Subsequent read-only process inspection found no remaining Node process, and node --version returned v26.5.0 normally. These observations do not prove the interrupted local tests passed or identify a test deadlock. Do not repeatedly rerun the same command without a new diagnosis.

The already-committed e316000 patch waits for the actual joined SDK room before strict authoritative validation; it does not fabricate state or alter trust. [Browser CI #18, run 38120484114](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38120484114) passed the regression step and all eight synthetic browser gates, including whole-process cold reopen, offline decryption, deletion non-resurrection and crypto-loss re-verification. The prior failure reported a missing SDK room despite persisted peer verification. This successful CI is not the interrupted local execution, Android, human OOB comparison, production admission or physical erasure evidence.
