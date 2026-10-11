# Restart cleanup: source-grounded next experiment

Status: source investigation and isolated Linux source checks complete. Candidate small control/clean/SIGKILL runtime pilots PASSED; broader safety, real101-row load, repeated-crash and power-loss validation remains incomplete. Existing retention run stays FAILED. No production/NCP changes or authorization.

## Verified v1.162.0 implementation

- [censor_events.py](https://github.com/element-hq/synapse/blob/v1.162.0/synapse/storage/databases/main/censor_events.py): CensorEventsStore registers _censor_redactions with Duration(minutes=5). It exits while the redactions_have_censored_ts_idx background update is incomplete, selects oldest eligible uncensored redaction rows, and limits each invocation to 100 rows. Native validity checks and original_event.internal_metadata.is_redacted() decide whether content is pruned. Zero retention changes eligibility, not the scheduling interval or batch cap.
- [clock.py](https://github.com/element-hq/synapse/blob/v1.162.0/synapse/util/clock.py#L155-L205): looping_call explicitly waits one full interval before the first call; looping_call_now starts immediately. Subsequent scheduling waits for the prior awaitable to finish. A fresh service startup therefore starts a fresh initial wait for this constructor-created loop, not a persisted per-message deadline.

This supplies a concrete restart-delay mechanism consistent with observed 343.659–545.165s cleanup upper bounds. It does not prove that scheduling was the only cause in the recorded run: index readiness, query/callback duration and queue depth were not separately measured. More than 100 eligible records can require multiple checks even without restart. Standard zero-retention configuration is not a strict 300000ms active-row guarantee.

## Minimal isolated candidate, not approved for operation

A pure, default-disabled source transformer and nine source-guard test cases are committed under experimental/matrix-cleanup-candidate (d2e03c0). The separate source-check workflow is committed at 3856e38. No operational server has been modified. The disposable CI image changes only the pinned scheduler expression:

- Old: looping_call(self._censor_redactions, Duration(minutes=5))
- Candidate: looping_call_now(self._censor_redactions, Duration(seconds=30))

The proposal pins the existing immutable Synapse image digest and official censor_events.py SHA256 6e995c5ddcc078f9ae099af8924ee2a2e40d2f5bf5349d148a1cfc7ad2030f2f, requires explicit synthetic opt-in, rejects changed/oversized/already-patched source, and requires reversible one-expression replacement. The entire native censorship body, 100-row cap, redaction validity checks and index gate remain unchanged. No direct SQL deletion, public endpoint, general history purge, trust bypass, batch-limit increase or operational wiring. Scope tags are not a security boundary; actual execution must remain confined to an isolated GitHub Actions fixture.

This is a private implementation customization, NOT a supported homeserver configuration knob. Startup safety and image-source correspondence must be proved, not assumed. Thirty seconds is a candidate cadence, not an SLA.

## Next gates, kept separate from the failed stock result

1. GitHub Actions-only source checks against the extracted immutable-image file, with hash mismatch failing closed. Run the nine source guards, compile the proposed Python, and prove no non-scheduler changes. No deployment or credential artifacts.
2. Disposable candidate image/compose override only, distinct from stock CI and production. Verify initialization, index-not-ready handling, no overlapping callbacks and no hidden fallback to stock cadence.
3. New bounded native SDK cases: restart with predefined pending ciphertext, API hiding after restart, 100/101-row queue boundary, repeated restart near the deadline, and original request/acknowledgement clocks unchanged. Do not reuse the old 35s pending precondition unchanged with a 30s timer; define and validate a new scenario before running. No convenient resampling.
4. Negative controls: unredacted encrypted messages remain unchanged; unauthorized and wrong-room redactions cannot erase them; policy-state redactions remain blocked by the ingress boundary. Cache/API/SDK display behavior must agree after cleanup.
5. Keep target at 300000ms, preserve confirmed misses and unknown boundaries, and record bounded callback/index/queue timing without event IDs, bodies, keys or tokens. Long outages and repeated restarts may still miss the target; never reset deadlines or claim unconditional guarantees.

## Resolved validation route and remaining local limitation

No local test pass is claimed. The earlier short Node test call reported file-not-found before any TAP output. A read-only probe confirmed the file exists. Switching from discovery to direct ESM loading produced EPERM on lstat C:\ at Node module resolution, before the test module ran. Both calls exited 1; no further retries or permission bypass. This identifies a local ancestor-path permission block. It does not retroactively explain the earlier daemon restart or exit 1223 cancellation.

The validation route is now working: [GitHub Actions source-check run 38123669253](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38123669253), commit 3856e38, succeeded in 25 seconds on Node22/Linux. It extracted the exact pinned-image source, passed all nine source guards (0 failures/cancellations/skips), generated a temporary candidate and passed Python syntax parsing with runtime_executed=false. Temporary source cleanup passed. This resolves the task validation blockage without expanding local filesystem permission; the local Windows EPERM limitation remains. The separately bounded candidate-runtime startup/ready-index/authorization pilot subsequently passed in run38124599670 (5ccf62d):3 control and3 pending-event clean restart samples. At that clean-restart stage it did not validate index-not-ready branches,100/101 batching or abrupt crash. The later mocked-unit and distinct SIGKILL evidence below narrows those gaps without validating real101-row load or production. Until runtime gates and operational approval, rollout, resource purchases, public staging changes and NCP deployment remain BLOCKED. WAL/backup/media/Android/human-OOB obligations remain unchanged.

## Runtime pilot follow-through

[Candidate evidence](../experimental/matrix-cleanup-candidate/RESULTS.md): run38124599670 passed six predefined active-row samples. Control upper bounds24.777–29.491s; clean-restart upper bounds2.979–3.043s. Existing stock restart miss results are preserved, not superseded as success. First candidate run38124400500 failed at a harness cross-room status expectation before sample registration; fixed using official pinned native error behavior without changing authorization.

Both jobs used the host-private internal Docker bridge; loopback publication stayed FAILED. The candidate source remains disabled outside explicit CI opt-in. No NCP or operating app configuration changed. The stronger terminal cleanup gate at614da25 passed in run38124904942 for both jobs, explicitly verifying private/build-directory and fixture-container absence. Its6/6 repeated functional samples passed:control24.928–30.044s; restart4.592–4.616s. Across the two successful pilots12/12 within300s, with no physical-erasure or SLA claim.

The installed-native fake-DB/clock cases now cover index-not-ready/retry and100/101 batching; three separate abrupt pending-event cycles passed in real encrypted runtime. Next bounded validation must separately exercise: (1) real database index-not-ready/ready integration; (2) real101 eligible-row/backlog load without altering the native100-row limit or weakening admission/rate limits; (3) repeated crashes of the same pending event, host power loss and exact boundary observations; (4) policy-regression reruns on the candidate composition, not only native direct-client paths. Any unit/fake-clock result must be labeled separately from real encrypted-client/native-database evidence. A load test that cannot accumulate101eligible rows under the unchanged policy must not disable policy or claim that boundary tested. Public staging, Android/human OOB, WAL/backups/physical deletion and NCP capacity still block rollout.

## Boundary and SIGKILL follow-through

Installed-native boundary run38125692435 (875a473) passed9/9 deterministic-clock/mock-DB cases but FAILED its real runtime stopped-volume probe, with1 pending sample and no confirmed300s miss. The helper omitted a user identity under owner-only directory permissions and dropped capabilities. Numeric CI_UID:CI_GID alignment at14ee899 retained all read-only/no-network/no-new-privileges restrictions; the suppressed original low-level exception is not a captured diagnostic.

Separate manually dispatched run38126060890 (14ee899) PASSED:9/9 mocked native cases and3/3 actual encrypted, pending-before/after-SIGKILL, exit137/non-OOM, same-container/same-volume recovery samples. Original clocks and300000ms target remained unchanged; conservative upper bounds5.077–5.136s,0 confirmed misses/boundary-unknown/pending. API/SDK hiding and encrypted sentinel preservation passed. Terminal gate verified private/build files and fixture containers absent, not physical erasure. Host-private internal bridge worked; loopback publication stayed FAILED.

These9 unit cases are not real SQLite101-row/index-transition evidence. These3 correlated functional crash samples are not an SLA, repeated-same-event crash test or host power-loss test. See the preserved failures, exact measurements and remaining gates in ../experimental/matrix-cleanup-candidate/RESULTS.md. Existing stock failure, public HTTPS/Android/human OOB, WAL/backups/physical deletion, production admission/ingress, NCP capacity, independent review and explicit approval continue to block operational migration. No NCP or operating-app configuration changed.
