# Candidate runtime pilot evidence

Scope: disposable GitHub Actions only, no NCP or production integration. This is an unofficial scheduler customization, not a supported configuration or SLA. Original stock retention workflow 38109336061 remains FAILED.

## Source and image chain

Source-only run 38123669253 (3856e38) passed 9/9 guards and Python syntax without executing the candidate. Runtime image/driver preparation: 36b0a0e; separate runtime workflow: d8cfbe3; exact negative-response check: 5ccf62d. The pilot repeats source and clock/probe regressions before starting any server, builds a non-published no-network image and verifies its installed module hash at runtime. The native censor body, index gate and 100-row limit are unchanged.

## First runtime attempt, preserved failure

[Run 38124400500](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38124400500) failed. The inspected restart job reached candidate startup, installed-source hash and fresh-database index completion. It stopped at negative controls before registering any measurement sample: nonmember redaction returned 403, cross-room redaction returned 400, while the initial harness wrongly excluded 400. This was a harness expectation failure, not a measured 300-second cleanup miss. It was not blindly rerun.

Official v1.162.0 [message.py](https://raw.githubusercontent.com/element-hq/synapse/v1.162.0/synapse/handlers/message.py) raises SynapseError(400, fixed cross-room message); [errors.py](https://raw.githubusercontent.com/element-hq/synapse/v1.162.0/synapse/api/errors.py) defaults its code to M_UNKNOWN. The fix checks exactly HTTP400 + M_UNKNOWN + equality to the public fixed error string, logging only a boolean, never response text. Any unrelated 400 fails. Nonmember rejection still requires a matching forbidden/not-found status/code. Native authorization was not altered.

## Second runtime attempt

[Run 38124599670](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38124599670), commit 5ccf62d. Separate fresh-fixture control/restart jobs; three predefined reciprocal ciphertext samples each. Request and acknowledgement clocks never reset across restart. SQLite probes are read-only, accept only encrypted/scrubbed states and measure a conservative request-to-first-observed-scrub upper bound. Acceptance remains 300000ms. A separate 90000ms early observation budget is not evidence of a confirmed five-minute miss if a sample is still pending.

Restart job inspected: PASSED, 3/3 scrubbed within target, 0 misses/boundary-unknown/pending. Upper bounds min2979.485071ms, p50 3016.860698ms, max3043.393327ms. Clean same-volume restart downtime: 2659,2693,2705ms. Three separate pending-event restart cycles, not repeated rapid restarts of one pending event or SIGKILL/power loss. API hiding remained after each restart; both SDK views were redacted after observation.

Nonmember response: 403/M_FORBIDDEN. Cross-room:400/M_UNKNOWN with exact fixed-message match. Untouched/cross-room-target sentinel remained an identical encrypted content object in API and encrypted in active SQLite after native ticks, and recipient SDK could still decrypt it.

Control job inspected: PASSED, 3/3 scrubbed within target, 0 misses/boundary-unknown/pending. Upper bounds min24777.063871ms, p50 29385.808485ms, max29491.088925ms. No restart scheduled. Nonmember/cross-room exact rejection and sentinel preservation gates passed. Whole run completed successfully in2m33s (control job2m31s, restart job1m21s).

## Transport and limitations

All inspected runtime probes used the host-private INTERNAL Docker bridge. Container-local/private-bridge HTTP200 passed; host loopback publication remained FAILED/ECONNREFUSED, explicitly logged. A pilot pass is not a public/staging/network-publication pass.

These twelve completed samples across two runs/four fresh fixtures are a small correlated synthetic functional pilot, not a stock-vs-candidate matched randomized comparison, broad reliability evidence or an SLA. Fresh-index not-ready branches, 100/101 batching, sustained load, same-pending-event repeated restarts, abrupt crash, WAL/backup/snapshot/attachment/physical erasure, Android, human OOB, production ingress/admission wiring and NCP capacity remain unverified. Exact synthetic key comparison is not human SAS. No traces, screenshots or secret artifacts are collected by CI; fixture cleanup was invoked in run#2, but its legacy always-success shell block did not independently prove removal. The stronger terminal gate was subsequently verified in run#3.

## Third attempt: explicit teardown verification

[Run38124904942](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38124904942), commit614da25, repeated the unchanged six-sample pilot specifically to verify the new terminal cleanup gate. Both jobs PASSED. The gate now propagates Docker teardown/remove/verification failures, checks runtime and public build-directory absence, and checks absence of containers with the exact fixture project label. Both job logs explicitly contain fixture_cleanup_verified=true; private_files_absent=true; fixture_containers_absent=true. This means fixture filesystem unlink/container cleanup, not physical media erasure.

| Run | Scenario | Within300s | Conservative upper min / max (seconds) |
|---|---|---:|---:|
|38124599670|control|3/3|24.777063871 /29.491088925|
|38124599670|clean restart|3/3|2.979485071 /3.043393327|
|38124904942|control|3/3|24.928479777 /30.043590443|
|38124904942|clean restart|3/3|4.592066118 /4.616042478|

Third-run clean restart downtime:4123,4136,4143ms. Negative-control, post-restart API hiding and final SDK redaction gates passed again. Across both successful runs:12/12 active rows observed scrubbed within the unchanged300s target,0 confirmed misses/boundary-not-proven/pending; six separate clean pending-event restart cycles. No matched stock comparison or general SLA follows from these counts. Loopback publication remains FAILED in both runs; the private bridge was the inspected working route.
