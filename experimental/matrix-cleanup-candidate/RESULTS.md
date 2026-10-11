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

These twelve completed samples across two runs/four fresh fixtures are a small correlated synthetic functional pilot, not a stock-vs-candidate matched randomized comparison, broad reliability evidence or an SLA. At this clean-restart pilot stage, fresh-index not-ready branches, 100/101 batching and abrupt crash had not been tested. The later mocked boundary and separate SIGKILL results below narrow those gaps only within their stated scopes. Real SQLite 100/101-row load, real index-transition integration, sustained load, same-pending-event repeated restarts, host power loss, WAL/backup/snapshot/attachment/physical erasure, Android, human OOB, production ingress/admission wiring and NCP capacity remain unverified. Exact synthetic key comparison is not human SAS. No traces, screenshots or secret artifacts are collected by CI; fixture cleanup was invoked in run#2, but its legacy always-success shell block did not independently prove removal. The stronger terminal gate was subsequently verified in run#3.

## Third attempt: explicit teardown verification

[Run38124904942](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38124904942), commit614da25, repeated the unchanged six-sample pilot specifically to verify the new terminal cleanup gate. Both jobs PASSED. The gate now propagates Docker teardown/remove/verification failures, checks runtime and public build-directory absence, and checks absence of containers with the exact fixture project label. Both job logs explicitly contain fixture_cleanup_verified=true; private_files_absent=true; fixture_containers_absent=true. This means fixture filesystem unlink/container cleanup, not physical media erasure.

| Run | Scenario | Within300s | Conservative upper min / max (seconds) |
|---|---|---:|---:|
|38124599670|control|3/3|24.777063871 /29.491088925|
|38124599670|clean restart|3/3|2.979485071 /3.043393327|
|38124904942|control|3/3|24.928479777 /30.043590443|
|38124904942|clean restart|3/3|4.592066118 /4.616042478|

Third-run clean restart downtime:4123,4136,4143ms. Negative-control, post-restart API hiding and final SDK redaction gates passed again. Across both successful runs:12/12 active rows observed scrubbed within the unchanged300s target,0 confirmed misses/boundary-not-proven/pending; six separate clean pending-event restart cycles. No matched stock comparison or general SLA follows from these counts. Loopback publication remains FAILED in both runs; the private bridge was the inspected working route.

## Installed-native mocked boundaries and abrupt recovery

[Boundary run38125692435](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38125692435), commit875a473, preserved FAILED status. Before a server started, all9 installed-native cases passed: exact installed source; retention disabled; index not-ready/ready transition;100-row and101-row batches; invalid redactions; transaction ordering/failure/retry; immediate/30-second clock ticks; asynchronous nonoverlap/error retry. The actual installed native functions and Synapse/Twisted deterministic clock execute, but DB queries, transaction/event fixtures and index readiness are MOCKS. This is not real SQLite101-ciphertext load or native database-index-transition evidence.

The runtime portion failed at stopped-server-pending-ciphertext:3 planned,1 registered,0 scrubbed/within-target/confirmed-misses/boundary-not-proven and1 pending. This is an incomplete probe, not a measured300s cleanup miss or a successful abrupt recovery. The initial helper omitted its user identity while the private fixture directory is owner-only and capabilities are dropped. Commit14ee899 adds validated numeric CI_UID:CI_GID to the no-network read-only helper, aligning it with the server/fixture owner without chmod, added capabilities, recovery writes or policy relaxation. The original low-level exception was suppressed, so the ownership explanation is consistent with the code and successful correction, not a captured raw diagnostic. No blind unchanged rerun was made.

[Separate boundary run38126060890](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38126060890), commit14ee899, was manually dispatched and PASSED in1m30s (job1m26s). The installed-native mocked cases repeated9/9. Real encrypted runtime samples passed3/3 with unchanged300000ms acceptance and original request/ack clocks. Counts: scrubbed3,withinTarget3,confirmedMiss0,boundaryNotProven0,pending0. Conservative request-to-first-observed-scrub upper bounds: min5077.324702ms,p505109.112631ms,p95/max5136.496629ms. Restart downtime was4608,4651,4623ms. The90000ms observation budget remains an early functional gate, not a changed retention target.

Each of three separate pending encrypted/redacted events was SIGKILLed: exact/data host bind, stopped exit137 and non-OOM, same-container/same-volume identity, ciphertext still pending in the stopped-volume read-only helper, and post-restart API hiding were required. Final SDK redaction and unchanged/decryptable unredacted/cross-room-target sentinel checks passed. Nonmember403/M_FORBIDDEN and cross-room400/M_UNKNOWN with exact fixed-message match remained required. This is process/container SIGKILL, not host power loss, repeated crashes of one pending event, WAL erasure, or evidence of physical deletion.

Terminal log: fixture_cleanup_verified=true; private_files_absent=true; fixture_containers_absent=true. This verifies fixture filesystem unlink/container removal only. CI emitted aggregate fixed gates, not message/event/key/token data, traces, screenshots or artifacts. Working transport remained host-private INTERNAL bridge; loopback publication FAILED/ECONNREFUSED throughout. Source/image pinning, native censor body/index/authorization checks and100-row cap remain unchanged.

Across the earlier12 clean/control samples plus these3 abrupt samples,15 successful functional samples were observed within target in mixed, correlated synthetic scenarios. Do not pool this into a reliability rate, matched comparison or SLA, and do not erase either preserved initial harness failure or stock workflow38109336061 failure. Production/NCP integration stays blocked. Remaining gates include real database index-transition and101-row/backlog load, sustained/concurrent load, repeated same-pending-event crashes, host power loss, broader cache consistency, public HTTPS/staging, Android two-device and human OOB, WAL/backups/snapshots/attachments/physical erasure, production admission/ingress wiring, NCP capacity, independent review and explicit approval.
