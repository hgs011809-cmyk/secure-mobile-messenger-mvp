# SDK-authenticated descriptor to preserving synthetic transfer

## Inspected Linux proof
- Run: https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38152247874 ; job114507916337. Completed successfully2m19s; actual composed stage1m25s. Source backup8170fc9, workflowc8e81c9, branchlab-matrix-cleanup-followup.
-28 exact source/policy hashes verified. Existing conversation/client/admission/ingress/broker/registry, crypto and receiver implementations unchanged.
- Four NEW POSIX mock-receipt fixture unit tests:4pass,0fail,0skip. They DO NOT establish actual SDK provenance. Windows loader earlier registered4,pass0,fail0,skip4; no Windows runtime proof.
- Actual SDK-to-Node preserving composition:5/5. Prior actual SDK descriptor6/6 also passed in same driver; its cold restore/corrupt/schema/redaction4KiB proof remains SEPARATE from8MiB transport proof.
- Independent always cleanup log verified privatefixture/profile/build/runtime paths, helper/project containers including named extraction absence, and no processes advertising private profile user-data-dir. These mean logical test-resource cleanup only, not physical erasure, crash recovery, or arbitrary process-tree/memory wipe.

## New5 gate boundaries
1. Actual SDK/Rust decrypted/trusted sender-device/room receipt drives private8MiB Node receiver; SDK reply detached/canonicalized/frozen after CDP clone. Source descriptor equality checked. Same-process receiver object recreated mid-transfer over same files; half-complete state resumes, lost final half-ack same-segment resend accepted idempotently; verified streaming decrypt yields exactly8MiB expected digest.
2. Receiver guarded operations and streaming crypto authorization repeatedly require fresh latest BOTH native sessions (including real native whoami veto), exact two ACTIVE registered immutable participant-device bindings and current SDK event context/device/room trust and same exported receipt. These are repeated checks, NOT atomic authorization or an auth MAC. Local binding hash is an identifier only.
3. Corrupted streamed COPY fails exact HASH_MISMATCH before any plaintext callback; source/receiver ciphertext and manifest unchanged. Not damaged persisted-cache repair.
4. Actual SDK descriptor redaction fails exact AUTHORIZATION_DENIED with zero plaintext while native session leases still active. Current SDK stage specifically REDACTED asserted; ciphertext preserved through denial.
5. Second sequential fixture has genuine SDK receipt and completed cache/positive streaming decrypt. Original coordinated native revocation then yields current receiver resolution null and exact AUTHORIZATION_DENIED, zero plaintext and preserved source/cache. Native lease check precedes SDK check. This final stage shares the original driver with its sender-key-loss negative fixture; it is NOT a separate native-only isolated trust-state experiment.

## Storage/cleanup/review
Each fixture8MiB, source+receiver+quarantine<=24MiB LOGICAL payload,256KiB chunks,64MiB policy ceiling. Reported ceiling follows fixed bounded source/receiver/quarantine composition, not measured RSS, physical disk allocation, GB throughput or Internet performance. Two fixtures sequential; first explicit receiver.erase tombstone+namespace removal beforesecond, same forfinal; fallback independently removes all tracked namespaces even if earlier removal fails. No plaintext/key fixture files, public profiles/descriptors/tokens/messages/SDP/ICE logs or uploaded artifacts/cache. Private SDK stores/logs under owner-only disposable paths. Controlled same-process reconstruction only, NOT runner/process-crash recovery or restore after erasure.

Independent read-only code/driver review found no final material interface mismatch. CDP reply freeze and actual post-revocation helper were confirmed. Workflow review prompted explicit named-container and profile-process absence checks. No independent external security audit implied. Screenshotattempt timed out; evidence is inspected aggregate CI logs, not an image.

## Preserved previous evidence and limits
Prior stream/reference40/40 run38145268441; resumed crypto45/45 run38146403716 (destructive handoff notcrashsafe); preserving handoff5/5 run38148000046; SDKdescriptor6/6 run38149969509; media74/74 run38140155348 and earlier synthetictone results separate. Historical stock-restart misses/cleanup/timeout failures remain recorded, not overwritten by thissuccess.

Ciphertext DATA PLANE IS PRIVATE IN-PROCESS FILE FIXTURE. Actual Matrix signaling/SDK encryption/control is composed, NOT MXC upload/download or browser/Android Internet file delivery. Real devices/users/rooms, humanOOB, GB/RSS/capacity, interrupted-write repair, hard runnerloss cleanup, atomic revocation, backup and physical erasure remainblocked/unverified. Existing policies NOTweakened; no main/Pages/productionapp/NCP/deploy/cost/capacity changes. This bounded step complete; checkpoint andSTOP, no automatic next-stage chain.
