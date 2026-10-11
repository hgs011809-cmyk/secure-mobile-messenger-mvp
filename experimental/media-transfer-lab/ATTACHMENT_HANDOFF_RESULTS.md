# Synthetic ciphertext-preserving handoff: Linux5/5 verified

New scope: exactly five flat POSIX-only built-in Node tests in attachment-handoff.spec.mjs. Existing encryptStream, decryptVerifiedStream and SyntheticReceiver unchanged. Source backup9892ac9443bf106bf686f6eef0676b30fb477468 on lab-matrix-cleanup-followup. Source SHA25651036acebbb6b93f6deff16d926b87380bb1b658ef6424f09e7d4753b4a998b5. New separate matrix-attachment-handoff-lab.yml workflow commit e89e750ce324e0b1c2e455e23635a7accb6bba8d. One bounded CI run completed; no second run or autochain.

## Evidence so far
- Independent read-only review completed: no material defect in declared fixture scope. Caveats below retained.
- Windows new5 loading:0pass,0fail,5skip,exit0. These POSIX cases did NOT execute; not runtime proof.
- Windows existing45+new5 loading/eligible run:50 registered,25pass,0fail,25skip,0cancelled,exit0. Temporary namespace removal verified. This does not replace Linux45 evidence.
- Initial direct pathname loader failed EPERM lstat C root (exit1, no tests). Switched to supported main-context data-URL loader. No unchanged retry. LCOV-suppressed loading exit0 and subsequent private TAP aggregate-only projection above. Private raw diagnostics not published.

## Linux acceptance and independent cleanup inspected
Run https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38148000046 at workflow e89e750: new5 tests=5,pass=5,fail=0,skipped=0. Exact lab branch confirmed;12s total,9s job. source_guard=verified; completed_fixture_namespace=empty_except_private_log; private_cleanup=verified. No artifacts/cache. Separate read-only workflow review found no critical issue. Non-failing actions Node20-runtime deprecation warning recorded; test runtime configured Node22. Two helper and one local proof screenshot attempts timed out; screenshot absence is not additional proof. Acceptance and cleanup aggregates inspected directly.

## Five cases, Linux all passed
1. Eight-MiB generated plaintext, source ciphertext retained during same-files receiver restart and lost-ack retry using SENDER copy; full trusted ciphertext hash and full plaintext digest. Both ciphertext copies kept even after success until explicit cleanup. Callback observes full three-copy logical peak24MiB.
2. Corrupted cached ciphertext: trusted hash rejects, zero plaintext callbacks; all sender files byte-intact, corrupted cached files remain unchanged. Existing accept rejects conflicting retry. No invented repair.
3. Fresh authorization revocation after complete quarantine spool: zero plaintext callbacks, source and cache byte-intact; quarantine cleanup verified.
4. Explicit receiver delete creates persistent tombstone, blocks reopen/accept/decrypt, zero plaintext; source preserved until explicit sender cleanup. Not remote delete authority or physical erase.
5. Pre-write authorization failure DURING resumed accept: prior source/cache byte-intact, candidate/pending absent, zero plaintext. Explicit fixture reauthorization followed by existing API absent-chunk retry and verified digest. Not automatic retry, write-interruption/crash repair or actual auth policy.

## Exact limitations
Every fixture is8MiB, chunks<=256KiB; logical live ciphertext files<=24MiB, under64MiB fixture policy. No whole-file payload buffer, key/plaintext file or payload/descriptors/key log. RAM digest strings never serialized. Counts exclude small filesystem metadata. Logical file preservation only; NOT physical disk allocation, RSS, erasure, crash recovery or hard-runner-loss cleanup guarantee. Owner-private0700 directories/0600 files validated on POSIX. Single-owner serial fixture and trusted ancestors remain assumptions.

Room descriptor, device identity and binding trust are EXTERNAL FIXTURES, not Matrix authentication. AES-CTR+SHA256 remains standard v2 subset, not authenticated descriptor construction. Existing receiver manifest broader chunk cap is NOT changed. Corrupt-cache repair and mid-write interruption recovery remain [blocked]. Real files, microphone/devices/rooms/users not used. GB, Android, OOB, actual SDK media, staging, backup operations, physical erase and operational changes remain [blocked] until specific validation/approval.

Prior evidence remains separate: standalone40 Linux38145268441; finalcore/reference40+DESTRUCTIVEroundtrip5=45/45 Linux38146403716,a51e91f,source9868544. Prior74 and browser-tone separate. Existing stock cleanup/timeouts and network teardown failures remain failures in prior documents; not erased. No production/main/Pages/NCP/deploy/capacity/cost/authpolicy change.
