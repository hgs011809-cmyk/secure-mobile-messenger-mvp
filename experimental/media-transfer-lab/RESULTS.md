# Final local checkpoint

Corrected combined source:74 registered tests (receiver28,voice20,ingress18,loopback8);72 portable pass,2 Linux-only skip,0 fail. Full direct built-in/data-URL run exited0. Public source hashes and private namespace removal=true saved in ignored last-direct-offline-run.json. Linux74/74 TAP-checked verification pending.

64 MiB file mechanics + actual8 MiB loopback TCP disconnect/retry/reconstruction verified separately; NOT actual Internet/Android/Matrix media or voice call. See NETWORK_RESULTS.md, VOICE_RESULTS.md, SDK_ANALYSIS.md, RUNTIME_NOTES.md and REQUIREMENTS.md. Earlier59 Linux and initial failed74 local runs remain historical, not certification of later source.

## Earlier checkpoints (preserved)

# Current reviewed checkpoint

After independent review, receiver tests expanded to28: local Windows26 pass,2 Linux-only skip,0 fail; voice20/20 and unchanged ingress18/18 remain separate. Combined portable64 pass+2 skip. Added initial manifest pending recovery, descriptor-only primitive snapshot validation, invalid/rollback clock rejection, actual post-write and post-hash revocation tests, callback-triggered terminal deletion recheck.

Baseline Linux run38138348223 at6bcc36c passed59/59, including Linux owner-only mode/symlink cases. That run precedes these seven review regressions and does NOT certify the corrected version. Corrected Linux66 test run is pending. The callback checks are not atomic cross-process/lease transactions; same-owner concurrent filesystem mutation and multi-instance behavior remain excluded. Tombstone persistence is tested across object reconstruction, not power-loss durability.

## Earlier baseline report (preserved)

# Synthetic ciphertext transport results

Local Windows Node v22.23.0: 21 tests, 19 passed, 0 failed, 2 Linux-only mode/symlink tests skipped. The pathname test runner could not resolve the permitted file path; successful execution loaded the exact module/test contents through data URLs using built-in modules, without expanding filesystem permissions. Linux CI must independently run the unchanged files normally.

64 MiB complete-file AES-256-CTR synthetic ciphertext, 256 KiB chunks: receiver reconstruction after 32 chunks recovered 8 MiB committed data, remaining chunks completed, trusted whole-file SHA256 matched. Largest processed payload 256 KiB; this is NOT a measured RSS/heap or browser bound. Key/IV and plaintext are never persisted or logged. Best-effort buffer clearing is not proof of memory erasure.

Passed local mechanics: invalid geometry, out-of-order holes, idempotent retries/conflict denial, caller buffer mutation isolation, partial pending write recovery, advisory checkpoint tampering, manifest substitution rejection, stored corruption/truncation, revoked/changed binding, deadline expiry, tombstone-before-erasure/non-resurrection, bounded outstanding chunk queue. Each test removes and checks absence of its disposable fixture.

LIMITS: no actual network disconnect, OS crash/power-loss, browser restart, Matrix media/SDK encryption integration, real lease/device cryptography, multi-instance transaction/locking, global quota, complete filesystem adversary/hardlink/ACL guarantees, public download, endpoint media deletion, backups/WAL/physical deletion, Android, upload speed or production capacity. An authorization callback and independently trusted manifest are fixture assumptions, not authentication proofs. Atomic rename plus file fsync is not directory fsync/power-loss durability. Current ingress remains unchanged and denies media. Parser 2 GiB cap is not a product guarantee.

Unchanged SDK request-policy regression: local 18/18 passed. Plaintext media/file/call/MatrixRTC and TURN routes remain denied. Valid opaque encrypted room envelope remains allowed; policy cannot classify the decrypted contents. This is a request-policy unit test, NOT response filtering or composition. Voice state tests separately passed20/20. Combined local 57 pass, 2 Linux-only skip, 0 fail.
