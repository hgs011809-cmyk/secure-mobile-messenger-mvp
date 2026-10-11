# New synthetic roundtrip composition

Five POSIX-only cases:8MiB streaming encryption->receiver same-file recreation halfway->idempotent retry after simulated lost ack->complete ciphertext trusted SHA->verified decrypt plaintext digest; corrupted cached ciphertext zero plaintext; fresh revocation after spool zero plaintext; durable tombstone blocks reopen/release; revocation during resumed acceptance prevents new persistence/release. Existing modules unchanged. Trusted descriptor/device/binding/ancestors are fixtures, not MatrixSDK/Internet/Android.

Static independent review found no material issue within declared assumptions. Windows final45-case loading/regression run:25pass,0fail,20skip;namespace removed. All5 new cases were skipped there; Linux execution pending. ExistingLinux40/40 run38145268441 is not evidence for new5.

8MiB live ciphertext payload bound excludes filesystem metadata/physical deleted copies. Destructive handoff unlinks prior ciphertext file before next stage stores it, so failures can lose data. NOT crash-safe/resumable production handoff; no rollback or physical erasure guarantee. No key/plaintext files or secret diagnostics.
