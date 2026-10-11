# Persisted ciphertext corruption experiment (candidate)

Synthetic only, six NEW flat Linux cases. Existing receiver/crypto/policy unchanged. Authorization and clock MOCK; parent RAM descriptor only. No process restart or SDK proof in this suite.

## Observed existing boundaries, not policy changes
- Receiver resume scans lengths, not hashes. Same-length corruption can appear present until finalize `integrity_failed`; original-byte retry is `conflicting_retry`. Streaming decrypt independently denies `HASH_MISMATCH` before plaintext.
- Bare SyntheticReceiver does not latch failed initialize: changed manifest initialization is `manifest_changed`, but this suite makes NO subsequent-method-denial claim. Callers must keep initialization gating; any future enforcement requires separate approved core change/review.
- Snapshots are taken after deliberate damage; negative reads/retries must preserve damaged cache and unchanged source. No repair.

## Status
Implementation and independent read-only review pending. Linux runtime not yet executed; no pass claim. Prior controlled-write6/6, ACK-idle4/4, actualSDK5/5 remain separate. No Internet/MXC/Android/GB/RSS/powerloss/whole-app/physical erase proof.
