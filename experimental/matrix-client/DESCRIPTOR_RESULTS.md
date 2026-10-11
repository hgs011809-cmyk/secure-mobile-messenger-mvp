# Actual SDK encrypted attachment descriptor: verified

Run https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38149969509
Source ccff0bd; workflow b48dbd2; branch lab-matrix-cleanup-followup.
One bounded Linux run, total 1m6s/job1m2s/runtime12s. No artifacts/cache.

## Inspected acceptance
- Exact 14 source/unchanged-boundary hashes: descriptor_source_and_policy_guards=verified.
- Unit fixtures: Windows12/12 and Linux12/12, zero failures/skips. These do NOT prove SDK cryptography.
- Actual SDK descriptor gates:6/6, fail0; fixture4096 bytes. receiver_key_source=SDK_decrypted_event; sdk_sender_device_and_room_checks=true; whole_ciphertext_hash_before_decrypt=true.
- Independent cleanup: candidate_composition_cleanup_verified=true; private_fixture_paths_absent=true; profiles_tmp_root_absent=true; fixture_containers_absent=true.
- Existing auth/ingress/client/native-veto regressions and installed candidate source gates passed. Non-failing action Node20-runtime warning, test Node22.

## Six actual-SDK gates
1. Existing SDK conversation gate denies file send before peer verification.
2. Genuine encrypted m.file event is stored as m.room.encrypted without plaintext file/body/key; recipient whole-browser close, same private profile and new P256-authorized lease, SDK/Rust decryption and existing exact peer device-key/authenticity/room checks.
3. File key comes ONLY from decrypted SDK event; Node-generated standard-v2 ciphertext is verified against the event digest before WebCrypto decrypt; resulting plaintext digest matches the generated4096-byte fixture. Text-only renderer remains unchanged and does not display file content.
4. Corrupted ciphertext requires the exact hash-mismatch error, intended decrypted SDK event state, and zero new decrypt calls.
5. Malformed descriptor in a genuine encrypted event requires exact INVALID_DESCRIPTOR and intended decrypted event state, zero new decrypt calls.
6. Actual target server redaction plus ledger sync requires exact REDACTED and actual redacted event state, zero new decrypt calls on reuse.

## Exact boundary
This narrows the external-descriptor assumption ONLY for this private actual-SDK4KiB composition. Existing attachment receiver/stream/handoff suites are NOT wired to this authenticated source yet; their previous fixture assumptions remain. Ciphertext bytes and expected plaintext digest are supplied in memory by the CI driver, NOT fetched from MXC. Synthetic MXC URL, no upload/download/media endpoint. This is neither actual browser streaming transfer nor Android/Internet/large-file behavior.
Repeated SDK trust/room/deletion checks are not atomic authority or a guarantee of fresh authoritative server-state/lease revocation at every local cached decrypt. SDK synchronized state and protected local profiles are trusted; no hostile JavaScript/proxy, memory compromise or post-check race protection. Human OOB verification was NOT performed; genuine SAS was automatically compared solely by synthetic driver. No plaintext/key fixture files or published SDK profiles/credentials/logs; existing SDK keystore uses disposable owner-only private profiles and verified cleanup, not physical erasure. GB/RSS/repair/crash/backups/hard-runner-loss cleanup/physical erase/operational approval remain blocked.

## Review and failure history
Independent read-only review found generic negative catches could mistake unrelated errors for intended rejection: fixed to specific whitelisted code + actual event state before CI. Review requested pinning authoring hook sources: added hook/fixture/driver hashes, even though executed composed HTML/driver were already pinned. Agent pathname run reported missing file; parent main-context data-URI unit loader passed12/12. Initial REPL authoring import-text rejection switched to file authoring; no runtime claim from that failure. One narrow proof screenshot timed out; accepted scalar evidence was inspected, no missing image treated as proof.

Prior40/45/handoff5/74/browser-tone evidence separate. Earlier failed cleanup/timeout/network tests remain failures. Existing conversation/client/admission/ingress/policy/main/Pages/app/NCP/deployment/capacity/cost unchanged. Stop after this bounded milestone, no autochain.
