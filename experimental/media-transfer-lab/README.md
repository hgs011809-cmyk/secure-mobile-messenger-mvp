# Synthetic resumable ciphertext transport

Security-first message, voice and large-file transfer are project goals, not completed product claims. This separate offline lab does not alter Matrix admission, deployed P2P app, NCP, deployment, cost or trust policy. Production migration remains blocked.

The receiver persists fixed-size opaque ciphertext chunks, verifies a separately trusted immutable manifest at finalization, re-scans committed files after reconstruction, rejects conflicting retries, and writes a deletion tombstone before local logical cleanup. It has no media key, plaintext renderer, server listener, public download or custom messaging encryption. The 64 MiB fixture uses standard Node AES-256-CTR for complete-file synthetic ciphertext generation only. It is NOT matrix-js-sdk attachment integration or standard Matrix resumable media.

Run on Linux with an explicit private TMPDIR: node --test --test-concurrency=1 receiver.spec.mjs voice-policy.spec.mjs ingress-regression.spec.mjs network.spec.mjs. Node22+, no dependencies/external network; network.spec uses127.0.0.1 ephemeral listeners only.
See RESULTS.md for exact executed evidence and limitations. Processed-payload bounds are not RSS/heap bounds. Restrictive Unix modes are tested only on Linux; Windows ACL privacy is not claimed.

Unchanged ingress regression18/18 and synthetic voice-state20/20 passed locally. See VOICE_RESULTS.md and SDK_ANALYSIS.md.

Next gates: native supported Matrix encrypted attachment format plus complete-file integrity under authenticated metadata; streaming memory measurements and bounded global storage; actual network loss/retry/browser restart; file deletion authorization/expiry/backup policy; Android two-device tests; public HTTPS and capacity/security review. Do not enable media by weakening the current allowlist.

## Additional transport evidence
network.spec.mjs uses actual loopback TCP disconnects and8 MiB complete-file ciphertext. Eight cases now passed locally after explicit socket-close observer cleanup; listener/receiver reconstruction is not an OS crash or Internet/Android test. See RUNTIME_NOTES.md for preserved failures and SDK_ANALYSIS.md for exact SDK limits.

## Interrupted-work resume
Persistent code/checkpoint lives under the account workspace, not session tmp. RESUME.md and REQUIREMENTS.md retain exact last result and next gate. Public SDK43 sources+LICENSE are saved locally under reference/, not treated as a complete offline toolchain. Never back up profiles, credentials, keys, payloads or capabilities.

Windows pathname-loader workaround: set MEDIA_LAB_ROOT to this code directory and MEDIA_LAB_TMP_ROOT to the authorized Aside session tmp, then load only authored direct-offline-runner.cjs contents in Node22 main context with --test-reporter=lcov. The nested runner is deprecated; VM without import callback is unsupported. last-direct-offline-run.json holds public source hashes/status/namespace cleanup, not test payloads.

## Final verified checkpoints
Linux74/74 reviewed code, independent namespace cleanup: LINUX_VERIFIED.md. New standalone voice-tone-lab.html has separate native-browser positive generated-tone/DTLS and expected-failing silence control; VOICE_TONE_RESULTS.md preserves failed earlier trials. No microphone/camera/real accounts; cannot stand in for intended-peer authentication or an actual product call. CHECKPOINT.md lists all remaining gates. Source, SDK reference and minimal built-in Node runtime are in persistent account workspace; full SDK/browser/container tooling is not bundled.
