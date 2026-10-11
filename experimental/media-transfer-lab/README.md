# Synthetic resumable ciphertext transport

Security-first message, voice and large-file transfer are project goals, not completed product claims. This separate offline lab does not alter Matrix admission, deployed P2P app, NCP, deployment, cost or trust policy. Production migration remains blocked.

The receiver persists fixed-size opaque ciphertext chunks, verifies a separately trusted immutable manifest at finalization, re-scans committed files after reconstruction, rejects conflicting retries, and writes a deletion tombstone before local logical cleanup. It has no media key, plaintext renderer, server listener, public download or custom messaging encryption. The 64 MiB fixture uses standard Node AES-256-CTR for complete-file synthetic ciphertext generation only. It is NOT matrix-js-sdk attachment integration or standard Matrix resumable media.

Run: node --test receiver.spec.mjs (Node22+; no dependencies/network).
See RESULTS.md for exact executed evidence and limitations. Processed-payload bounds are not RSS/heap bounds. Restrictive Unix modes are tested only on Linux; Windows ACL privacy is not claimed.

Next gates: unchanged-ingress deny regression; native supported Matrix encrypted attachment format plus complete-file integrity under authenticated metadata; streaming memory measurements and bounded global storage; actual network loss/retry/browser restart; file deletion authorization/expiry/backup policy; Android two-device tests; public HTTPS and capacity/security review. Do not enable media by weakening the current allowlist.
