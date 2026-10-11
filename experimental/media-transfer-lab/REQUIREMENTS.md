# Security-first media requirements and rollout gates

User goals: secure text + voice + reliable large-file sending. Frequent Internet interruption requires incremental code-only checkpoints and resume instructions, not storage of secrets or runtime crypto profiles. Product size/speed target remains unspecified;64 MiB fixture and2 GiB parser cap do not establish a product guarantee.

## Text and identity
Preserve existing verified Matrix device/key binding, fail-closed room state and current lease checks. Existing message experiments do not automatically prove voice/file security. Keep prior stock restart failures, native SQLite hybrid, actual SDK composition and new transport/state units separate.

## Files
Use standard audited/interoperable complete-file encryption and authenticated encrypted metadata. Do not invent independent per-chunk crypto or treat receiver-supplied hashes as trusted. Preserve ciphertext only in resumable staging, bounded chunks/queues, expired/revoked binding denial, final hash before release, tombstone-before-logical-cleanup and explicit user controls. Next gates: global quota, streaming encryption/decryption compatibility, actual transport failure, recipient identity+event/manifest binding, browser/Android restart, display/download policy, authenticated upload/download ingress, attachment expiry/deletion/backups, physical-copy limitations, realistic size/throughput/memory tests and storage/cost approval.

## Voice
Prefer1:1 P2P WebRTC with supported encrypted call signaling and exact verified device/DTLS-fingerprint binding. DTLS-SRTP transport encryption alone is not intended-peer authentication. No default group/SFU path or plaintext signaling fallback. Next gates: supported SDK43 call-event behavior, permissions before microphone, late trust/revocation, ICE/TURN/restart, authenticated route policy review, two-device Android WiFi/mobile/background tests and independent review. Synthetic state flags are not cryptographic verification.

## Approval boundary
Only offline/loopback synthetic development and lab-branch CI. No main merge, production app wiring, NCP change, deployment, spending/resource increase, public service, relaxed trust/rate/state policy or publication of images. Operational migration remains blocked until security/device/deletion/hosting gates plus explicit approval.
