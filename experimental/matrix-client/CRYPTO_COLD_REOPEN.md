# Synthetic browser SAS and cold-reopen acceptance

Development only. The deployed P2P app and NCP are unchanged. No real accounts, messages or server secrets are used. This harness is NOT connected to the admission broker/read-only ingress.

## Receiver boundary

Decryption alone does not authorize UI display. The adapter now requires the exact two-member encrypted private room and one mapped device each, locally verified peer, decrypted Olm-established sender Curve25519/claimed Ed25519 keys matching the expected device, and SDK43 event-authenticity shield NONE/no reason. Unknown sender, changed key, unknown device, missing verification, key forwarding/authenticity warnings or failed lookup withhold plaintext and clear visible memory. Async trust checks cannot resurrect a concurrently deleted message. Device/trust updates conservatively clear visible memory. This is not a substitute for server admission, room provisioning or a hardware identity.

## Intended live gates (pending until inspected CI passes)

1. Real Chromium clients initialize Rust crypto and sync with isolated Synapse v1.162.0; unverified sends fail closed.
2. Actual to-device SAS request cancellation does not grant trust.
3. SDK43 requestDeviceVerification/accept/startVerification('m.sas.v1')/show_sas produce equal complete decimal tuples, followed by explicit confirmation on both sides. No setDeviceVerified shortcut.
4. Recipient's whole persistent Chromium context/process closes. Sender creates only an encrypted server event while recipient is absent.
5. New Chromium process opens the same disk profile, restores identical public device keys and verification, syncs and decrypts the offline event.
6. Sender's whole browser closes; ordinary peer redacts its message. Reopen and a second reopen cannot display the deleted event; deletion metadata survives.
7. Fresh profile with lost crypto state and the same synthetic device ID does not inherit peer trust or regain sending automatically.

This is clean full-process shutdown/relaunch, NOT forced OS kill, power loss, Android process death, mobile PWA/service-worker delivery, native production reauthentication or arbitrary-old-history pagination. CI reinjects the same ephemeral access token only in memory after relaunch. No token persistence, plaintext event store, SDK logging, HAR, browser traces or credential screenshots. Crypto keys and deletion metadata intentionally persist in the temporary profile, which is destroyed after the test.

## Transport and operational limits

The client factory permits only loopback port18008. If the known Docker loopback publication fails, the CI driver's Playwright route handler proxies only that exact synthetic loopback origin to the inspected job-owned private internal bridge. This bypass is test infrastructure, NOT evidence for public HTTPS, public ingress, network firewall or admission integration. Registration is private synthetic shared-secret setup, not production account admission.

Synthetic automatic decimal comparison tests protocol mechanics, not a human's out-of-band comparison or defenses against browser/hosting compromise. Android two-phone SAS/cold-reopen/offline/delete tests are still required. Deletion in this job verifies logical redaction/absence, not the 5-minute active-row cleanup target, load/restart deletion SLA or WAL/backups/media/physical erasure. Server resource capacity and production rollout remain unapproved.
