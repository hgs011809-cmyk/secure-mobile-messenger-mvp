# Synthetic browser SAS and cold-reopen acceptance

Development only. The deployed P2P app and NCP are unchanged. No real accounts, messages or server secrets are used. This harness is NOT connected to the admission broker/read-only ingress.

## Receiver boundary

Decryption alone does not authorize UI display. The adapter now requires the exact two-member encrypted private room and one mapped device each, locally verified peer, decrypted Olm-established sender Curve25519/claimed Ed25519 keys matching the expected device, and SDK43 event-authenticity shield NONE/no reason. Unknown sender, changed key, unknown device, missing verification, key forwarding/authenticity warnings or failed lookup withhold plaintext and clear visible memory. Async trust checks cannot resurrect a concurrently deleted message. Device/trust updates conservatively clear visible memory. This is not a substitute for server admission, room provisioning or a hardware identity.

## Live gates (observed pass in run #3; scope below still applies)

1. Real Chromium clients initialize Rust crypto and sync with isolated Synapse v1.162.0. Each initial synthetic profile bootstraps its own cross-signing identity via supported SDK API/private synthetic UIA; this is never auto-run on reopen or key loss. Peer auto-trust remains disabled; unverified sends fail closed.
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

## Observed acceptance and failed variants

Run #3 passed on 2026-10-11 Asia/Seoul at code commit `f76586b5d316207cdca019c26e06ea827b76a507`: https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38100831239 . All 24 sender/receiver/deletion regression tests passed, and the live script emitted eight passed gates (including initial own cross-signing setup). Full context closure asserted the isolated Browser was disconnected before relaunch. Both public device keys restored unchanged; mutual SAS trust survived; the offline event decrypted and entered the adapter snapshot only after the unchanged sender-key and SDK NONE/no-reason authenticity guard passed. The sender was fully closed during peer redaction, and two subsequent opens did not resurrect that event. A fresh lost-crypto profile did not inherit peer trust. Browser localStorage/sessionStorage remained empty and no SDK event-history database was found. This is one synthetic run, not a stress/power-loss/mobile guarantee.

Run #1 (`38100147254`, `8941da8`) and diagnostic run #2 (`38100444081`, `20c95ce`) failed closed on cold-reopen display. Run #2 explicitly passed unverified rejection, SAS cancellation, matching real SAS and encrypted server storage. It then restored keys/trust and decrypted the offline event, but SDK RED/UNKNOWN_DEVICE (colour2/reason2) withheld display despite current device key matches. No warning was bypassed. The pass followed supported initial-profile cross-signing bootstrap, real peer SAS and unchanged strict display checks. This observation does NOT establish missing cross-signing as the direct UNKNOWN_DEVICE cause: Rust UNKNOWN_DEVICE denotes a missing sender/session device lookup; bootstrap may affect key-query timing/store availability as well as provenance. Precise causality needs a controlled cache/lookup study, not a broader warning exception.

The inspected job used a harness proxy to its private Docker bridge; loopback port publication remained failed. Admission broker + constrained ingress + room/key/message API composition, public HTTPS staging, Android two real phones and human comparison remain separate gates. Do not deploy or raise NCP capacity/cost from this result.
