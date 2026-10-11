# Synthetic broker + bounded ingress + Matrix SDK composition

Status: implemented for CI; acceptance result pending. Not production wiring or security approval.

## Separate trust boundaries

- `MatrixAdmissionBroker` still requires a fresh enrolled P-256 proof, fixed Matrix identity/device, finite session and latest-token lease. Existing signaling/push credentials are neither reused nor weakened.
- Private `SdkBindingRegistry` requires an additional one-use P-256 signature over the exact Matrix user/device and browser Ed25519/Curve25519 public key pair. Exactly two immutable records and one private room. No public registry HTTP API, silent key replacement or automatic enrollment. The registry is a single-process fixture, not distributed durable consensus or physical hardware attestation.
- `createSdkIngress` remains disabled by default. Upstream must be operator-selected loopback or numeric private IPv4 HTTP on the lab ports, with redirects rejected. The synthetic Synapse backend is unpublished on the CI private Docker bridge; only the loopback gateway is used by runtime SDK requests.
- SDK routes are scoped to the preprovisioned two-user, two-device encrypted room. Device-key upload verifies the approved Ed25519 signature and exact key pair; signed OTK/fallback uploads are bounded. SDK query `[]` is rewritten to the one approved device ID, never forwarded as a wildcard. Claim and to-device delivery exclude third users/devices. SAS and Olm are the only allowed to-device families. Megolm room send and empty-body redaction only; no plaintext room send.
- Login/registration/refresh/device CRUD/dehydration/admin/room create/join/invite/leave/state/account-data/backup are default denied publicly. Read routes and forced sync filter are bounded to the fixed room. Response filtering independently strips unbound rooms/UIDs/to-device senders/types; do not rely on Synapse supporting to-device filter fields.
- Runtime signature upload accepts only valid signatures by the pinned owner's user-signing key on the two already-pinned master identities. It cannot replace owner/master/device keys or authorize arbitrary users.
- Request/rate/concurrency/response bounds and latest identity rechecks fail closed. Revocation cannot atomically undo a native write that was already in flight; response suppression and denial of new requests are not rollback of accepted server events.

## Private setup is not a public capability

The trusted CI coordinator privately provisions ordinary accounts and one encrypted invite-only nonfederating two-member room. First profiles generate their own cross-signing secrets locally. An explicit temporary driver capability handles only the first owner bootstrap/signature upload against the private backend, including any UIA with the server-only account password. This capability is off during SAS/runtime and never enabled on reopen/key loss. It is not exposed by SDK ingress, a production API, or staging HTTPS. Public cross-signing replacement is denied.

The driver compares synthetic SAS values and confirms both actors. This is real SDK/Rust SAS protocol traffic, not human out-of-band identity verification. P-256 key-pair approval does not replace peer SAS.

## Intended CI gates, not yet accepted

Run `.github/workflows/matrix-composed-lab.yml`: bounded Node/native-module regression suites followed by actual Rust crypto in two persistent Chromium profiles. Intended checks include P-256 admission and key binding, no implicit trust, SAS/key distribution over ingress, prohibited route denial, full-process recipient close/offline ciphertext, new P-256-authenticated lease on cold reopen with old lease rejection, retained crypto trust/decryption, peer deletion while sender is closed/no resurrection, and coordinated revocation blocking access/new peer key delivery.

Credentials/runtime/browser profiles are destroyed. No sensitive logs, screenshots, traces or secret artifacts. A CI failure must remain a failure; no authenticity shield or unverified-device exception is allowed.

## Still blocked

Production auth/app/NCP integration, public HTTPS, real Android two-phone SAS/force-stop/reopen/offline/delete, human OOB comparison, repeated 5-minute physical-delete/load/restart gates, WAL/backup/snapshot/attachment erasure policy and safe NCP cohosting. No capacity purchase or operational rollout authorized. Clean Chromium close is not power-loss/Android proof. Matrix ciphertext remains opaque to the gateway; recipient crypto checks are still required. This fixture is not independent security audit or absolute erasure.
