# Synthetic broker + bounded ingress + Matrix SDK composition

Status: synthetic composition acceptance passed in GitHub Actions run #17 (`38106432202`, commit `3c39460`) and again after room-state hardening in run #18 (`38106701224`, commit `d73b74f`). Not production wiring or security approval.

## Separate trust boundaries

- `MatrixAdmissionBroker` still requires a fresh enrolled P-256 proof, fixed Matrix identity/device, finite session and latest-token lease. Existing signaling/push credentials are neither reused nor weakened.
- Private `SdkBindingRegistry` requires an additional one-use P-256 signature over the exact Matrix user/device and browser Ed25519/Curve25519 public key pair. Exactly two immutable records and one private room. No public registry HTTP API, silent key replacement or automatic enrollment. The registry is a single-process fixture, not distributed durable consensus or physical hardware attestation.
- `createSdkIngress` remains disabled by default. Upstream must be operator-selected loopback or numeric private IPv4 HTTP on the lab ports, with redirects rejected. The synthetic Synapse backend is unpublished on the CI private Docker bridge; only the loopback gateway is used by runtime SDK requests.
- SDK routes are scoped to the preprovisioned two-user, two-device encrypted room. Device-key upload verifies the approved Ed25519 signature and exact key pair; signed OTK/fallback uploads are bounded. SDK query `[]` is rewritten to the one approved device ID, never forwarded as a wildcard. Claim and to-device delivery exclude third users/devices. SAS and Olm are the only allowed to-device families. Megolm room send and empty-body redaction only; no plaintext room send.
- Login/registration/refresh/device CRUD/dehydration/admin/room create/join/invite/leave/state writes/account-data/backup are default denied publicly. Read routes and forced sync filter are bounded to the fixed room. Authoritative read-only room state is fetched through the same current-lease ingress before binding; creation must explicitly disable federation and match an unredacted current creation when present. Malformed IDs, duplicate state tuples, redaction markers and oversized state fail closed. Response filtering independently strips unbound rooms/UIDs/to-device senders/types; do not rely on Synapse supporting to-device filter fields.
- Runtime signature upload accepts only valid signatures by the pinned owner's user-signing key on the two already-pinned master identities. It cannot replace owner/master/device keys or authorize arbitrary users.
- Request/rate/concurrency/response bounds and latest identity rechecks fail closed. Revocation cannot atomically undo a native write that was already in flight; response suppression and denial of new requests are not rollback of accepted server events.

## Private setup is not a public capability

The trusted CI coordinator privately provisions ordinary accounts and one encrypted invite-only nonfederating two-member room. First profiles generate their own cross-signing secrets locally. An explicit temporary driver capability handles only the first owner bootstrap/signature upload against the private backend, including any UIA with the server-only account password. This capability is off during SAS/runtime and never enabled on reopen/key loss. It is not exposed by SDK ingress, a production API, or staging HTTPS. Public cross-signing replacement is denied.

The driver compares synthetic SAS values and confirms both actors. This is real SDK/Rust SAS protocol traffic, not human out-of-band identity verification. P-256 key-pair approval does not replace peer SAS.

## Accepted synthetic CI gates

Run `.github/workflows/matrix-composed-lab.yml`: bounded Node/native-module regression suites followed by actual Rust crypto in two persistent Chromium profiles. Run #17 passed all nine driver gates:

1. Registered P-256 admission, latest fixed-device sessions.
2. Immutable P-256-approved Matrix Ed25519/Curve25519 key pins.
3. Preprovisioned room and no implicit peer trust.
4. Actual Rust SAS and signed-key exchange through constrained ingress.
5. Denial of room creation/invite/state mutation, third devices and plaintext send.
6. Whole-browser cold reopen, fresh P-256 lease, old lease denial and offline decryption.
7. Ordinary peer deletion and cold reopen without message resurrection.
8. Lost crypto profile stays untrusted and cannot replace pinned device keys.
9. Coordinated revocation denies access and new peer key delivery.

Evidence: https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38106432202

Room-state hardening/repeat evidence: https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38106701224

The fixture uses real Synapse, two persistent Chromium profiles and the actual HTTP ingress on a private CI host. A trusted Playwright route adapter maps the SDK's loopback lab origin to this gateway; initial owner bootstrap alone uses its private capability. This is not public HTTPS/reverse-proxy integration. The backend's unpublished host loopback port is refused as expected; readiness uses the private Docker bridge. That diagnostic does not prove production backend isolation.

Compatibility is limited to the installed SDK/Rust traffic: bounded optional `org.matrix.msgid`, separate URI/body transaction-ID rules, explicitly known SAS MAC names, and an optional `method` in SAS accept only. Accept still requires all commitment/hash/KDF/MAC/SAS negotiation fields and rejects unknown methods/algorithms. Mandatory device Ed25519 signatures, exact recipient/key binding, explicit SAS verification and plaintext denial remain required. Room-state hardening also has 11 pure regression tests and passed repeat composition run #18.

Credentials/runtime/browser profiles are destroyed. No sensitive logs, screenshots, traces or secret artifacts. A CI failure must remain a failure; no authenticity shield or unverified-device exception is allowed.

## Still blocked

Production auth/app/NCP integration, public HTTPS, real Android two-phone SAS/force-stop/reopen/offline/delete, human OOB comparison, repeated 5-minute physical-delete/load/restart gates, WAL/backup/snapshot/attachment erasure policy and safe NCP cohosting. No capacity purchase or operational rollout authorized. Clean Chromium close is not power-loss/Android proof. Matrix ciphertext remains opaque to the gateway; recipient crypto checks are still required. This fixture is not independent security audit or absolute erasure.
