# Matrix client: experimental development foundation

Not imported by deployed `app.js`; not a finished offline messenger. No production accounts, keys or services are changed.

## Implemented
- Matrix SDK 43.0.0 browser factory with Rust crypto/IndexedDB and unverified-device blocking. Factory permits only local test server port 18008.
- Fail-closed sending: encrypted, invite-only, non-federated, joined-history, two-member room; one bound device per member; peer device verified in the Matrix SDK. Existing P256 safety codes do not satisfy this verification.
- SDK text sending, in-memory-only rendered messages, room-scoped durable deletion metadata, no plaintext fallback.
- Either participant can request redaction without peer approval or online presence. Peer key changes do not block an authorized deletion request.
- Pending deletion is hidden locally but not described as completed for the other device. Retry after reconnect; late/replayed events cannot resurrect locally deleted content.
- Logical redaction acknowledgment does NOT confirm database, WAL, media or backup cleanup.

## Development checks
With Node 22+ in this folder: `npm install --ignore-scripts`, `npm test`, `npm run build`, `npx playwright install chromium`, `npm run test:browser`.

Build copies the official crypto WASM beside the browser bundle. No external CDN import is used. Root versions are pinned; generated dependency lock must be reviewed and committed before production use.

The browser harness uses synthetic credentials only, aborts loopback homeserver requests, and tests actual WASM initialization plus IndexedDB deletion metadata. It is not a two-phone/server delivery test.

## Not implemented / deployment gates
- Existing invite/device authentication to Matrix account/token provisioning.
- Server-enforced two-account/two-device enrollment and private room power-level policy.
- UI timeline/decryption/redaction listener wiring, verified key setup/recovery, startup reconciliation, authoritative delete-status UI and message pagination.
- Device-wide plaintext memory/cache handling and third-party copy restrictions cannot be guaranteed.
- Persisted event store inspection to ensure it contains only encrypted content in all SDK flows.
- Real offline delivery, offline redaction sync, and measured <=5-minute active-database ciphertext scrubbing under load.
- Backup/WAL/media lifecycle: redaction alone does not remove these copies. No server-cleanup success label until measured/proven.
- Matrix redaction permissions cover state as well as messages. They require server-side policy/security review; UI restrictions are insufficient.
- Production browser bundle, Android regression, dependency lock and security review.

The client checks are defense in depth, not authoritative server membership enforcement. A membership change can race a send unless the provisioning/server policy prevents unauthorized joins. Never enable this adapter in production before those gates pass.
