# Matrix client: experimental development foundation

Not imported by deployed `app.js`; not a finished offline messenger. No production accounts, keys or services are changed.

## Implemented
- Matrix SDK 43.0.0 browser factory with durable Rust crypto in IndexedDB, memory-only SDK event store (no localStorage pending-event persistence), and unverified-device blocking. Factory permits only local test server port 18008.
- Fail-closed sending: encrypted, invite-only, non-federated, joined-history, two-member room; one bound device per member; peer device verified in the Matrix SDK. Existing P256 safety codes do not satisfy this verification.
- SDK text sending, in-memory-only rendered messages, room-scoped durable deletion metadata, no plaintext fallback.
- Either participant can request redaction without peer approval or online presence. Peer key changes do not block an authorized deletion request.
- Pending deletion is hidden locally but not described as completed for the other device. Retry after reconnect; late/replayed events cannot resurrect locally deleted content.
- Logical redaction acknowledgment does NOT confirm database, WAL, media or backup cleanup.

## Development checks
With Node 22+ in this folder: `npm ci --ignore-scripts`, `npm test`, `npm run build`, `npx playwright install chromium`, `npm run test:browser`.

Build copies the official crypto WASM beside the browser bundle. No external CDN import is used. Root versions and the reviewed CI-generated dependency lock are committed. The successful initial build used crypto engine 18.9.0; the earlier standalone smoke test used 18.7.0.

The browser harness uses synthetic credentials only, aborts loopback homeserver requests, and tests actual WASM initialization plus IndexedDB deletion metadata. A stronger test also checks device-key continuity after SDK stop/recreate and page reload. It is not a two-phone/server delivery test.

## Not implemented / deployment gates
- Existing invite/device authentication to Matrix account/token provisioning.
- Server-enforced two-account/two-device enrollment and private room power-level policy.
- UI timeline/decryption/redaction listener wiring, verified key setup/recovery, startup reconciliation, authoritative delete-status UI and message pagination.
- Device-wide plaintext memory/cache handling and third-party copy restrictions cannot be guaranteed.
- Optional local encrypted-history cache is not implemented. After restart history must be retrieved from the encrypted server; without network, previous history is not available. Crypto keys and deletion metadata remain durable. SDK IndexedDB event storage is deliberately not enabled because its plaintext-persistence guarantees require further audit.
- Real offline delivery, offline redaction sync, and measured <=5-minute active-database ciphertext scrubbing under load.
- Backup/WAL/media lifecycle: redaction alone does not remove these copies. No server-cleanup success label until measured/proven.
- Matrix redaction permissions cover state as well as messages. They require server-side policy/security review; UI restrictions are insufficient.
- Production browser bundle, Android regression, dependency lock and security review.

The client checks are defense in depth, not authoritative server membership enforcement. A membership change can race a send unless the provisioning/server policy prevents unauthorized joins. Never enable this adapter in production before those gates pass.
