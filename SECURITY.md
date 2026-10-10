# Security Policy

## Status

This repository is an unaudited pilot, not a production-grade secure messenger.

## Data flow

- Message content is sent over a WebRTC RTCDataChannel.
- The service does not intentionally store chat messages.
- The active private mode uses the deployed NCP device-authentication, PeerServer and TURN stack. Network metadata can be observed by signaling, STUN/TURN, access-network and hosting providers.
- Device identity uses a browser-generated ECDSA P-256 key kept as a non-exportable CryptoKey where IndexedDB structured cloning is supported. Private-server enrollment sends only the public key and proves possession with short-lived signed challenges.
- Users must compare the displayed safety code through a separate trusted channel.

## Do not use for

Classified information, regulated medical/financial/legal data, credentials, recovery secrets, high-value intellectual property, or safety-critical communications.

## Known limitations

- No independent security audit.
- No authenticated account directory.
- Authenticated TURN and generic consent-gated Web Push wakes are deployed. Android Web Push receipt was confirmed by the user. There is still no offline message queue, persistent conversation history, app-layer E2EE protocol, multi-device sync, self-service recovery or group messaging.
- Browser-delivered code integrity depends on the HTTPS hosting account and supply chain.
- Metadata minimization and traffic analysis protections are not provided. The private stack disables access logs by default, but IP, timing, peer IDs, and relay usage still exist in memory or infrastructure telemetry.
- A compromised endpoint can read messages before encryption or after decryption.
- PeerJS admission tokens travel in the WebSocket URL query. They are short-lived, peer-bound, single-use, and access logging must remain disabled.
- Device recovery is administrative: revoke the old device and issue a new one-time invite. There is no self-service recovery.

## Reporting

Do not include real message content, private keys, tokens, or personal data in reports. Use the GitHub repository security/contact channel configured by the owner.

## Web Push metadata

- Push subscriptions and mutual wake-consent relationships are stored on the authentication server. They are additional metadata, not message content.
- The payload contains only a generic request to open the app, with no message body or sender name.
- Delivery is best effort; a forced stop, restricted background execution, revoked notification permission or network failure can prevent receipt.
- Browser push provider credentials are not the device identity keys. VAPID private keys remain in server-side secret files and must never be published or logged.

## Planned persistent messaging

Offline message delivery and retained history must not be implemented by putting plaintext WebRTC messages into the current server. A reviewed app-layer E2EE implementation and deletion/synchronization design are prerequisites. Either participant may request deletion for both without the other participant approving it. An offline device can apply deletion only when it next synchronizes. Screenshots, exports, compromised clients and external backups are outside that guarantee. These capabilities are not implemented yet.
