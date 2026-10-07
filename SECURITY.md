# Security Policy

## Status

This repository is an unaudited pilot, not a production-grade secure messenger.

## Data flow

- Message content is sent over a WebRTC RTCDataChannel.
- The service does not intentionally store chat messages.
- PeerJS Cloud performs signaling. Network metadata can be observed by signaling, STUN, TURN (if added later), access-network, and hosting providers.
- Device identity uses a browser-generated ECDSA P-256 key kept as a non-exportable CryptoKey where IndexedDB structured cloning is supported.
- Users must compare the displayed safety code through a separate trusted channel.

## Do not use for

Classified information, regulated medical/financial/legal data, credentials, recovery secrets, high-value intellectual property, or safety-critical communications.

## Known limitations

- No independent security audit.
- No authenticated account directory.
- No TURN service, offline queue, multi-device sync, recovery, or group messaging.
- Browser-delivered code integrity depends on the HTTPS hosting account and supply chain.
- Metadata minimization and traffic analysis protections are not provided.
- A compromised endpoint can read messages before encryption or after decryption.

## Reporting

Do not include real message content, private keys, tokens, or personal data in reports. Use the GitHub repository security/contact channel configured by the owner.
