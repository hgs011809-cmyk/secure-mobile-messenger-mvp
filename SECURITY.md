# Security Policy

## Status

This repository is an unaudited pilot, not a production-grade secure messenger.

## Data flow

- Message content is sent over a WebRTC RTCDataChannel.
- The service does not intentionally store chat messages.
- The currently active public mode uses PeerJS Cloud for signaling. The repository also contains an undeployed authenticated PeerServer/TURN mode. Network metadata can be observed by signaling, STUN/TURN, access-network, and hosting providers.
- Device identity uses a browser-generated ECDSA P-256 key kept as a non-exportable CryptoKey where IndexedDB structured cloning is supported. Private-server enrollment sends only the public key and proves possession with short-lived signed challenges.
- Users must compare the displayed safety code through a separate trusted channel.

## Do not use for

Classified information, regulated medical/financial/legal data, credentials, recovery secrets, high-value intellectual property, or safety-critical communications.

## Known limitations

- No independent security audit.
- No authenticated account directory.
- No deployed TURN service, offline queue, multi-device sync, recovery, or group messaging. The repository contains an undeployed NCP auth/PeerServer/coturn stack and client integration, while the public `config.js` remains in public mode.
- Browser-delivered code integrity depends on the HTTPS hosting account and supply chain.
- Metadata minimization and traffic analysis protections are not provided. The private stack disables access logs by default, but IP, timing, peer IDs, and relay usage still exist in memory or infrastructure telemetry.
- A compromised endpoint can read messages before encryption or after decryption.
- PeerJS admission tokens travel in the WebSocket URL query. They are short-lived, peer-bound, single-use, and access logging must remain disabled.
- Device recovery is administrative: revoke the old device and issue a new one-time invite. There is no self-service recovery.

## Reporting

Do not include real message content, private keys, tokens, or personal data in reports. Use the GitHub repository security/contact channel configured by the owner.
