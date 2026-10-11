# Synthetic voice admission model

Local Windows Node22 built-in/data-URL execution: 20/20 tests passed, no skip/failure. Model requires two externally verified endpoints, detached immutable epoch/room/call identity, authorized sender, fresh pre/post authorization, ordered lifecycle, terminal hangup, replay/order denial, bounded event/candidate metadata and queue, exact expiry, clock rollback rejection and group/SFU denial.

This is NOT a functioning voice call: no SDP/ICE payload, WebRTC, microphone, audio codec, signaling encryption, fingerprint binding, actual media E2EE, TURN, reconnection/ICE restart, latency, Android or background handling. Callback verification flags are supplied fixture trust, not cryptographic endpoint proof. Strict fail-closed closing on malformed events/retries is a model choice, not a reviewed production usability/DoS policy. Callback timeout and replay persistence across new instances remain unimplemented. Existing ingress still denies plaintext call/MatrixRTC and TURN routes; opaque encrypted room content cannot be classified by the server policy. Production remains blocked.

Voice module/spec were authored under the separate local voice-call-lab folder, then copied unchanged into this unified media-transfer-lab for code-only branch backup and CI. No production files were edited.
