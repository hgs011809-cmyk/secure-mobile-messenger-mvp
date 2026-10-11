# Pinned SDK43 source review: qualified findings

Offline source: reference/matrix-js-sdk-43.0.0; installed metadata43.0.0. Source inspection only, not executed SDK media/call integration.

## Call signaling: do not generalize all paths as plaintext
- src/webrtc/call.ts2472–2536: sendVoipEvent has two routes. With opponentDeviceId, encrypted to-device path selected by getUseE2eForGroupCall() explicitly throws Unimplemented (Rust migration TODO); disabling it sends plaintext sendToDevice. Never disable encryption or expand plaintext call allowlist to make calls work.
- Without opponentDeviceId, it calls client.sendEvent(roomId,eventType,content). src/client.ts3022–3085: known encrypted rooms use cryptoBackend.encryptEvent; reactions/redactions excluded. Therefore room-based call signaling CAN follow room encryption conditions. This does not prove verified device/DTLS-fingerprint binding, incoming call-handler authorization or working calls.
- Existing ingress permits opaque encrypted room envelopes; it cannot classify decrypted m.call/m.file contents. Current conversation renderer only supports m.text. New tests check plaintext endpoint denial, not decrypted semantic denial.

## Upload: no proven streaming pipeline
- src/http-api/index.ts38–48 documents browser XHR body and Node Buffer/String/ReadStream; browser branch uses xhr.send(file), node branch passes body to authedRequest.
- src/http-api/interface.ts245 types FileType as XMLHttpRequestBodyInit. src/http-api/fetch.ts280–313 forwards body to fetch but supplies no duplex option. The comment is not proof that native Node fetch accepts a ReadStream or that browser encrypted streaming works; runtime-specific tests remain needed.
- uploadContent includes filename by default. Any future encrypted media integration must explicitly suppress filename in transport and avoid sensitive MIME/metadata exposure, keeping recipient metadata inside a verified encrypted event.
- No attachment-specific public encryption helper was found by the scoped SDK investigation. Room-event encryption does not encrypt upload bytes; audited standard encrypted-attachment format and streaming interoperability are separate gates. The new Node AES-CTR fixture does NOT establish Matrix metadata/crypto/SDK integration.

## Remaining gates
No microphone/audio/real call/Internet/Android/SFU admission tests. Review receive-side SDK automatic call handling, exact bound sender crypto keys, room state, fresh epoch/lease, signaling-to-DTLS fingerprint binding, relay policy, reconnect and privacy. Keep default-deny operational wiring unchanged.
