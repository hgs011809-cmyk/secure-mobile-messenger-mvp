# Separate browser audio primitive probe

Trial1: actual same-page native WebRTC DTLS connected=true; inbound audio stats supported=true;585 RTP packets; received audio RMS threshold=false. Overall FAIL/OBSERVATION_TIMEOUT. Do not claim actual tone or user voice. Both peers closed, tracks ended, AudioContexts closed and cleanup verified=true. No microphone/camera/STUN/TURN/SDK/network service.

HTTP127.0.0.1 publication path failed; supervisor terminated static source server session1027; graceful closure not established. Authored data URL used instead, no auth/ingress policy changed.

Trial2 will explicitly clock sender graph through zero-gain output and add scalar sender/receiver graph/energy diagnostics. Missing received RMS or DTLS still fails; no lowering thresholds or enabling microphone/unencrypted signaling. This page is separate from Linux74/74.

Trial2: explicit sender clocked silent graph; sender+receiver AudioContexts running=true, sender tone RMS threshold=true;591 inbound RTP packets and DTLS connected=true. Received RMS=false; positive audio-energy predicate=false (missing stat vs zero not distinguished). Overall FAIL/OBSERVATION_TIMEOUT, not verified audible/tone/human call. Both peers/tracks/contexts closed; cleanup verified=true. Thresholds/DTLS requirement unchanged; no microphone, encryption-off, credentials or production route used. Root cause unresolved. Further diagnostic must distinguish stats availability/track mute/source energy before asserting silence or codec/policy cause.

GB-scale product transfer, actual people/Android/OOB, Matrix media signaling/attachment crypto composition, public HTTPS and NCP capacity remain[blocked] pending dedicated validation/approval, not implied by74 Node tests or connected DTLS packets.

Trial3: added strictly muted,volume0 HTML media consumer to clock remote decoding. Native same-page data-URL probe PASS: sender+receiver contexts running, sender+received RMS above0.005,4 inbound RTP packets, DTLS supplied+connected, muted consumer playing. Peers closed, tracks ended, contexts closed, muted sink stopped;cleanup verified=true. Energy positive predicate stillfalse; not distinguished from missing stat and not used as success evidence. Prior failures remain failures. No microphone/permissions/unencrypted signaling changes. This is generated-tone local primitive only, NOT people/Matrix/Android/Internet/identity/OOB/SFU E2EE proof.

Next negative control: identical authored document with only synthetic gain0.2 replaced by0 must not pass RMS gate; separate from Linux74-case result.

Trial4 silence negative control: same authored trial3 document, exact single gain0.2->0 substitution in RAM. Overall expected FAIL/OBSERVATION_TIMEOUT. Both contexts running,584 RTP packets and DTLS connected, but sender/received RMS=false. Muted consumer playing; peers/tracks/contexts/sink cleanup verified=true. Thus RTP+DTLS alone did not satisfy tone gate. Packet value from inspected final snapshot; no microphone or policy changes.
