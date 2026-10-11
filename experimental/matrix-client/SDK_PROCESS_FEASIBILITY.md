# Actual SDK authority to separate ciphertext receiver: read-only feasibility

Observation: 2026-10-12 01:45 KST scheduled phase. Branch lab-matrix-cleanup-followup only.
Status: conditional design candidate; feasibility NOT established by runtime or implementation. NOT implemented, NOT executed. Existing child worker unsuitable as-is. No new test pass or real process/SDK integration claim.

## Inspected evidence
- transport-composed-ci.mjs:108-116 resolves BOTH latest native sessions, exact participant/device identities, two active registered bindings, and current SDK event status. Lines119-151 compose actual receipt with an IN-PROCESS receiver and real redaction/native denial. Prior Linux38152247874 actual SDK transport5/5 remains separate.
- transport-hooks.inc.mjs:2-20 retains/revalidates the receipt in a page-local map, cleared on pagehide. An exported clone is not continuing authority.
- transport-pipeline.mjs:127-148 injects async authorization; bindingId is a local identifier, not an auth MAC. Lines170-218 describe same-process resume/retry and guarded hash-before-plaintext decrypt.
- process-restart-worker.mjs:32-38 captures mockAllowed. This fixed synthetic boolean MUST NOT substitute for live SDK/native authority. Existing process tests remain mock evidence only.
- receiver.mjs:25-29,50-74 has async authorization checks. Resume validates lengths, not content hashes. Failed initialize is not a permanent denial latch. New wrapper must gate every subsequent operation; no existing receiver patch authorized.
- attachment-stream.mjs:13-14 warns async source/sink/authorization may hang. Timeouts must close the owned channel/child, not merely reject a Promise while work continues.
- process-write-fault-cleanup.cjs establishes the narrow cleanup precedent: private marker PID/start/exact Node executable/worker path/full argv/private root, revalidation before kill; scan-only discovery never grants kill authority. Separate SDK cleanup must additionally verify its owned profile processes and named containers.

## New-file-only candidate
Keep authoritative receipt, descriptor keys and native credentials in the still-live parent RAM. Child receives validated non-key manifest/chunks, performs ciphertext-only filesystem operations and whole ciphertext hash checks. It never receives descriptor keys/plaintext/native tokens. Parent performs stream verification/decryption only after fresh authority and trusted whole-hash validation; instrument real plaintext callbacks and bytes.

The child receiver authorization callback must request a NEW parent decision for EACH invocation over private fork IPC. The parent executes the real current authority chain, never a caller-supplied mockAllowed or previously cached grant. A boolean result from that real per-request chain is a transport reply, not an independent authentication proof. Authenticate the channel by ownership/inherited IPC, not an invented MAC/security protocol.

Bind requests/replies to session generation nonce, monotonic request ID, exact operation/checkpoint, transfer/binding/event context and bounded deadline. One serialized command and one outstanding authority request; strict exact field/type/size checks, bounded chunks and no arbitrary paths/method calls. Retire consumed requests; reject replay, wrong generation/context, unsolicited/out-of-order replies, expired decisions and post-close messages. Child disconnect/parent death/timeouts fail closed; close channel and observe child exit before root removal or fresh PID. Initialize failure latches only the NEW wrapper; reinitialize requires a new owned child/session. Repeated checks do NOT make revocation atomic or undo in-flight filesystem writes.

Reuse the authority semantics by a NEW experimental variant, preserving BOTH latest native sessions, two ACTIVE immutable participant bindings and current SDK device/room/event/receipt checks. Do not modify existing policies or turn off trust/encryption. Exact immutable binding equality against the initial accepted snapshot must be an explicit assertion, not inferred from two active entries. Verify this during implementation/review.

## Bounded execution acceptance, next routine only
Target6 flat Linux cases on8MiB ciphertext/chunk256KiB, sequential fixtures, logical source+receiver+quarantine<=24MiB; not measured RSS or GB capacity.
1. Actual SDK positive: fresh two leases/two bindings/SDK receipt drives owned child;16 committed chunks, ACK-idle exit observed, different PID, exact resume16, idempotent lost-ACK retry, whole hash and parent plaintext digest. Parent stays alive with RAM keys.
2. IPC freshness: duplicate/stale/wrong-generation/expired/out-of-order responses reject. These protocol injections are SYNTHETIC negatives, not real native revocation proof.
3. Actual SDK redaction with both native leases demonstrably active: exact AUTHORIZATION_DENIED at parent decrypt, zero real plaintext callback/bytes; child denial vocabulary separately asserted. Source/cache preserved.
4. Actual native recipient revocation: current recipient resolve null, exact AUTHORIZATION_DENIED and zero plaintext. SDK sender-key-loss state must not be mistaken for isolated native-only proof. Do not claim independently exercised sender revocation/inactive registry/wrong-room cases unless actually executed.
5. Same-length persisted ciphertext mutation: length-only resume not considered integrity, existing finalize integrity_failed/stream HASH_MISMATCH before plaintext; compare source and post-damage cache fingerprints after denial, no repair.
6. Owned IPC disconnect/timeout lifecycle: deterministic private protocol fault, exit observed, no later accepted command/ACK/plaintext; independently always-clean all owned resources. Synthetic lifecycle evidence distinct from actual SDK evidence.

Each top-level case can assert several conditions but aggregate must report exactly6 tests, pass/fail/cancel/skip plus flat/nested count; SDK gates separately enumerated. Exact child authorization/error vocabulary is an implementation acceptance item, NOT a tested result here. Hash-pin all unchanged policy/core/prior sources AND new files before/after Linux execution. Independently reviewed isolated workflow, owner-only raw logs, stdout aggregate only, no uploaded artifacts/cache/profiles. Always cleanup must verify owned child exit, named container absence and private namespace/profile absence; no broad kill scans, no physical erase claim. Keep historical failures.

## Current boundary and next step
No source/runtime/workflow modifications in this phase. No new CI launched; pendingCI null. Next scheduled routine may delegate one precise NEW sdk-process-* implementation scope and obtain independent read-only review before any isolated Linux CI. If per-request fresh authority, immutable bindings, lifecycle or secret isolation cannot be established without core/policy changes: mark blocked and choose bounded cold-recipient/quota alternative. No new phase after04:15 KST.

Actual MXC ingress/media, Android/Internet/real-user devices, human OOB, whole-app/runner restart, persisted-key recovery, power loss, atomic authorization, production/cloud/cost/capacity/deployment and physical erasure remain blocked/unverified. Existing SDK5/5, process ACK-idle4/4, write-fault6/6 and persisted-corruption6/6 remain SEPARATE.

## Review
Read-only investigation bZcgUyvsP90GFDUL: proposed new variant, blocked as-is; no execution. Independent read-only review5VVQy8NFGcMvOydp: PASS for scoped proposal framing, ISSUES for unimplemented exact immutable binding assertion, live per-callback IPC decisions, initialization latch and timeout/owned-child lifecycle. Claiming established feasibility or actual integration remains BLOCKED. These are implementation acceptance items, not passing source/runtime evidence. Next routine may attempt only the bounded NEW wrapper candidate and must fail closed/choose the alternative if it requires existing policy/core changes. No runtime tests or CI in this phase. Previous155 source/config/workflow fingerprints (excluding2 checkpoint JSON files) rechecked unchanged.
