# Startup ownership: bounded static audit

## Decision

BLOCKED for actual SDK/process runtime. A transparent read-and-transform wrapper around the current Node fork and Playwright persistent-context interfaces does not establish independently recoverable birth ownership before process execution or across abrupt parent death. No existing source/policy is changed. This phase adds only this document and `sdk-process-startup-audit.cjs`. No runtime workflow, processes, browser, backend, container, media or auth action is launched by the helper.

## Inspected evidence

Line numbers describe the current pinned source, not a future version:

- `sdk-process-session.mjs:11` calls `fork(worker,...)`; line12 installs `once(child,'exit')`. The child can execute before the parent receives/records its PID. The parent returning/knowing a PID is not a pre-execution persisted ownership barrier.
- `sdk-process-worker.mjs:6-10` validates argv/root, reads `/proc/self/stat` and then writes `owned-child-<pid>.json`. The marker is self-written after execution begins. Its record has PID/root/start only, not executable/full argv. Parent death or worker termination before line10 leaves the independent cleanup identity incomplete. No cross-process ordering follows from parent/child source order.
- `transport-composed-ci.mjs:42` awaits `chromium.launchPersistentContext(profile,...)` then retains only the context in a RAM set. This exposed interface supplies no persisted prelaunch Chromium PID/start/executable/full-argv identity. Playwright may launch subprocesses before returning or rejecting. A browser context or later `browser()` handle is not a process birth record, and browser descendants are not covered by a single discovered main PID.
- `transport-composed-ci.mjs:72,154` uses `mkdtemp(tmpdir(), 'composed-*')` and RAM profile arrays. Line166 closes contexts and removes profiles in `finally`; hard parent exit bypasses it. Knowing a profile directory or finding `--user-data-dir` afterwards is detection only, not authority to kill a process tree.
- `sdk-process-live-composed-ci.mjs:4-6,29` transforms existing transport text, retains the original import basis, and does not replace fork or Chromium startup. Its exact-once transforms are not startup ownership instrumentation.
- `sdk-process-live-driver.inc.mjs:29,33` retains a close handle before awaiting session creation, then obtains the session only after `openCiphertextSession` succeeds. This improves in-process close bookkeeping but does not persist birth identity or close the spawn-to-marker death window. Lines45-46 concern acknowledged-idle close/reopen, not startup crash.
- `SDK_PROCESS_LIVE_CI.md` already records no runtime/CI and independent birth ownership blockers. This audit narrows the decision: do not add a cosmetic post-spawn marker and call it a fix.

## Proposed wrapper boundary, not implemented

A NEW child bootstrap can defer loading receiver code until a private IPC gate after an independently revalidated ownership record. That can establish **before receiver payload execution**, not **before child process execution**: the bootstrap itself must run before it can know/write its PID/start/executable/argv. Replacing only `fork` with such a gate still leaves newborn bootstrap cleanup unowned if the parent dies before registration. No claim that existing worker/session policy permits a new protocol or that it has been tested.

Chromium would require an independently owned launcher/supervisor or a pre-established kernel containment mechanism that covers launcher and all descendants, plus exact resource identities and a separately reviewed cleanup implementation. A shell wrapper writing a marker then `exec` changes executable/argv at the identity boundary and still leaves grandchildren; polling `/proc` afterwards is not a prelaunch ownership barrier. Cgroups, new privileges or resource-management permission are not assumed or requested. Existing interfaces do not establish this requirement. Keep the actual SDK/process positive gate blocked, do not weaken cleanup checks, and do not modify policy/core files.

## Deterministic audit helper

The helper reads only six exact same-directory source/doc files, verifies pinned SHA-256 content, verifies ten exact-once anchors and three textual-order predicates. It imports no inspected source, generates no transforms, scans no directories/processes, writes no files and logs only fixed aggregate fields/codes. Pin hashes reside in the helper and can be inspected there. A mismatch exits1 with a fixed sanitized code. Read errors, including inaccessible source files, also exit1. Symlink/non-file targets are rejected. These are static checks, not a concurrency proof, recursive source closure, permission-hardening proof or integration tests. The source-order predicates intentionally do not assert parent/child happens-before.

Observed main-context command (Windows):

```powershell
$env:SDK_PROCESS_WORKSPACE='C:/Users/mycom/.aside/u/0/workspaces/secure-mobile-messenger-lab'
node -e "const fs=require('node:fs'),path=require('node:path');const d=path.join(process.env.SDK_PROCESS_WORKSPACE,'experimental/matrix-client');new Function('require','__dirname',fs.readFileSync(path.join(d,'sdk-process-startup-audit.cjs'),'utf8'))(require,d);"
```

Observed exit0: source pins6/6; exact-once anchors10/10; textual-order checks3/3; runtimeTests0; subprocess/browser/container launches0; transforms0; helper writes0; preExecutionBirthOwnershipEstablished=false; independentAbruptParentCleanupEstablished=false. Fixed blocked codes: `CHILD_SPAWN_BEFORE_BIRTH_MARKER`, `BROWSER_BIRTH_IDENTITY_UNAVAILABLE`, `INDEPENDENT_CONTAINMENT_NOT_ESTABLISHED`. `static_audit_verified_runtime_blocked` means inspected sources still match the audit, never runtime acceptance.

The first direct `node <absolute helper path>` attempt failed before helper loading with Node module-loader EPERM resolving `C:/`; exit1, no audit result. The main-context invocation above avoids the known loader path limitation without nested spawning or broad filesystem permission requests. There is no Linux execution evidence and no negative-fixture runner invocation in this phase. No test runner counts are inferred from the static aggregate. Runtime tests registered/executed/passed/failed/cancelled/skipped: 0/0/0/0/0/0. The SDK/process runtime gate remains blocked and unlaunched, not a skipped executed test. Independent review and remote backup belong to the parent and are not claimed by this document.

## Concrete safe next phase

Choose one NEW synthetic logical-filesystem-quota fixture instead of another unexecuted startup wrapper. Suggested bounded scope: 8MiB ciphertext, 256KiB chunks, parent-only mock authorization, new fixture accounting helper plus flat tests. Measure sums of actual ciphertext file lengths in a private namespace (logical application accounting, not filesystem-enforced quota). Test exact-boundary admission, next-chunk over-boundary rejection with a NEW fixture-specific code, duplicate retries consuming no new logical bytes, restart/recompute from persisted file lengths, and denial preserving existing source/cache length/hash inventories. Keep immutable receiver/crypto/policies untouched and clearly identify fixture-budget denial versus existing receiver error codes. Require source pins, isolated Linux execution, aggregate runtime logs and independent owned cleanup before any pass claim. Do not claim native filesystem quota, allocated blocks, GB/RSS, powerloss, interrupted-write repair, actual SDK, Android, Internet, actual MXC or production capacity.

## Parent verification and independent review

Parent main-context audit separately exited0 with pins6/6, anchors10/10 and order3/3; prior919 non-checkpoint files matched their pre-phase fingerprints. Independent read-only reviewer `AFQfaOT3f7PLBuRu` reported PASS for source/static disposition only and independently ran the same audit once. Implementation task `8e6rbieZ2fq7czlC`. No Linux/SDK/cleanup runtime proof added. Next scheduled run should use the concrete logical-budget fixture alternative, not repeat unexecuted startup wrappers.
