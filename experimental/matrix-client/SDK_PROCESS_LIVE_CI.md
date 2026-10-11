# NEW live SDK/process CI ownership feasibility review

## Disposition: BLOCKED before runtime

No runtime or CI launched. This is a bounded source-level feasibility result, NOT SDK/process integration proof. One intended positive candidate gate remains unexecuted: expected 1, executed 0, pass 0, fail 0, cancelled 0, skip 1 (blocked). These are planning counts, not a test runner result. Legacy descriptor successes are separate and never counted. SDK redaction acceptance remains BLOCKED, closure cause UNKNOWN, counted false. No parent plaintext/hash or zero-plaintext proof exists. The current 1500ms authority deadline is unchanged.

## Concrete blocking evidence

1. `transport-composed-ci.mjs` inherits `launchPersistentContext(profile, ...)`; profiles are created with `mkdtemp` and retained in RAM arrays. There is no persisted birth-ownership marker for Chromium PID/start-time/executable/full argv. Its finally block closes contexts and removes profiles. Hard driver exit can bypass this finally block. A post-hoc `/proc` match on `--user-data-dir` is detection, not permission to kill an exact owned process. Broad profile process termination would violate the delegated requirement.
2. `sdk-process-session.mjs` forks the child before `sdk-process-worker.mjs` persists its own PID/root/start marker. A termination between spawn and marker leaves no independent birth record. This is an existing experimental lifecycle limitation, not a permission to alter it during this phase.
3. Existing foundation `sdk-process-cleanup.cjs` accepts only a direct `PRIVATE_ATTACHMENT_ROOT/sdk-process-*` root. The live candidate actually places the worker root at `PRIVATE_ATTACHMENT_ROOT/sdk-process-live-*/receiver`. Copying foundation cleanup unchanged would miss/reject the live nested marker. The NEW inspection helper detects that layout but deliberately does not turn a scan into signaling authority.
4. The existing authenticated transport workflow uses fixed extraction/container/image names and a workspace backend runtime. It must not simply be copied into a claimed exact-owned isolated runtime workflow. A reviewed NEW launch wrapper must establish resource identities before startup, keep private runtime/build/profile paths under its namespace, and independently revalidate before cleanup.

## New files and safe behavior

- `sdk-process-live-prepare.cjs`: generates ONLY the NEW workflow; exact SHA-256 pins for 134 source/config dependencies across client, transfer, bridge, cleanup candidate, native auth source and CI backend. Includes current SDK live/authority/protocol/session/worker code, receiver/crypto, package lock, build/server and backend policy/config. Excludes runtime, dist, node_modules and .git. The generated workflow is not self-hashed; it is identified by its future immutable branch commit. No existing policy/source files are modified.
- `sdk-process-live-cleanup.cjs`: Linux-only read-only `/proc` identity observations; never signals a process. Validates an exact run/attempt namespace under real RUNNER_TEMP, UID, directory type and mode0700, detects live worker/profile processes, and removes only an empty owned namespace. Unexpected content or detected processes fail closed, retaining evidence for a later approved exact cleanup. It does not claim birth ownership or exit observation after runtime.
- `.github/workflows/matrix-sdk-process-live-lab.yml`: MANUAL DISPATCH ONLY; no push trigger. Lab branch gate, contents read, no overlapping cancellation, no runtime opt-in. Pre/post pins, explicit BLOCKED aggregate with exit1 before browser/backend build, Docker read-only exact reserved-name absence check with private077 capture, independent always empty namespace helper. No browser install, container/image create/remove, backend config, SDK, media, real device, deployment or external-service actions. No artifacts/cache/raw logs upload. **Do not launch this workflow as a runtime acceptance test.**

Reserved names are run/attempt-specific (`sdk-process-live-<run>-<attempt>-synapse` and `...-extract`). They are inspected for absence only. No containers are created. Docker inspection failure remains unverified, not a pass; no container deletion is attempted. A later workflow must be separately reviewed before using these names for actual resources.

## Exact source-only invocation

PowerShell:

```powershell
$env:SDK_PROCESS_WORKSPACE='C:/Users/mycom/.aside/u/0/workspaces/secure-mobile-messenger-lab'
node -e "const f=require('node:fs'),vm=require('node:vm');const r=process.env.SDK_PROCESS_WORKSPACE;for(const n of ['sdk-process-live-prepare.cjs','sdk-process-live-cleanup.cjs']){new vm.Script(f.readFileSync(r+'/experimental/matrix-client/'+n,'utf8'));}eval(f.readFileSync(r+'/experimental/matrix-client/sdk-process-live-prepare.cjs','utf8'));console.log('syntax_modules=2; runtime_tests=0');"
```

Observed exit0: prepared true, pins134, syntax_modules2, runtime_tests0, CIStarted false, blocked true. This parses two modules and generates YAML only. Cleanup/Linux/SDK runtime was NOT executed; YAML runtime was NOT verified. No Windows nested spawning was used.

## Smallest next safe step

Separate narrowly delegated NEW-file startup ownership wrapper plus independent read-only review. Capture child and browser birth records (PID/start/exe/fullargv/root) before considering independent signaling; if that cannot be established within existing interfaces, keep runtime blocked rather than patching policy or using broad kills. Require exact owned containers and private runtime path tracking. Only then create a separately reviewed actual one-positive-gate Linux runtime workflow. Preserve deadline and all source/policy pins. Parent-survives ACK-idle boundary only; no powerloss, whole-app, persisted-key, Android, Internet, MXC, GB/RSS, repair, production or atomic authorization claim.

## Independent source-blocker review and narrow correction

Parent reported independent read-only source-blocker review PASS. This is source review only, not runtime verification. Parent also identified that `/proc` identity EACCES was incorrectly suppressed as disappearance. Narrow NEW-helper correction: only ENOENT/ESRCH now return null; EACCES and all other unknown inspection errors propagate to sanitized CLEANUP_FAILED and exit1. This can fail closed on any inaccessible PID, intentionally preferring an unverified blocked inspection to a false absence claim. No broader signaling authority was added.

Regenerated NEW workflow pins after the correction using the same main-context helper: exit0, pins134, syntax_modules2, runtime_tests0, CIStarted false. No existing source, policy, checkpoint or remote modifications. Independent review remains source-only; Linux cleanup, Docker inspection and actual SDK/process execution have not been run.
