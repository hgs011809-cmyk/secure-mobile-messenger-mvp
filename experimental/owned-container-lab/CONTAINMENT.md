# CI-only owned-container containment experiment

**Status: actual runtime UNVERIFIED; independent cleanup FAILED in the first CI attempt.** No Docker build, test, browser, network or workload execution was performed by this author while writing or instrumenting these files. Parent-reported CI run `38175781795`, job `114577758655`, commit `d78221f` failed in 42 seconds: four flat contracts **4/4 passed**, image build took 34 seconds, `--run` failed in 1 second, independent cleanup failed in 0 seconds. The build completed there, but generic failure output established neither a runtime/cleanup PASS nor how many containers were created or started. No stage/cause or started count is inferred from duration. A bounded diagnostic CI rerun is pending. Actual Matrix SDK integration remains **BLOCKED**. The SDK dependency is copied unchanged as part of the existing manifest/lock, not exercised by this fixture.

## Ownership and integration boundary

Only these five new lab files are in scope. Parent owns the workflow, minimal build-context preparer, original-input verification, BASE digest resolution, private-root preparation and always-running independent cleanup. No workflow, existing source, input lockfile, security policy, app, deployment, NCP account or cost configuration is changed here. Use only the GitHub runner's existing local Docker daemon; the controller neither installs nor starts dockerd.

Build context contains only this Dockerfile, this worker and the unchanged original `experimental/matrix-client/package.json` and `package-lock.json`, preserving repository-relative paths. `ARG BASE` is supplied by the parent as the resolved Node 22 bookworm-slim RepoDigest, never a floating default. Build uses `npm ci --include=dev` and installed Playwright to install genuine Chromium with system dependencies. Public dependency network access at build time is allowed. Runtime network is `none`. The resulting exact `sha256:<64 lowercase hex>` image ID, not a tag or RepoDigest, is supplied to the controller. This is a standalone fixture, not SDK execution.

## Exact API and environment

Controller: `node experimental/owned-container-lab/container-control.cjs --run`, followed independently by the same executable with `--cleanup`, including after failure. No other arguments are accepted. Importing the CJS controller exports only pure `validateRecord(record, observed, intent, exactId)` and performs no execution. `container-control.spec.cjs` has exactly four flat `node:test` data-contract tests: ID, labels, config/image and unknown evidence. These do not claim mocked runtime proof. Parent owns invoking those tests and both actual CLI modes in CI.

Required for both modes:

- Linux, `CI=true`, `GITHUB_ACTIONS=true`, usable existing local Docker CLI/daemon at `unix:///var/run/docker.sock`.
- `RUNNER_TEMP`: real existing runner temporary directory.
- `PRIVATE_CONTAINMENT_ROOT`: precreated empty owner-only directory for `--run`, mode exactly 0700, owned by controller UID, no symlink, directly beneath the real `RUNNER_TEMP`, basename matching `owned-containment.[A-Za-z0-9_-]+`. Cleanup needs the same still-existing root, not a recreated empty directory.
- `CONTAINMENT_IMAGE_ID`: required only for `--run`, exact lowercase `sha256:<64 hex>`.

Controller supplies `HOST_PID_NAMESPACE=pid:[inode]` to the container, read from the local controller's `/proc/self/ns/pid`. This nonsecret namespace comparison value is private in records, not stdout. It is not a PID and provides no host-process signaling authority. Worker modes `graceful` / `linger` and internal `--child` / `--probe` are fixed implementation entrypoints, not a user-supplied executable API.

Success stdout, one fixed JSON aggregate per CLI mode:

```json
{"status":"passed","cases":2,"pass":2,"fail":0,"graceful":true,"timeout":true,"preStartOwnership":true,"genuineChromium":true,"privatePIDNamespace":true,"networkNone":true,"noHostPIDSignals":true,"actualSDKIntegration":false}
```

```json
{"status":"cleanup_verified","containersAbsent":true,"privateRootAbsent":true}
```

Failure is exit code 1 with only a whitelisted JSON object: fixed `status=failed`, `reason=containment_unverified`, `stage`, `gate`, integer `createdCount`, `startedCount`, `completedCount` (each 0..2), fixed-enum `networkMapObservation`, and boolean `imageEnvExpectedKeys`. Positive CLI aggregates and all admission rules are unchanged. Every pure-contract rejection retains Error.message `containment_unverified`. No Docker/browser exceptions, namespace values, IDs, nonce, private-root paths, profiles, URLs or keys are forwarded. All Docker stdout/stderr and worker aggregates are captured in private 0600 files; successful cleanup deletes that root. Failed/ambiguous cleanup preserves evidence. Each Docker command capture is bounded to 4 MiB combined stdout/stderr; exceeding it aborts the client and fails unknown. Private-file reads also reject oversized files; this is not a disk quota proof.

## Concrete confinement

Two separate containers are created but not started. Before each start, the controller persists individually, with exclusive-create (`wx`/`O_EXCL`), file fsync and directory fsync: the full 64-hex ID file and immutable expected JSON containing the exact image, labels, complete Config and complete HostConfig. Before either intent is persisted, the controller inspects the exact supplied sha256 image ID and admits its full image `Config.Env` only if it contains exactly four unique keys: `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `NODE_VERSION=22.x.x`, `YARN_VERSION=1.x.x`, and `PLAYWRIGHT_BROWSERS_PATH=/opt/playwright`. Unknown, missing, duplicate, unexpected or malformed values fail closed; official-image variants are not silently relaxed. Each intent immutably stores the observed `imageEnvironment` array. Before recording a container, its entire Env must semantically equal that baseline plus exactly one `HOST_PID_NAMESPACE` entry; order is irrelevant but duplicates are forbidden. This is image-environment admission evidence, not recursive public-dependency or base-image trust proof. Intent records for both cases are persisted before either create. All expected files are 0600 beneath the 0700 root. Expected records are never rewritten.

Required controls checked after create and against the entire recorded config before start and before every stop/remove:

- Default private PID namespace (no host/container PID sharing), private IPC and cgroup namespace.
- Nonroot `10001:10001`, cap-drop ALL, no added capabilities, no-new-privileges, no privileged mode.
- Network none, no published ports, no links or extra hosts.
- Read-only root; writable `/tmp` tmpfs `rw,noexec,nosuid,nodev,size=256m,mode=1777`; private shared memory 128 MiB.
- Memory 1 GiB, memory+swap 1 GiB, CPU 1 (`NanoCpus=1000000000`), pids 128.
- No bind mounts, Docker socket mount, devices, device requests, inherited volumes, host namespace sharing, automatic removal or init wrapper. Create explicitly requests `--init=false`; admission requires `HostConfig.Init === false`, rejecting null, missing, malformed and true values. Only recognized tmpfs mounts are tolerated in inspect mount data.

The worker creates `/tmp/ownedfixture` mode 0700 and its own browser profile; it never receives host paths. Chromium `--no-sandbox` is limited to this nonroot/cap-drop/no-network/read-only container fixture and is **not a production browser security-policy recommendation**. Only `about:blank` and synthetic DOM are used. `/proc` inspection is read-only and limited to the container namespace. Limits are Docker configuration evidence, not measured RSS, memory quota exhaustion or physical isolation proof.

## Genuine cases and shutdown authority

The genuine fixed Node fork has IPC and reports ready. Chromium is launched via installed Playwright, and its main executable (chrome/chromium/headless_shell, not a renderer-only handle) is observed via `/proc` with an ancestor chain ending at the worker, which is container PID 1. The Node child is separately observed with the worker ancestor. Worker rejects a PID namespace equal to the host namespace. No browser launch handle alone establishes proof.

1. **Graceful:** IPC requests child shutdown, waits boundedly for actual exit code 0 with no signal, closes Chromium boundedly, verifies no live browser descendants remain, deletes the private profile directory and emits exactly one known-schema completion aggregate. Controller requires container exit 0.
2. **Timeout:** PID 1 and its Node child ignore TERM; Playwright's automatic signal handlers are disabled. Both are observed alive before readiness. Controller performs a fresh internal `docker exec` read-only `/proc` probe for the child and main browser immediately before stop, validates exactly the same alive schema, then delegates TERM-to-KILL to Docker `stop --time 3` on the full recorded ID. Controller requires not-running and exit 137. PID 1's engine kill terminates its private namespace; there is no workload host-PID fallback. IPC disconnect exits the Node child if its parent exits first.

Docker CLI calls are bounded at 15 seconds (create at 30 seconds); startup/completion polling has a 60-second deadline. A hung Docker CLI client is killed only as a command transport subprocess, never by deriving or signaling a workload host PID. Stop/remove RPC timeout is ambiguous and fails closed; independent cleanup must revalidate. The legacy API key `noHostPIDSignals` is precisely a **no host WORKLOAD PID signals** projection, not an absolute claim that no host subprocess ever receives a signal. On timeout or capture failure the controller may cancel only its own directly spawned Docker CLI child. There is no broad, discovered, post-hoc or workload PID kill. This key remains unchanged for parent API compatibility. An error, malformed aggregate, unexpected key/value/count, stderr, permission denial or unexplained absence never counts as runtime success.

## Cleanup and proof limits

Cleanup reloads private intent/ID/expected records, validates saved expectations even if already absent, re-inspects exact IDs before stop and remove, and requires explicit Docker No Such Container for the exact ID afterward. Missing records, EACCES, malformed output, wrong labels/config/image or unknown state are not absence. Cleanup attempts the other recorded case even if one case fails, but never broadens authority. Stopped containers can be removed only after another exact-ID validation. No name/label discovery is ever used to kill.

Read-only residual scans by the recorded run label are **detection only**. Any residual output fails cleanup. An unrecorded container from an ambiguous create is unknown and is never killed by a discovered label/name. A missing not-yet-created record likewise fails unknown; partial-root cleanup is intentionally not silently certified. The private root is removed only after both recorded IDs are explicitly absent and residual scans are empty, followed by an explicit root ENOENT check. No root recreation/retry-as-empty can establish prior ownership.

This supports only the recorded, standalone owned-container experiment. It does not establish absence of all host processes, containment after hard runner loss, physical power-loss durability, actual SDK integration, SDK 8 MiB behavior, decryption correctness, no-plaintext handling, RSS or quota exhaustion. SDK work remains BLOCKED; genuine runtime and verified cleanup evidence remain pending a successful CI attempt.

## Bounded failure diagnostics (no admission relaxation)

`stage` is the current attempted phase, not a statement that a phase named `persisted` finished. It is strictly one of: `rootcheck`, `runempty`, `imageinspect`, `image_env_admission`, `intentspersisted`, `create`, `IDpersisted`, `created_security_admission`, `recordpersisted`, `start`, `gracefulwait`, `lingerready`, `probe`, `stop`, `cleanup_load`, `cleanup_stop`, `cleanup_remove`, `cleanup_absence`, `cleanup_residual`, `cleanup_rootremove`.

`gate` is strictly one of: `root`, `image_env`, `saved_record`, `absence`, `docker_cli`, `identity_config`, `env`, `namespace_config`, `bounds`, `tmpfs`, `host_mounts`, `ports`, `image_volumes`, `mounts`, `network_map`, `image_identity`, `create_id`, `created_state`, `workload_output`, `workload_state`, `persistence`, `private_file`, `cleanup_residual`, `root_absence`, `cli_args`, `intent`. These codes are assigned internally before each corresponding admission group or operation, never copied from exception text, Docker output or environment. Unknown Docker CLI transport/exit/parse failures map to `docker_cli`. Cleanup continues its independent exact-ID attempts but preserves its first failure projection, rather than overwriting it with the last attempt.

Counters are local to this CLI invocation. `createdCount` increments only after successful Docker create and a full validated ID response; `startedCount` only after a successful Docker start response; `completedCount` only after validating the case output and required actual terminal exit state. No counter increments on ambiguous timeout, label scan or saved-record inference. Independent cleanup therefore does not manufacture run counters from old records.

`networkMapObservation` discloses only `empty`, `none_only`, `other` or `missing`, based on the inspected network map's key shape; no network names or values are forwarded. It defaults to `missing` before observation. `imageEnvExpectedKeys` reports only whether the inspected image environment has exactly the four expected unique key names; it discloses no values or unknown key strings and is false before observation. A true boolean does not certify value admission.

Strict `Networks` admission still requires exactly `none`; neither an empty pre-start map nor unknown Docker normalization is guessed acceptable. This diagnostic change is not a fix for the first runtime failure's unknown cause and provides no new containment PASS. The parent may project only this fixed failure schema for one bounded diagnostic CI rerun; raw captures remain private.

