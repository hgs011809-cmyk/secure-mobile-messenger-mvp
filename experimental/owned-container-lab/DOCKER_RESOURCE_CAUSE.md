# Docker OOM representation investigation: source evidence, not CI proof

The user explicitly renewed authorization for investigation, independent review and isolated CI after checkpoint 980f136. Existing production, NCP, main, SDK, admission and trust policies remain outside scope. The first four failed runs remain failed; this note does not revise their unpublished values.

## Pinned public source chain

Read-only investigation uBj7m1vztRbfpJ92 found the following Docker 29.0.0 paths:

1. [cgroup2_linux.go L76-L87](https://github.com/moby/moby/blob/docker-v29.0.0/pkg/sysinfo/cgroup2_linux.go#L76-L87): capability `info.OomKillDisable=false` for cgroup v2. This capability flag is not a container setting.
2. [daemon_unix.go L446-L456](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/daemon_unix.go#L446-L456): resource verification sets a nonnil OomKillDisable pointer to nil when unsupported. Only true emits the OOM warning; false is silently discarded.
3. [create.go L90-L93](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/create.go#L90-L93) and [L119-L127](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/create.go#L119-L127): create verifies, then adapts defaults.
4. [daemon_unix.go L364-L368](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/daemon_unix.go#L364-L368): create adaptation makes nil explicit false.
5. [start.go L63-L69](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/start.go#L63-L69): start re-verifies the stored HostConfig, not a defensive copy; no subsequent create adaptation applies.

The same chain is present in 28.5.1: [capability](https://github.com/moby/moby/blob/v28.5.1/pkg/sysinfo/cgroup2_linux.go#L76-L89), [verification](https://github.com/moby/moby/blob/v28.5.1/daemon/daemon_unix.go#L470-L480), [default](https://github.com/moby/moby/blob/v28.5.1/daemon/daemon_unix.go#L376-L380), [create](https://github.com/moby/moby/blob/v28.5.1/daemon/create.go#L92-L95), [start](https://github.com/moby/moby/blob/v28.5.1/daemon/start.go#L63-L69), and [nullable API field](https://github.com/moby/moby/blob/v28.5.1/api/types/container/hostconfig.go#L404-L408).

## Prediction versus observed evidence

These source versions predict omitted/false requests become explicit false after create and nil after start on an unsupported OOM-disable capability. Nil normally serializes as null. A CLI explicit-false flag cannot prevent this source branch. This is not proof of our runner's daemon version, cgroup mode, actual transition, or exact CI4 failed bounds member.

CI3 observed only the OomKillDisable field name difference. CI4 observed grouped post-start bounds failure with comparisons not reached. Previously comparison diagnostics came after the rejecting resource predicate, obscuring the changed field. The renewed diagnostics move comparison observation before security rejection and split the unchanged strict predicate into fixed `oom_killer` gate. No resource admission, expected-record overwrite, normalization, equality relaxation, signaling authority or SDK launch is introduced.

Public diagnostics remain fixed enums, bounded invocation counters and allowlisted field names. Read-only Docker info is privately captured; only source-version class, cgroup class and OOM-disable capability class are emitted. Only a fixed OOM field-shape classification is emitted, never arbitrary serialized field values. These are diagnostic observations, not new authorization or kernel verification.

## Decisions pending runtime diagnostics

- Preserve literal false plus complete raw equality on affected stock cgroup v2: remain BLOCKED. Do not keep trying omitted/false CLI variants.
- Compatible/fixed engine: requires separately authorized environment/provisioning and independent review; do not start a new daemon, downgrade cgroups or patch the runner here.
- A phase-bound representation contract is a separate proposed contract revision, not yet authorized. It would retain the immutable raw precreated record and precompute any exact post-start expectation before birth, conditioned on trusted engine/cgroup evidence; compare the entire record, never drop fields or rebaseline from observed post-start data. It would also require container-owned kernel cgroup evidence for memory.max1GiB, memory.swap.max0, CPU1 and pids.max128. No such contract or kernel proof is implemented or accepted here.

[Docker resource documentation](https://docs.docker.com/engine/containers/resource_constraints/#--memory-swap-details) describes equal memory and memory-swap as no swap and OOM killer enabled by default. [Kernel cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html) distinguishes memory.oom.group from disabling the OOM killer. Neither documentation proves this runner's enforcement.

The renewed isolated diagnostic trial is for identifying this blocker under unchanged strict acceptance. Genuine lifecycle, independent cleanup and actual SDK integration remain unaccepted until separately established.

## CI5 diagnostic update

[CI5](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38181608392/job/114595176353) subsequently observed only OomKillDisable changing after successful strict pre-start false admission, with post-start shape unset_null; cgroup classv2 and daemon capability unsupported. This confirms this run's false-to-null representation change, not earlier runs' unpublished values. Engine classother_version does not establish either pinned source version, so an exact version-specific implementation cause remains unverified. Runtime and independent cleanup both rejected the OOM predicate; no completed lifecycle case or cleanup proof was accepted. See CI5_DIAGNOSTIC_RESULT.md. A NEW phase contract still requires explicit approval; namespace-local kernel limits alone do not certify exact container-owned cgroup identity, and live evidence after exit must be handled explicitly.
