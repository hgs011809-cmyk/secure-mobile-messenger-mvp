# Phase fixture implementation API v1 (proposed, no runtime acceptance)

Scope: trusted isolated CI host/daemon/runtime/pinned image; no atomic or continuous adversarial-host protection. No new privileges, setns, mounts, host-PID sharing, host workload signals, SDK or production. Existing strict fixture remains blocked unchanged. Engine/runtime exact profile must be reviewed and pinned before any container start. Permissions/unknown layout fail closed.

## Immutable controller plan

After Docker create admission and BEFORE start, persist with exclusive create/fsync/0600 under owner-only0700 root:

- exact64hex ID, image sha256ID, run/nonce64hex, mode graceful/linger;
- exact engine/runtime/API/cgroupv2/driver/unsupported-OOM profile;
- full created Config, full created HostConfig;
- full planned poststart HostConfig = deep clone, ONLY own OomKillDisable false replaced with null;
- observer namespace baselines PID/cgroup/mount/time.

Exact plan topkeys: version,identity,engineProfile,config,hostConfigCreated,hostConfigPoststart,observerNamespaces. Identity keys: exactId,exactImageId,run,nonce,mode; use identity.mode only. EngineProfile17flatkeys: exactServerVersion,exactServerGitCommit,apiVersion,cgroupVersion,cgroupDriver,defaultRuntime,runcVersion,runcGitCommit,containerdVersion,containerdGitCommit,hostCgroupPathTemplate,hostCgroupMountRoot,hostCgroupMountPoint,expectedCpuQuota,expectedCpuPeriod,expectedCpuBurst,oomDisableCapability. Profile types: cgroupVersion canonical string `2`, oomDisableCapability false, CPU quota/period/burst canonical decimal strings; exactImageId `sha256:<64hex>`, namespace key mount has raw tag `mnt:[digits]`. Profileacceptance/source matching is controller responsibility. Pure kernel validator also rejectsunknownschema keys but does not grant engine acceptance.

Never overwrite/rebaseline expectations. Preserve creation hard controls; explicitly OomScoreAdj0. Complete Config equality all phases. Full HostConfig equality: created before start intent; poststart after successful start. Durable start-intent unresolved permits either exact predefined complete snapshot for cleanup only, never case acceptance. Terminal-after-start requires poststart snapshot. Unknown third shape/state rejects. No raw metadata public.

## Native read-only anchor helper

NEW `kernel-fd-probe.c`, normal CI UID, no privilege fallback. CLI exactly `<exactId> <observedHostPid> <systemd|cgroupfs>`; require Linux CI/GITHUB_ACTIONS. Hold proc directory O_PATH FD, mapped cgroup directory FD, preferably pidfd for POLLIN only. All process file reads via retained procFD/openat (stat,cgroup,oom_score_adj); never later numericPID lookup. Read helper own mountinfo/ns identities, NOT target protected ns/mountinfo/root. Intentional proc directory and observer-own namespace references are explicit; no namespace entry/signals/writes.

Admit one unambiguous host cgroup2 mount profile root `/`, mountpoint `/sys/fs/cgroup`. Systemd exact membership `/system.slice/docker-<fullID>.scope`; cgroupfs exact `/docker/<fullID>`. Map relative to verified host mount; retain directory FD, use openat2 beneath/no-symlink/no-mount-crossing for children after verified mount-root entry. Reject deleted/escape/unknown/extra components. Require fstat dev+inode and fstatfs cgroup2 magic, domain cgroup. Reads must actually succeed; O_PATH success alone is not proof.

Outputs PRIVATE newline JSON only:

`{version:1,op:"begun",facts:HostFacts}` then waits boundedly for stdin exactly `finish\n`, outputs `{version:1,op:"finished",facts:HostFacts,processStayedAlive:true}`. Max window30s, fixed errors `{version:1,op:"blocked",gate:<fixedenum>}`; no exception/path/raw output on errors. Parent captures stdout privately. Closing stdin/errors exits helper; direct helper CLI cancellation is not host workload signaling.

HostFacts exact keys:

- `pid`, `startTicks`, `state`, `membership`, `oomScoreAdj`;
- `procAnchor:{device,inode}`;
- `cgroupRoot:{device,inode,fsType,mountRoot,mountPoint,mountDevice}`;
- `observerNamespaces:{pid,cgroup,mount,time}`;
- `bounds:{memoryMax,memorySwapMax,cpuQuota,cpuPeriod,cpuBurst,pidsMax,cgroupType}`.

Decimal integers are canonical bounded strings; namespace strings exact type:[digits]. fsType fixed `63677270`. Expected memoryMax1073741824, memorySwapMax0, cpuQuota100000/cpuPeriod100000, cpuBurst0, pidsMax128,cgroupType domain, PID1 oomScoreAdj0. Task state must be nonterminal R/S/D/I at each observation; normal R↔S transitions are not identity drift. Before/after identity/membership/bounds/observer mapping equal; proc/cgroup FDs retained. pidfd exit must reject. Exact-ID Docker inspect brackets helper session, same PID and running complete metadata.

## Worker PID1 server and exact-ID exec client

NEW `phase-worker.mjs`, genuine fixed Node fork and Playwright Chromium; ONLY synthetic about:blank DOM. Nonroot10001, readonly root/no-network/capdrop, own0700tmpfsdir/profile/socket. Baseline imageEnv exactly old four keys plus HOST_PID_NAMESPACE/HOST_CGROUP_NAMESPACE/HOST_MOUNT_NAMESPACE/HOST_TIME_NAMESPACE. PID1/client must have same PID/cgroup/mount/time namespace; PID/cgroup/mount differ from host observer, time equals host for comparable startticks.

Server holds PID1 at `ready` after observing live genuine Node child + main Chromium executable and ancestry, and at `result_ready` before graceful exit or timeout stop. One fresh nonce64hex per challenge, reject replay/duplicate/unknown milestone/fields. A never-seen nonce may supersede a pending challenge at the SAME actual milestone for independent cleanup: permanently consume/invalidate the old nonce/release, keep only the newest outstanding nonce, and retain bounded history without eviction. No phase rollback or simultaneous active challenges. On nonce-history bound exhaustion reject; stateful replay controls remain required. Client via exact-ID Docker exec `node phase-worker.mjs --challenge <nonce> <milestone>`; release via `--release <nonce>`. Client talks to PID1 server at fixed private socket, response comes from server, not independent self-report alone. Exact socket request shapes: challenge {version:1,op:"challenge",nonce,milestone,pid}; release {version:1,op:"release",nonce,pid}. Challenge CLI stdout is Witness only; release stdout is {version:1,op:"released",nonce,milestone}. Failure client exits1 without raw stderr; server may return fixed {version:1,op:"blocked",reason:"worker_evidence_unverified"}. Release flush/ack/client-exit draining is bounded before graceful PID1 exit so successful exec completion is not falsely inferred. Trusted fixture client/worker boundary, no claim of OS peer-credential authentication. Server verifies supplied live client process evidence; client PID differs from1.

PRIVATE Witness exact keys:

`{version:1,nonce,milestone,init,client,cgroupRoot,containerMount,bounds,children,caseResult}`.

- init/client = `{pid,startTicks,state,membership,oomScoreAdj,namespaces:{pid,cgroup,mount,time}}`; init pid1, membership`0::/`, oomScoreAdj0; client same memberships/namespaces, nonterminal. State each nonterminal, not exactR/S matching.
- cgroupRoot = `{device,inode,fsType}`; dev+inode/fsType match host mapped FD.
- containerMount = `{root,mountPoint,mountDevice,filesystem,readOnly,unexpectedOvermounts}`; root `/`, mountPoint `/sys/fs/cgroup`, fs cgroup2, readonlytrue, overmountsfalse; device mapping matches actual cgroupRoot.
- bounds same exact HostFacts bounds.
- children at ready and linger result_ready: exactly node_child and chromium_main evidence `{role,pid,startTicks,state,membership,oomScoreAdj,namespaces,executableClass,ancestorToInit}`; same membership/namespaces, nonterminal, oomScoreAdj0 for these two main processes, classes node/chromium_main, true ancestry. Not proof of every browser descendant's OOM score or membership.
- graceful result_ready children empty after acknowledged node exit0/no signal, bounded browser close, no live observed browser descendants, profile removed. Keep PID1 alive for second proof.
- caseResult = `{mode,childObserved,browserObserved,childrenAlive,childClosed,browserClosed,profileRemoved,childCount}`; ready/lingerresult: true,true,true,false,false,false,1; gracefulresult: true,true,false,true,true,true,1.

After validated ready proof, release allows graceful close or linger readiness. After validated graceful result proof release permits PID1 exit0. Linger PID1+Node child ignoreTERM, Playwright automatic signal handlers disabled; after second live proof parent exact-ID Dockerstop3s must yield137, no release needed.

## Pure kernel contract module

NEW `kernel-contract.cjs` exports `validateLiveWitness(plan,before,witness,after,expectedNonce,expectedMilestone)` only, no workload side effects. Before/after inputs are HostFacts, not helperenvelopes; controller independently validates samehelper session/envelopes. Sixth milestone argument is mandatory and matches witness exactly. Pure validator checks nonce correlation only; stateful replay prevention lives in controller/worker and is not claimed by pure tests. Reject exact error `KERNEL_PROOF_UNVERIFIED` on unknown/malformed/extra/replay/identity/bounds/layout/correlation. Do not mutate input. Verify host PID/startTicks, retained anchor identities, expected profile path, proc/worker startTicks equality with time namespace agreement, worker root dev+inode/fsType matching host, observer namespace correlation, all bounds, role/milestone results. Full plan acceptance/engine ownership stays controller responsibility. No data validation is lifecycle proof.

## Cleanup and proof limits

No case count until BOTH live milestones and required terminal exit. Independent cleanup revalidates immutable exact-ID/full-phase metadata. Running cleanup needs a new live proof before stop; stopped/absent paths do not claim live revalidation. Saved PID/cgroup proof records are detection only, never signaling/removal authority. Only Docker exact-ID stop/remove, strict terminal state, exact-ID NoSuchContainer and residual detection/private-root checks can establish limited cleanup. Kernel read permission or schema gaps remain failclosed, not solved by sudo/caps or broad label/PID kill. No physical erasure/hard-runner-loss/GB/RSS/real-user/SDK/production claims.
