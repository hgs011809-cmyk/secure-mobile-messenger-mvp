# CI5: exact blocker identified, containment remains BLOCKED

| Evidence | Observed result |
| --- | --- |
| Run / job | 38181608392 / 114595176353 |
| Commit | ba4bd60cd962a7e9d0f52379a14e45c313717fbe |
| Linux pure contracts / source pins | 4/4 / 38 verified |
| Public image build / job duration | 37s / 43s |
| Actual accepted lifecycle cases | 0 |
| Strict pre-start OOM field | Literal false admission passed |
| Post-start rejection | gracefulwait / oom_killer |
| Only changed HostConfig field | OomKillDisable |
| Observed post-start field shape | unset_null |
| Config / HostConfig / state shape | equal / different / valid |
| Daemon diagnostic classes | cgroup v2; OOM-disable unsupported; other_version |
| Independent cleanup | Failed at cleanup_stop / oom_killer; same sole field and null shape |
| SDK integration | BLOCKED, not launched |

Create1/start1/completed0 are acknowledgment counters in this invocation, not child/Chromium completion or cleanup proof. Cleanup invocation zeros are not historical resource counts or absence. Cleanup daemon classes were not_observed, not copied from run data.

CI5 establishes a pre-start false to post-start null transition for this run only. It does not reveal or retroactively establish CI1-4 values. The runtime engine class does not match either pinned 28.5.1 or 29.0.0 source, so the exact source-version cause remains unverified. The result is consistent with the documented unsupported-capability mutation; no kernel enforcement, physical erasure, hard-runner-loss or production guarantee follows.

All five Linux runtime/cleanup failures remain failed. Local Node26 same-process data contracts4/4 and fixed projection checks19/19 are separate from Linux runtime. Windows launcher, test-discovery and report-format helper limitations remain recorded. Independent static review passed; this does not convert runtime failure to success.

## Next approval boundary

Do not repeat false/omitted CLI variants or relax the existing fixture. A NEW separately reviewed phase-bound fixture would require explicit contract-revision approval, immutable complete created/post-start expectations computed before birth, a pinned verified daemon/cgroup condition, and live container-owned namespace/cgroup/kernel-limit correlation. Namespace-local limits alone do not certify exact cgroup ownership. The design must explicitly handle unavailable live namespace evidence after exit. No such contract, provisioning, or SDK trial is authorized or implemented here.

Existing crypto/receiver/SDK/auth/admission/room/device/ingress policies, main, production app, NCP, deployment and capacity/cost settings remain unchanged. No automatic chain or new runtime follows this diagnostic checkpoint.
