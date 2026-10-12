# Exact image/build input candidate, not runtime authorization

Observed 2026-10-12 in scheduled session dgNFuBKTcXKl5NqV. Current remote lab branch UI showed backup 92da5d5. All 56 readonly workflow source pins checked locally: zero mismatches. No helper, worker, build, pull, workload container or CI launched in this run. Old fixture unchanged.

## Base selection candidate

Public Docker Hub metadata https://hub.docker.com/v2/repositories/library/node/tags/22-bookworm-slim returned tag updated 2026-10-06, index digest sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 and linux/amd64 child digest sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562.

Proposed literal BASE: docker.io/library/node@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562 with explicit linux/amd64 build/pull platform. This is API-reported metadata ONLY: registry manifest bytes/digest, config OS/architecture, exact Node22 version, default environment, image provenance and image availability are not verified. Do not dynamically resolve the tag at lifecycle time or reuse old workflow's first matching RepoDigest. Before accepting this candidate, independently review registry manifest/config and supported Docker parent pipeline. No accepted profile is created by this document.

## Minimal context input inventory (SHA-256)

- Dockerfile: 63c0ff305f296e16adc239ea42ea25d44adfdce4dfe05f967ab981459e2caba5
- phase-worker.mjs: fbc461bb5bbc2cf845b812e252b23f2d56dbd7ca97908f266dfd305cbab1bfc4
- phase-worker-contract.mjs: 95d424c671f5d0d453061ee3f3c5e09ac88a99ac8ffa44b6ffd8715c01dab980
- ../matrix-client/package.json: 33f10febea5c27104d4fdadef2b52a8819aa784a25047ccf4afec7f3f42cc0cc
- ../matrix-client/package-lock.json: af8f94989d03eb33cd42ff8e4ee04f935248405b606137eff249ede0136efbba

Actual context must contain ONLY these five regular files at their repository-relative paths, copied after checks into an exclusive owner-only directory; reject links/unexpected entries and verify copied bytes again. Do not submit the repository, runtime profiles, native helper, logs or credentials as context. Pin this inventory and complete existing 56 pins literally in reviewed parent workflow before build; no regenerated self-pins or changed old 38.

Existing package declares matrix-js-sdk43.0.0, esbuild0.28.2, @playwright/test1.64.0. Dockerfile runs npm ci --include=dev and Playwright Chromium --with-deps. Lockfile bytes pin npm resolution, NOT all downloaded browser/apt bytes. Current install allows package scripts and live apt/browser downloads; dependency execution/network build is a trusted public-dependency build boundary, NOT fully reproducible or offline build. Separate workload containers remain network-none. Review scripts, browser revision/checksum behavior and apt inputs before pipeline acceptance; do not silently claim an immutable base makes all build inputs immutable.

## Future parent workflow gates, not executable workflow

1. Exact lab branch, finite today's authorization, exclusive owned lock, independently reviewed workflow/source/image/profile. Do not launch new CI after23:45 Asia/Seoul, no extension past23:59.
2. Verify literal old38/full56 and additional image-plan/context pins. Require registry manifest/config candidate validation. No fallback tag or platform.
3. Build the minimal reviewed context with explicit pinned BASE/platform, bounded private capture. Require owned exclusive iidfile with canonical sha256 imageID, inspect exact imageID and independently check architecture/OS/Node22 and full image config/environment. No workload/helper execution merely to grant profile acceptance.
4. Compile exact reviewed kernel-fd-probe.c via cc -std=c11 -O2 -Wall -Wextra -Werror into private owned runtime root. Export literal reviewed C digest and just-built ELF digest using the already reviewed provenance module in THIS workflow. Preflight temporary binary is not transferable authority. Controller requires owned0700/nlink1 binary and expected digests before create/every reuse.
5. Only after independent source/profile/parent pipeline review passes may accepted-engine-profile.json be separately considered. Keep it absent now. Predeclared path/CPU values remain expectations, with actual kernel gates failclosed.
6. At most ONE separately reviewed isolated lifecycle CI in today's window after all gates. Two mode cases are proposed, not completed. Verify exact-ID durable phases, retained-FD live kernel/nonce correlation, memory1GiB/swap-only0/CPU1/pids128 and mandatory private/nonroot/capdrop/readonly/network-none/no-newprivileges controls; separate independent always cleanup. Any unknown permission/layout/runtime failure closes this attempt: no automatic rerun/relaxation/fallback/new privileges/host workload PID signals.

Hashing proves byte integrity within trusted host/compiler/daemon/build boundaries, not malicious-host authenticity or semantic binary proof. Worker namespace report is not independent protected host namespace evidence; retained-FD window is not atomic/continuous hostile-host protection; after exit no live kernel revalidation. SDK/production/Android/Internet/MXC/GB-RSS/physical erasure/powerloss remain unproved and outside this candidate.

Next actionable step: readonly registry manifest/config validation and independent build-dependency/pipeline review, then implement a separately reviewed parent pipeline. This document does not authorize helper/container execution.
