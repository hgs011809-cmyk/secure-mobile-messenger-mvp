# Build integrity and engine-profile gates, not lifecycle acceptance

## Verified checkpoint

Readonly CI [38217074965](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38217074965), commit `7444dd988ec96ce76bfea584b4e0ebce50333fa0`: 51 source pins verified; C compiled with `cc -std=c11 -O2 -Wall -Wextra -Werror`; four pure suites 280/280. Native helper and worker were not executed, and zero workload containers were created. Earlier two readonly failures and old strict fixture's five failures remain separate and preserved.

## Candidate is not accepted

`engine-profile-candidate.json` contains the exact 17-key schema: eleven observed software metadata fields and six predeclared layout/CPU expectations. The observed fields are not installed-binary authentication. Expected `/system.slice/docker-{id}.scope`, mount root `/`, mountpoint `/sys/fs/cgroup`, CPU quota/period `100000/100000`, burst `0` are source-supported expectations, not a verified host layout or kernel write. `accepted-engine-profile.json` must remain absent until independent profile and parent-pipeline review passes. The candidate file is never substituted automatically.

The mandatory contract remains memory 1 GiB, swap-only zero, one CPU, and pids **128**, not 64. Live retained-FD reads must prove exact values. Missing swap control, unsupported CPU burst, unknown mount layout, or permission failures reject; there is no privilege or policy fallback.

## Public source support, narrowly

- Docker 28.0.4 source: `6430e49a55babd9b8f4d08e70ecb2b68900770fe`, Apache-2.0. Earlier review supports only the precomputed `OomKillDisable: false -> null` phase difference and stated CPU/swap conversions. No arbitrary null acceptance or post-start rebaseline.
- runc v1.5.1: `8f2685a471d3347a686ad3909783d8aafc6bb208`, Apache-2.0. Vendored cgroups CPU quota/period: [cpu.go L54-L68](https://github.com/opencontainers/runc/blob/8f2685a471d3347a686ad3909783d8aafc6bb208/vendor/github.com/opencontainers/cgroups/fs2/cpu.go#L54-L68). Swap conversion: [utils.go L443-L471](https://github.com/opencontainers/runc/blob/8f2685a471d3347a686ad3909783d8aafc6bb208/vendor/github.com/opencontainers/cgroups/utils.go#L443-L471). Zero swap and memory: [memory.go L44-L66](https://github.com/opencontainers/runc/blob/8f2685a471d3347a686ad3909783d8aafc6bb208/vendor/github.com/opencontainers/cgroups/fs2/memory.go#L44-L66). Important: source may silently ignore missing swap control when disabling swap; only the independent kernel check can establish it.
- Positive pids limits, including 128, use the supplied positive value: [pids.go L16-L37](https://github.com/opencontainers/runc/blob/8f2685a471d3347a686ad3909783d8aafc6bb208/vendor/github.com/opencontainers/cgroups/fs2/pids.go#L16-L37). Systemd scope/path composition: [common.go L62-L105](https://github.com/opencontainers/runc/blob/8f2685a471d3347a686ad3909783d8aafc6bb208/vendor/github.com/opencontainers/cgroups/systemd/common.go#L62-L105), [v2.go L430-L479](https://github.com/opencontainers/runc/blob/8f2685a471d3347a686ad3909783d8aafc6bb208/vendor/github.com/opencontainers/cgroups/systemd/v2.go#L430-L479). Valid slice syntax is required.
- containerd v2.3.6: `ee2735368117d2eb259779949d5e75cdafec9761`, Apache-2.0. [Source runc version pin L1](https://github.com/containerd/containerd/blob/ee2735368117d2eb259779949d5e75cdafec9761/script/setup/runc-version#L1) is v1.5.1. Configurable runtime binary/systemd options prevent treating version-pair support as installed runtime selection or provenance.

## Parent build-integrity gate being prepared

1. Verify literal SHA-256 pins for old protected sources, reviewed C, new modules, candidate, documentation and Dockerfile before compile or build. Preserve old 38 pins unchanged.
2. Compile that C with the reviewed command. Compiler failure cannot produce an accepted build record.
3. Read owned regular source/binary through bounded retained FDs, reject links/permissions/races/overflow and validate the expected ELF64 little-endian amd64 header. Match C against an explicit literal reviewed-source digest, then hash the just-built binary.
4. Export `PHASE_KERNEL_SOURCE_SHA256` as that literal reviewed digest and `PHASE_KERNEL_BINARY_SHA256` as the verified just-built digest only after success. The helper's existing metadata file is consistency-only, not authentication.
5. Pure tests and readonly compile/export CI still do not execute the helper. A temporary binary removed after preflight cannot be reused or claimed as runtime-ready.

## Still blocked before lifecycle

Independent parent-pipeline and candidate-profile review, pinned base-image selection/build inputs, actual runtime choice/layout, permissions, PID1 nonce milestones, live kernel ownership/limits, and independent exact-ID cleanup remain gates. The future lifecycle workflow must perform the same reviewed compile and digest-export in its own controlled namespace before using its binary; preflight hashes are not transferable runtime authority.

Hashes mean integrity under the trusted isolated host/daemon/runtime/compiler/workflow boundary, not authentication against a malicious host/compiler or continuous/atomic containment. No helper execution, container acceptance, physical erasure, hard-runner recovery, SDK integration, production readiness, main/NCP/provisioning/privilege/policy change is established here.

## Prepared gate review, not new CI acceptance yet

Independent static reviews: candidate schema/framing PASS; bounded build-provenance module PASS for controlled CLI; parent compile/export workflow PASS. Module synthetic tests 30/30 via direct Node entry. First local Node --test discovery attempt failed before test registration; preserved, not counted as a test pass. Parent synthetic exporter FS/VM checks 25/25; prior bounded compiler projector regression checks 20/20. Neither VM suite wrote a real environment file or executed compiler/helper/container.

The exported in-process module API is limited to controlled ordinary input objects. Arbitrary getters/proxies/symbol/nonenumerable extras are not a supported security boundary; CLI constructs its own argv-string object. New source-protected count is 56, preserving old 38. Await isolated NO-CONTAINER compile/export CI evidence. Candidate remains unaccepted; lifecycle image/base/runtime/kernel/cleanup gates remain pending.
