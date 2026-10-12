# Archive byte-inventory candidate checkpoint, not acquisition acceptance

Owner IcUJ8UMoJUKXJWiB, renewed authorization 2026-10-13 through 12:00 noon Asia/Seoul; no new CI after 11:45. Original archived lock/recovery audit preserved. Exact current lock owned by this session.

## Observed direct execution

- Original unpublished archive-inventory.spec.cjs: PASS 128 synthetic checks, exit 0, direct Node require with --preserve-symlinks --preserve-symlinks-main. No spawnSync or Node --test discovery.
- Empty inventory/duplicate decoded JSON keys/path complexity fixes: PASS 136 checks, exit 0.
- Independent review BKkxwKJZ4UwJ9YWn found post-JSON.parse numeric rounding allowing fractional source claims and invalid-cap test masking by empty inventory. Corrected parser to accept only canonical nonnegative decimal safe-integer tokens, rejecting decimal/exponent/-0/oversized integers before rounding. Corrected cap tests and added exact path/segment/depth boundaries. Direct PASS 145 synthetic checks, exit 0; independent source-only correction review BKkxwKJZ4UwJ9YWn PASS. Subsequent digit-token length guard limits BigInt conversion to 16 characters; same145 direct checks pass.
- Protected workflow literal pins: all 56 present and matched; accepted-engine-profile.json absent. Original Dockerfile and old strict fixture unchanged.
- NEW zip-byte-inventory.cjs / .spec.cjs implementation worker kWpnFzaUurmfWowy reports actual direct PASS 99 synthetic tests, exit 0, elapsed 36 ms. Independent review 76PD58BSSHeKD711 independently reproduced99 PASS, but found decorated Buffer length/valueOf getter cap bypass and post-JSON.parse numeric rounding. Fixed with intrinsic TypedArray length/buffer getters, intrinsic Uint8Array.set private snapshot, SharedArrayBuffer rejection and canonical <=16-character safe-integer numeric tokens. Added9 regression checks: parent actual direct108 PASS, exit0, 27ms; independent correction review76PD58BSSHeKD711 PASS with exact hashes matched and independent direct108 PASS, 29ms, exit0. Additional matching-value numeric/getter/offset/spoof probes passed. Runtime built-ins must be trusted and unmodified. No extracted payload execution.

## ZIP candidate scope

Narrow stored/deflate Unix ZIP32 parsing with independently supplied archive length/SHA256, explicit finite caps and complete expected tree/path/type/mode/size/hash manifest. CRC and output digest checks bind decoded bytes; complete local/central layout, metadata and archive boundary checks reject unsupported input. Symlinks, ZIP64, descriptors, extras, comments and special types deliberately fail closed. This may reject real browser archives and is not a general ZIP parser safety audit.

Current synthetic hard ceilings are archive 16 MiB, output 32 MiB, entry 8 MiB, 512 entries, path 512/depth16/ratio100. These are NOT observed or approved Playwright browser requirements. No real archive was acquired, no approved literal vendor/archive pins or tree manifests exist. stagingImplemented:false, no filesystem staging runtime. Candidate is not usable as an accepted browser acquisition/build gate.

## Debian bootstrap finding, not authentication execution

Read-only investigator BqcQnYVzm5YuX7qh identified a concrete conditional trust chain: existing trusted GitHub Ubuntu runner's package-managed Ubuntu archive keyring -> signed Ubuntu Noble InRelease -> authenticated universe Packages -> exact debian-archive-keyring 2023.4ubuntu1 all package -> data-only suite keyring extraction -> Debian signed Release. This relies on explicit approval of Ubuntu distribution packaging authority for Debian keys, not direct Debian authentication of the Ubuntu package. No install/import/source modification/script execution is necessary in principle. Preexisting runner keyring/tool availability and all actual signed bytes/digests/signer/freshness policies remain unverified. No CI or chain execution yet.

Sources: https://documentation.ubuntu.com/security/software-integrity/archive-verification/ ; https://documentation.ubuntu.com/security/software-integrity/image-verification/ ; https://packages.ubuntu.com/noble/debian-archive-keyring ; https://packages.ubuntu.com/noble/all/debian-archive-keyring/filelist ; https://manpages.debian.org/bookworm/dpkg/dpkg-deb.1.en.html ; https://manpages.debian.org/trixie/gpgv/gpgv.1.en.html

## Preserved limits and next work

No new CI/build/install/image pull/helper/worker/container lifecycle, accepted profile, kernel ownership/cleanup or SDK proof. Existing readonly run38218708450 source56/pure280+30 and prior failures remain separate. Trusted host/compiler byte-integrity is not malicious-host/compiler authenticity. Continue independent candidate review, then bounded approved real-archive acquisition and staging implementation with separately frozen pins; prepare narrowly reviewed no-container authenticated Ubuntu-to-Debian metadata bootstrap. Signed package closure/base inventory and maintainer-script review still block build. Ordinary checkpoints do not end the renewed continuous window.
