# Browser staging source findings, not archive validation

2026-10-12 session JVFWUc59oxbQOhoF. Readonly public source at Playwright commit606ecd8b34bac100db32561b6278ffd76e5eb3cd. No installer, browser archive, build, helper, worker, container or CI execution. ACQUISITION_GATES.md backup72fe8e3 [skip ci] freshly confirmed in GitHub directory UI; editor adds display blank spacing, remote byte equality not asserted.

## Platform and directory selection

packages/utils/hostPlatform.ts L109-114 chooses debian12-x64 for Debian version12 and os.arch x64; L131-140 maps short platform to linux-x64. The exact browsers.json objects for chromium1248, chromium-headless-shell1248, ffmpeg1013 contain NO revisionOverrides. Therefore registry/index.ts L461-476 uses ordinary revisions/directories chromium-1248, chromium_headless_shell-1248, ffmpeg-1013. This conditional source result is not observation of the future base filesystem or environment override.

## Actual download subprocess order

packages/playwright-core/src/server/registry/oopDownloadBrowserMain.ts L45-46 defines INSTALLATION_COMPLETE. L117-128 downloads first, removes the existing browser directory, extracts ZIP to browserDirectory, chmods supplied executablePath0755, writes an EMPTY completion marker. Parent directly checked lines: investigator fvVGuaz2cyfk3Lw3 incorrectly reported102-111 for this order; corrected before adoption. Marker is successful installer-flow bookkeeping, NOT approved archive hash/tree proof. index.ts L1049 names a separate DEPENDENCIES_VALIDATED marker; full validation write/skip conditions remain pending.

## Extractor behavior relevant to safe replacement

Correct helper location is packages/utils/third_party/extractZip.ts, not packages/playwright-core/src/utils (404). L69-114 uses yauzl lazyEntries; skips __MACOSX entries; creates parent directories, realpaths parent, rejects relative parent containing '..'. L136-159 derives file type and permission bits, masks modes to0777. L175-180 reads ZIP symlink payload and creates that symlink directly; regular files use createWriteStream without explicit exclusive/no-follow flags here. L207-215 requires absolute output root, creates it and realpaths it. These are source observations, NOT a demonstrated exploit or comprehensive path-safety audit. No literal target allowlist, duplicate-destination checks or our proposed finite aggregate extraction caps were established in this helper; yauzl dependency behavior has NOT been audited. Do not reuse this installer as the strict inventory/staging admission boundary without separate review. Full frozen tree/links/modes/hash validation and controlled new empty root remain mandatory.

## Next actionable gates

Read dependency-validation marker conditions and pinned yauzl source/tool requirements; choose a separately reviewed bounded archive-inventory implementation before downloading/extracting any browser archive. Three ZIP sizes/hashes/manifests still absent. Independently authenticate Debian signing-key/Release/Packages chain and base dpkg inventory, then closure. Original Dockerfile and accepted-profile absence remain unchanged; no privilege/host access fallback. Existing readonly280+30 and failures remain separate, no SDK/runtime acceptance.

Sources (prepend https://raw.githubusercontent.com/microsoft/playwright/606ecd8b34bac100db32561b6278ffd76e5eb3cd/):
- packages/playwright-core/browsers.json
- packages/playwright-core/src/server/registry/index.ts
- packages/playwright-core/src/server/registry/oopDownloadBrowserMain.ts
- packages/utils/hostPlatform.ts
- packages/utils/third_party/extractZip.ts
