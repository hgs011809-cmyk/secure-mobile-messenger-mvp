# Build input inventory proposal, not executable build

2026-10-12 session xUq4vSVbtRJ6wxyc. Exclusive owned lock acquired; local readonly workflow56 pins verified, mismatch0, accepted profile absent. Fresh GitHub directory UI shows latest commit862a98d on lab-matrix-cleanup-followup. No install/build/pull/helper/worker/container/CI execution. Original Dockerfile and protected files unchanged.

## Runtime dependency finding
Read-only investigator Js7ilgS5MIGgM6EG inspected phase-worker.mjs/contract: runtime uses Node builtins and dynamically imports /opt/fixture/node_modules/playwright/index.mjs. No esbuild use; package.json build script is not invoked by worker. Lock esbuild0.28.2 hasInstallScript:true. Therefore propose future npm ci --include=dev --ignore-scripts, with PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 scoped to npm installation, retaining current locked dependency closure initially. Do not claim runtime proof from static imports. Do not remove dependencies/change package locks now.

This suppression variable controls npm installation hooks, not an explicit playwright install command. Removing the live --with-deps command requires a separate reviewed archive staging/extraction plan, OS package closure and installation marker/layout verification; this document provides no runnable replacement Dockerfile.

## Exact Debian12 x64 top-level dependency proposal
Pinned nativeDeps.ts was fetched HTTP200 through browser-backed fetch after PowerShell network lookup failed. Source: https://raw.githubusercontent.com/microsoft/playwright/606ecd8b34bac100db32561b6278ffd76e5eb3cd/packages/playwright-core/src/server/registry/nativeDeps.ts

Shared tools11: xvfb, fonts-noto-color-emoji, fonts-unifont, libfontconfig1, libfreetype6, xfonts-scalable, fonts-liberation, fonts-ipafont-gothic, fonts-wqy-zenhei, fonts-tlwg-loma-otf, fonts-freefont-ttf.

Chromium21: libasound2, libatk-bridge2.0-0, libatk1.0-0, libatspi2.0-0, libcairo2, libcups2, libdbus-1-3, libdrm2, libgbm1, libglib2.0-0, libnspr4, libnss3, libpango-1.0-0, libx11-6, libxcb1, libxcomposite1, libxdamage1, libxext6, libxfixes3, libxkbcommon0, libxrandr2.

These32 names are top-level Playwright source inputs, NOT exact versions/transitive apt closure or installed requirements proof. Preserve shared tools rather than silently dropping fonts/Xvfb. Debian snapshot candidates from BUILD_INPUT_REVIEW remain unvalidated. Required inventory per repository: exact dated import, suite/component/architecture, authenticated InRelease or Release+Release.gpg, trusted Debian signing key identity, Packages index size/SHA256 authenticated by Release, every selected/transitive deb name/version/architecture/size/SHA256 authenticated by Packages. Review base preinstalled package state as part of solving closure. No trusted=yes, signature bypass, sudo/capability/new privilege grant. Historical validity handling needs separate narrow review, not signature bypass.

## Chromium CLI archive set
Pinned registry/index.ts resolveBrowsers lines1280-1312 explicitly resolves chromium and chromium-headless-shell without shell override, adds ffmpeg for browser executables, deduplicates. Pinned browsers.json declares chromium/headless revision1248 browser156.0.8078.4 and ffmpeg1013. Thus inventory for the EXISTING install chromium command must include all THREE archive artifacts, not only browser ZIPs.

Sources:
- https://raw.githubusercontent.com/microsoft/playwright/606ecd8b34bac100db32561b6278ffd76e5eb3cd/packages/playwright-core/src/server/registry/index.ts
- https://raw.githubusercontent.com/microsoft/playwright/606ecd8b34bac100db32561b6278ffd76e5eb3cd/packages/playwright-core/browsers.json

Candidate Chromium URLs already documented in BUILD_INPUT_REVIEW. For each archive establish exact platform URL/redirect acquisition chain, byte length and SHA256, archive layout/executable/marker expectations, safe extraction containment and permissions. No browser/ffmpeg ZIP acquired or digest established in this run. Same-acquisition hash is trusted-acquisition byte pinning, not independent vendor authentication or malicious-content safety.

## Next bounded step and blocked gates
Independently review this document, then prepare a separate failclosed acquisition/inventory plan and non-executable Dockerfile delta with verified archive locations and authenticated apt closure. Do not change the existing Dockerfile until review and input pins are complete, because it is one of current56 pins. Future source/profile/parent pipeline must be separately reviewed before accepting profile or considering the at-most-one lifecycle attempt today. Build gates remain BLOCKED. No runtime rerun/relaxation/privileges; SDK/production out of scope. Earlier readonlyCI280+30 separate, two readonly compile failures and old strict five failures preserved. RetainedFD/trusted-host/postexit evidence limits unchanged.
