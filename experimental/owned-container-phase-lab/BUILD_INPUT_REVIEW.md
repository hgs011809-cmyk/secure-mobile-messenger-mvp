# Build dependency lock preparation, no runtime acceptance

Observed 2026-10-12 session M1bY29pmDfHWK4Q5. Remote lab branch 91f5953485080dcfe4d7f5781096d61162d86790 freshly observed. Local source56 zero mismatches; old fixture untouched; accepted profile absent. No npm/install/build/pull/helper/worker/container/CI execution.

## Playwright source review
Readonly independent investigator YYKsamwxVF1pGGlO inspected exact public version1.64.0 and local lock: test -> playwright -> core all1.64.0. Registry gitHead606ecd8b34bac100db32561b6278ffd76e5eb3cd; Chromium and headless shell revision1248/browser156.0.8078.4. This is source/package metadata, not downloaded browser validation.

References:
- https://registry.npmjs.org/playwright-core/1.64.0
- https://unpkg.com/playwright-core@1.64.0/browsers.json
- https://raw.githubusercontent.com/microsoft/playwright/606ecd8b34bac100db32561b6278ffd76e5eb3cd/packages/playwright-core/browsers.json
- https://raw.githubusercontent.com/microsoft/playwright/606ecd8b34bac100db32561b6278ffd76e5eb3cd/packages/playwright-core/src/server/registry/oopDownloadBrowserMain.ts L64,79-86,118-128
- https://raw.githubusercontent.com/microsoft/playwright/606ecd8b34bac100db32561b6278ffd76e5eb3cd/packages/playwright-core/src/server/registry/browserFetcher.ts
- https://raw.githubusercontent.com/microsoft/playwright/606ecd8b34bac100db32561b6278ffd76e5eb3cd/packages/playwright-core/src/server/registry/index.ts L117-147,1066-1094

Inspected installer requires HTTP200, conditionally checks Content-Length (nonchunked only), extracts/chmods and writes INSTALLATION_COMPLETE; no expected browser archive cryptographic digest comparison found in this flow. npm lock integrity covers npm package, not browser ZIP. Derived default Linux x64 URLs use browser version, not revision path:
- https://cdn.playwright.dev/builds/cft/156.0.8078.4/linux64/chrome-linux64.zip
- https://cdn.playwright.dev/builds/cft/156.0.8078.4/linux64/chrome-headless-shell-linux64.zip
These archive URLs were NOT downloaded or availability/hash verified. Other install artifacts such as ffmpeg must also be inventoried if required. No archive digest established.

## Debian snapshot preparation
https://snapshot.debian.org/ documents dated apt snapshots and earlier-timestamp resolution when an exact import does not exist. Readonly machine API https://snapshot.debian.org/mr/timestamp/ returned actual candidates: debian20261006T203214Z and debian-security20261006T205323Z. They are selection candidates ONLY, not verified Release signatures/index/package hashes or package availability. Query archive/year/month on the API did not narrow the response; explicitly filter the returned archive list.

## Next implementation gates
1. Keep Node22 amd64 digest already validated as candidate; do not replace it with a Playwright image without redoing Node22/env/base review. Investigate exact nativeDeps for Debian12 and Chromium-only required archives from pinned Playwright source.
2. Prepare separate new Dockerfile changes: npm ci --include=dev --ignore-scripts with browser-download suppression. esbuild install hook should not run merely to provision this fixture; verify worker dependency usage first. This is a proposed change, not yet made/tested.
3. Replace live --with-deps with explicit reviewed apt package list, observed exact snapshot imports and signed Release/Packages/deb SHA256/version closure. Never trusted=yes or global authentication bypass. If expired snapshot metadata needs narrow validity handling, independent review must distinguish historical metadata freshness from signature authentication; no change is accepted now.
4. Retrieve required browser/helper archives readonly into controlled private files, record size+SHA256 and acquisition source, independently review byte pins and completeness, then future build verifies those literal digests BEFORE extraction. A same-download hash pins observed bytes under trusted HTTPS/acquisition boundary; it does not independently authenticate vendor origin or malicious-content safety. Do not claim upstream checksum verification when none is available.
No elevated privileges, sudo/caps/setns/hostPID/hostmount or host-workload PID signals may be introduced by acquisition/build/lifecycle work; existing restrictions stay unchanged.

5. Update minimal context/pipeline pins only after changes and independent review; preserve old38. Build, profile acceptance, helper and lifecycle remain blocked until all gates. At most one separately reviewed lifecycle attempt today; no new CI after23:45KST, stop by23:59.

Readonly public metadata lookup and source investigation are not install/build/runtime proof. Existing readonlyCI38218708450 (280+30 separate), two readonly failures and five old strict failures preserved. RetainedFD and trusted-host evidence limits unchanged; SDK/production remain outside scope.
