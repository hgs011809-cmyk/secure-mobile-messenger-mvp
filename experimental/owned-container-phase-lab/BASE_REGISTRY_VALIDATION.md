# Readonly pinned base validation, not runtime acceptance

Observed 2026-10-12, session 2026-10-12_xGvkiVwGXrpq6zar. Registry manifest/config fetched via browser-backed HTTP after Node CLI fetch failed. No pull/build/helper/worker/container/CI execution.

- Exact manifest SHA256: efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562; 1929 bytes; OCI schema2. Returned Docker-Content-Digest matched; independently SHA256-hashed downloaded bytes matched.
- Config SHA256: d0a16be756b6ec6658aecb8b7bcf87fa6c7d0d7fcc6ca53ad14bb49a4c90bdd7; 6771 bytes, matching manifest config size and digest.
- Config declares linux/amd64; NODE_VERSION=22.23.3; YARN_VERSION=1.22.22; PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin. Entrypoint [docker-entrypoint.sh], Cmd [node], default User and WorkingDir empty. Five compressed layers and five rootfs diffIDs declared. Layers were NOT downloaded, applied or verified. No executed Node-version/binary or publisher provenance claim.
- Manifest annotations name docker-node revision 81f419144a1251854c6d9afb09eaa39928e724e8 and debian:bookworm-slim base digest a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91. These are declarations, not authenticated provenance.

Independent read-only dependency review v31RPEagdlq0VIlA: lockfile3 pins npm graph/tarball integrity; esbuild hasInstallScript true and npm ci allows scripts. Playwright --with-deps downloads browser/apt inputs not pinned by lockfile. No fully immutable/offline build established.

Next: review exact Playwright1.64.0 browser revision/download verification and Debian snapshot/package pinning; decide minimal new Dockerfile build changes (without modifying old fixture), then separately review parent workflow with literal source pins, five-file context, pinned BASE/platform, exact imageID/full environment checks and reviewed C compile/digest export. A digest-pinned base does not close mutable build input gates. accepted-engine-profile.json remains absent. No runtime authorization is inferred.
