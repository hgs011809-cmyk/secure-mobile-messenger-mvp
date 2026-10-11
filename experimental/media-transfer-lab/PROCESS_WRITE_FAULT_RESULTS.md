# Controlled pending-write process fault fixtures

Status: implemented and independent read-only review completed; Linux CI pending, no runtime pass claim.

## Scope
New synthetic fixture files only, unchanged receiver/crypto and admission/security policies. Separate actual child process with worker-local filesystem interception targets a deliberately truncated real chunk `.pending` write (131072 bytes, not an OS-generated short-write failure) and a complete/synced `.pending` (262144 bytes) before rename. Parent survives and keeps synthetic crypto material only in RAM. Neither power-loss durability nor whole-app/runner crash recovery is established.

Planned six flat cases: each of two fault boundaries with authorized restart/retry/hash verification, fresh mock authorization denial (`not_authorized`), and changed manifest denial (`manifest_changed`). Inspected existing setup discards pending files BEFORE checking persisted manifest equality. Changed-manifest fixtures therefore expect pending deletion and only assert committed manifest/chunks and sender source immutability. Unauthorized initialization must preserve even pending data. Exact aggregate results must be inspected before claiming completion. Existing ACK-idle 4/4 and actual SDK 5/5 remain separate evidence.

No real SDK authorization, MXC, Internet/Android transfer, new cloud services, deployments, capacity/spend or policy weakening. Private Linux namespace/IPC, no plaintext/key fixture files and no sensitive public logs. Controlled pending discard/retry is not filesystem repair or physical erasure.

## Runtime
Pending. Historical failures in earlier result files retained. Local shell quoting/Node absolute-path loader diagnostics are not test failures or syntax/runtime passes; main-context evaluation is the supported helper path.

## Review and cleanup
Independent read-only review found the boundary/restart/hash assertions sound but flagged cleanup scan identity as too broad. New-file-only fix independently re-reviewed: kill is marker-tracked PID/start/exact executable/entire argv/private root only, revalidated before signal; scan-only matches fail closed and are never killed. Worker zero-plaintext counters are fixed protocol vocabulary because the child has no decrypt path, not independent decrypt instrumentation; parent denial callback counters are genuine. Linux aggregate/runtime/always-cleanup inspection still pending. No container creation intended. Do not infer pass from source, a green badge, or the earlier suite.
