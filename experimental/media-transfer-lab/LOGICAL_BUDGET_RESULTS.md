# Synthetic logical ciphertext file-length budget

## Inspected Linux evidence
- Run https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38164502992 ; job114544128863. Sourceb959d12841b5bfed389dadc4632622fb7794260e,workflowcee9b9029c0d15fc8483fa041d743d5b6340a504. Single CI run, total12s/job9s/test3s.
- Actual safe aggregate:6tests,6pass,0fail,0cancelled,0skipped;flat=true,runner_exit=0.39pre AND post exact source/policy pins verified.
- Independent always cleanup inspected:ownedtestprocessesalive0,stopped0,childrencreated0,containerscreated0,readonlyprocessinspection=true,private_namespace_absent=true. Logical unlink,notphysicalerasure.
- Independent review hjdadNlDTZLTVTcQ PASS revisedsourceonly; parent rejected initial inherited posthoc signal authority, implementer removed ALL signaling and regenerated pins before CI. No policy/core changes.
- Initial Windows require-path EPERM retained; maincontext generator/syntaxonly,notruntime. Actions Node20deprecation/forcedNode24 warning separate from testNode22,no operationalfix.

## Scope
Implementation worker launched no CI; parent inspected runtime and cleanup above.

New files only: logical-budget.mjs, logical-budget.spec.mjs, logical-budget-prepare.cjs, logical-budget-cleanup.cjs and isolated matrix-logical-budget-lab.yml. Existing receiver/attachment-stream/SDK/security policies unchanged. Helper is independent synthetic accounting, NOT wired into SyntheticReceiver or SDK.

## Intended evidence
- Generated AES-256-CTR ciphertext source: 8MiB, 32 x 256KiB. Keys/IV only in RAM, wiped after generation; no plaintext/key files, decrypt sink or plaintext-release proof.
- Exact complete source+cache file-length boundary 16MiB, with cache chunk hashes independently matching source slices.
- Ceiling one byte below projected first cache write: exact LOGICAL_BUDGET_EXCEEDED before mutation.
- Exact retry at full ceiling: same bytes/files/hashes; conflicting same-length retry: exact conflicting_retry, no replacement.
- New accounting object independently reads half-complete cache then finishes. This is object recreation, not process/app restart or crash recovery.
- Deliberately extended cached ciphertext: exact INVALID_CIPHERTEXT_LENGTH on inventory and new accept. Negative inventory snapshots include all source/cache names, lengths, permissions, owner and SHA256 before/after. No repair.

## Workflow and privacy
Branch lab-matrix-cleanup-followup only, push trigger only own new workflow path, plus manual dispatch. Node22/Linux. Prior immutable34 policy/source pins plus 4 new implementation files and 1 prior workflow (39) checked before AND after tests. New helper import pinned. Private owner0700 namespace and 0600 ciphertext/log files; raw TAP retained only in disposable private root, stdout exact safe aggregate. No artifacts/cache uploads. Independent always cleanup performs read-only /proc inspection matching suite argv, uid and private namespace environment. Any matching live test process or inspection failure blocks deletion and retains the root; no process signals are sent. CI timeout supervisor owns runner termination. Only after observed test-process absence does cleanup delete the exact owner-validated namespace and confirm its absence. Suite itself creates no children or containers; Node test runner workers are checked separately. No other suite namespaces removed.

## Explicit limits
Application regular-file length accounting under trusted single-owner sequential operations only. NOT native/physical filesystem quota, allocated blocks, free-space guarantee, concurrency control, adversarial filesystem protection, admission/security enforcement, durable atomic writes, powerloss, GB/RSS, browser/Android/Internet/MXC, actual authenticated SDK, physical erasure or operational capacity. Same-length source tampering is outside helper's trust model; helper hashes for inventory/retry comparison, not authenticity. Failed IO may leave an incomplete file; no crash-safe/repair claim.

## Local implementation status
Workflow generator ran in Node main-context eval without launching tests/children: immutable34 plus5 guards generated. Initial require-by-path attempt failed EPERM during Windows root realpath; no pass inferred from that attempt. No POSIX runtime execution attempted on Windows. Parent owns independent review, branch backup and Linux execution.
