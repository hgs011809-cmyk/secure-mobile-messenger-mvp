# Synthetic logical ciphertext file-length budget candidate

## Source candidate only
Runtime tests executed: 0. Expected Linux tests: 6 flat top-level cases. No pass/fail or cleanup-runtime claim until aggregate CI and independent always-cleanup logs are inspected. No CI launched by implementation worker.

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
