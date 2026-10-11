# Pending ciphertext logical-length accounting candidate

Status: source candidate only. No tests executed locally; Linux aggregate and independent cleanup evidence pending parent-run isolated CI. This is a separate read-only projection helper, not receiver integration, interrupted-write repair, security enforcement, atomic/concurrent reservation, physical quota, fsync/powerloss durability, SDK, Android, Internet, GB or RSS evidence.

## Six flat Linux-only cases
1. Real synthetic AES-256-CTR source 8MiB, committed 256KiB, half pending 128KiB and full pending 256KiB: actual lengths counted.
2. Existing half pending counted once, only remaining 128KiB projected; exact boundary accepts projection, one-byte less rejects `LOGICAL_BUDGET_EXCEEDED` with unchanged names/lengths/hash/mode/uid inventory.
3. Identical full pending retry projects zero growth, preserves inventory.
4. Conflicting same-length pending bytes reject `conflicting_retry`, preserve inventory.
5. New accounting object recomputes all persisted committed/pending lengths, with no process-restart claim.
6. Zero or oversized pending file rejects `INVALID_CIPHERTEXT_LENGTH`; candidate cannot repair it.

`chunk-N.bin.pending` matches existing receiver naming but no receiver code is imported, changed or wired. Projection never writes, renames, unlinks or repairs a fixture. AES keys/IV and synthetic plaintext are ephemeral and never logged; no decryption/plaintext-release test is claimed. No children or containers created by suite. Independent cleanup inspects `/proc` read-only, sends no signals, retains namespace/fails closed on matching live processes or unknown inspection; supervisor timeout owns test termination. Always cleanup confirms disposable private namespace absence, not physical erasure.

## Guards and execution
Generator starts with prior logical-budget workflow's 39 immutable pins, adds four new executable files and prior logical-budget workflow pin: 44 total pre/post pins. All custom dependencies pinned; helper imports only Node builtins. Workflow is branch-only and runs only six new flat cases, owner-only disposable logs, aggregate stdout, no raw uploaded artifact.

Windows direct require-by-path/syntax invocation failed `EPERM lstat C:\` before execution; not a test failure/pass or permission expansion. Main-context generator invocation succeeded without spawning helpers:

```powershell
$env:PENDING_BUDGET_WORKSPACE='C:/Users/mycom/.aside/u/0/workspaces/secure-mobile-messenger-lab'
& "$env:PENDING_BUDGET_WORKSPACE/tools/node-v22.23.0-win-x64/node.exe" -e "eval(require('node:fs').readFileSync(process.env.PENDING_BUDGET_WORKSPACE+'/experimental/media-transfer-lab/pending-budget-prepare.cjs','utf8'))"
```

Generator is idempotent only for equal existing workflow content; refuses different overwrite. Runtime tests executed: 0. CI/review/run IDs pending.

Main-context `vm.SourceTextModule` (unlinked) for two ESM files and `vm.Script` for two CJS files accepted syntax: 4 syntax modules, linked=false, tests_executed=0. This is not import/runtime or Linux pass evidence.

Independent review bZtE1kRz6IgwfwNj: PASS source-only;44pre/post maps identical/current hashes match,923priorfiles unchanged. Linux pending.
