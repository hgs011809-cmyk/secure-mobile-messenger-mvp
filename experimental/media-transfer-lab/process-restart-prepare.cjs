const f=require('node:fs'),c=require('node:crypto'),root=process.env.RESTART_WORKSPACE;
const prior=f.readFileSync(root+'/.github/workflows/matrix-authenticated-transport-lab.yml','utf8').match(/p=(\{[^\n]+?\});for\(const \[n,h\]/);
if(!prior)throw Error('guard_missing');const pins=JSON.parse(prior[1]);
for(const n of ['process-restart-worker.mjs','process-restart.spec.mjs','process-restart-cleanup.cjs']){const p='experimental/media-transfer-lab/'+n;pins[p]=c.createHash('sha256').update(f.readFileSync(root+'/'+p)).digest('hex');}
const yaml=`name: Synthetic encrypted receiver real-process boundaries
on:
  workflow_dispatch:
  push:
    branches: [lab-matrix-cleanup-followup]
    paths:
      - '.github/workflows/matrix-process-restart-lab.yml'
permissions:
  contents: read
concurrency:
  group: synthetic-process-restart-${'${{ github.ref }}'}
  cancel-in-progress: false
jobs:
  restart:
    if: github.ref == 'refs/heads/lab-matrix-cleanup-followup'
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - name: Owner-only private namespace
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          private_root="$(mktemp -d "${'${RUNNER_TEMP:?}'}/synthetic-restart.XXXXXX")"
          chmod 700 "$private_root"
          printf 'PRIVATE_ATTACHMENT_ROOT=%s\\nTMPDIR=%s\\n' "$private_root" "$private_root" >> "$GITHUB_ENV"
      - name: Exact source and unchanged policy guards
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          test "$GITHUB_REF" = 'refs/heads/lab-matrix-cleanup-followup'
          node -e 'const f=require("node:fs"),c=require("node:crypto"),o=require("node:os"),p=require("node:path"),r=process.env.PRIVATE_ATTACHMENT_ROOT,s=f.lstatSync(r);if(f.realpathSync(o.tmpdir())!==f.realpathSync(r)||(s.mode&4095)!==448||s.uid!==process.getuid()||s.isSymbolicLink())process.exit(1);const pins=${JSON.stringify(pins)};for(const [n,h]of Object.entries(pins))if(c.createHash("sha256").update(f.readFileSync(p.join(process.env.GITHUB_WORKSPACE,n))).digest("hex")!==h)process.exit(1);console.log("source_policy_guard_files=${Object.keys(pins).length}; verified=true; unchanged_policy=true");' > "$PRIVATE_ATTACHMENT_ROOT/guard.log" 2>&1 || { echo 'source_policy_guards=failed; raw_diagnostics_suppressed=true'; exit 1; }
          rm -- "$PRIVATE_ATTACHMENT_ROOT/guard.log"
          echo 'source_policy_guard_files=${Object.keys(pins).length}; verified=true; unchanged_policy=true'
      - name: Four actual child-process fixture cases
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          log="$PRIVATE_ATTACHMENT_ROOT/test-output.log"
          if ! timeout --kill-after=5s 150s node --test --test-concurrency=1 process-restart.spec.mjs > "$log" 2>&1; then
            node -e 'const f=require("node:fs"),t=f.readFileSync(process.argv[1],"utf8");console.log(JSON.stringify({process_tests_failed:true,failed_case_indexes:[...t.matchAll(/^not ok ([0-9]+) -/gm)].map(m=>Number(m[1])),raw_diagnostics_suppressed:true}));' "$log"
            exit 1
          fi
          grep -qx '# tests 4' "$log"
          grep -qx '# pass 4' "$log"
          grep -qx '# fail 0' "$log"
          grep -qx '# cancelled 0' "$log"
          grep -qx '# skipped 0' "$log"
          node process-restart-cleanup.cjs --check-only
          node -e 'const f=require("node:fs"),n=f.readdirSync(process.env.PRIVATE_ATTACHMENT_ROOT);if(n.length!==1||n[0]!=="test-output.log")process.exit(1);console.log("fixture_namespaces_absent_after_tests=true");'
          echo 'process_restart_tests=4; pass=4; fail=0; cancelled=0; skipped=0; fixture_bytes=8388608; chunk_ceiling=262144; fresh_OS_processes=true; clean_exit_boundary=true; SIGKILL_acknowledged_idle_boundary=true; retry_idempotent=true; complete_hash_and_stream_decrypt=true; source_and_ciphercache_preserved=true; fresh_mock_authorization_denial=true; changed_manifest_denial=true'
          echo 'authorization=mock_fixture_only; actual_SDK_in_this_suite=false; actual_media=false; Android=false; midwrite_crash_recovery=false; power_loss_durability=false; filesystem_repair=false; atomic_authorization=false; RSS_GB=false; physical_erasure=false; production_changes=false'
      - name: Independent owned-worker and private namespace cleanup
        if: always()
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          node process-restart-cleanup.cjs
`;
f.writeFileSync(root+'/.github/workflows/matrix-process-restart-lab.yml',yaml);console.log(JSON.stringify({processWorkflowPrepared:true,sourcePolicyGuardFiles:Object.keys(pins).length}));
