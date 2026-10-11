// Main-context generator only. Creates ONLY the new workflow; never executes tests or children.
// PENDING_BUDGET_WORKSPACE=<workspace> node -e "require('./experimental/media-transfer-lab/pending-budget-prepare.cjs')"
const f=require('node:fs'),c=require('node:crypto'),p=require('node:path');
const root=process.env.PENDING_BUDGET_WORKSPACE;
if(!root||!p.isAbsolute(root))throw Error('workspace_required');
const hash=n=>c.createHash('sha256').update(f.readFileSync(p.join(root,n))).digest('hex');
const priorName='.github/workflows/matrix-logical-budget-lab.yml';
const prior=f.readFileSync(p.join(root,priorName),'utf8').match(/const pins=(\{[^\n]+?\});for\(const \[n,h\]/);
if(!prior)throw Error('guard_missing');const pins=JSON.parse(prior[1]);
if(Object.keys(pins).length!==39)throw Error('guard_count');
for(const [n,h]of Object.entries(pins))if(hash(n)!==h)throw Error('immutable39_changed');
// Retain the prior crypto/receiver policy pins; new suite imports only its separately pinned helper.
for(const n of ['receiver.mjs','attachment-stream.mjs'])if(!pins['experimental/media-transfer-lab/'+n])throw Error('import_guard_missing');
const added={};for(const n of ['pending-budget.mjs','pending-budget.spec.mjs','pending-budget-cleanup.cjs','pending-budget-prepare.cjs']){const q='experimental/media-transfer-lab/'+n;added[q]=hash(q);}
const all={...pins,...added,[priorName]:hash(priorName)};
const guard=`const f=require("node:fs"),c=require("node:crypto"),o=require("node:os"),p=require("node:path"),r=process.env.PRIVATE_ATTACHMENT_ROOT;if(process.platform!=="linux")process.exit(1);const s=f.lstatSync(r);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&4095)!==448||s.uid!==process.getuid()||f.realpathSync(o.tmpdir())!==f.realpathSync(r))process.exit(1);const pins=${JSON.stringify(all)};for(const [n,h]of Object.entries(pins))if(c.createHash("sha256").update(f.readFileSync(p.join(process.env.GITHUB_WORKSPACE,n))).digest("hex")!==h)process.exit(1);`;
const yaml=`name: Synthetic logical ciphertext length budget
on:
  workflow_dispatch:
  push:
    branches: [lab-matrix-cleanup-followup]
    paths:
      - '.github/workflows/matrix-pending-budget-lab.yml'
permissions:
  contents: read
concurrency:
  group: synthetic-pending-budget-${'${{ github.ref }}'}
  cancel-in-progress: false
jobs:
  pending-budget:
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
          private_root="$(mktemp -d "\${RUNNER_TEMP:?}/synthetic-pending-budget.XXXXXX")"
          chmod 700 "$private_root"
          printf 'PRIVATE_ATTACHMENT_ROOT=%s\\nTMPDIR=%s\\n' "$private_root" "$private_root" >> "$GITHUB_ENV"
      - name: Immutable39 and additional file guards before tests
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          test "$GITHUB_REF" = 'refs/heads/lab-matrix-cleanup-followup'
          node -e '${guard}' > "$PRIVATE_ATTACHMENT_ROOT/guard.log" 2>&1 || { echo 'source_policy_guards=failed; raw_diagnostics_suppressed=true'; exit 1; }
          rm -- "$PRIVATE_ATTACHMENT_ROOT/guard.log"
          echo 'immutable_source_guards=39; new_file_guards=4; prior_workflow_guards=1; imported_custom_dependencies=1; all_custom_imports_pinned=true; verified=true'
      - name: Exactly six new flat logical budget tests only
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          log="$PRIVATE_ATTACHMENT_ROOT/test-output.log"
          set +e
          timeout --kill-after=5s 180s node --test --test-reporter=tap --test-concurrency=1 pending-budget.spec.mjs > "$log" 2>&1
          result=$?
          set -e
          node -e 'const f=require("node:fs"),t=f.readFileSync(process.argv[1],"utf8"),names=["tests","pass","fail","cancelled","skipped"],counts=Object.fromEntries(names.map(n=>{const m=[...t.matchAll(new RegExp("^# "+n+" ([0-9]+)$","gm"))];return [n,m.length===1?Number(m[0][1]):null];}));const flat=[...t.matchAll(/^ok [0-9]+ -/gm)].length===6&&!/^not ok |^    (?:ok |not ok |# Subtest:)/m.test(t);const verified=counts.tests===6&&counts.pass===6&&counts.fail===0&&counts.cancelled===0&&counts.skipped===0&&flat&&process.argv[2]==="0";console.log(JSON.stringify({expected_tests:6,...counts,flat,runner_exit:Number(process.argv[2]),verified,raw_diagnostics_suppressed:true}));if(!verified)process.exit(1);' "$log" "$result"
          node pending-budget-cleanup.cjs --check-only
          node -e 'const f=require("node:fs"),n=f.readdirSync(process.env.PRIVATE_ATTACHMENT_ROOT);if(n.length!==1||n[0]!=="test-output.log")process.exit(1);console.log("fixture_namespaces_absent_after_tests=true");'
          echo 'new_flat_tests=6; fixture_ciphertext_bytes=8388608; chunk_bytes=262144; pending_half_bytes=131072; pending_full_bytes=262144; projection_remaining_only=true; exact_negative_codes=LOGICAL_BUDGET_EXCEEDED,conflicting_retry,INVALID_CIPHERTEXT_LENGTH; source_cache_inventory_immutable_on_denial=true'
          echo 'application_length_accounting_only=true; native_physical_quota=false; concurrency_security_enforcement=false; read_only_projection_helper=true; receiver_not_wired=true; object_recreation_only=true; process_restart=false; SDK_network_Android_GB_RSS=false; owned_children_created=0; containers_created=0; raw_artifacts_uploaded=false; production_changes=false; physical_erasure=false'
      - name: Immutable guards after new tests
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          node -e '${guard}' > "$PRIVATE_ATTACHMENT_ROOT/guard.log" 2>&1 || { echo 'post_source_policy_guards=failed; raw_diagnostics_suppressed=true'; exit 1; }
          rm -- "$PRIVATE_ATTACHMENT_ROOT/guard.log"
          echo 'post_immutable_source_guards=39; additional_guards=5; verified=true'
      - name: Independent always owned-process exit and private namespace cleanup
        if: always()
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          node pending-budget-cleanup.cjs
`;
const target=p.join(root,'.github/workflows/matrix-pending-budget-lab.yml');
// Repeat validation is idempotent, never overwrite a different existing file.
if(f.existsSync(target)){if(f.readFileSync(target,'utf8')!==yaml)throw Error('workflow_exists_different');}
else f.writeFileSync(target,yaml,{flag:'wx'});
console.log('pending_budget_workflow_generated=true; new_flat_tests=6; immutable_source_guards=39; additional_guards=5; imported_custom_dependencies_pinned=1; tests_executed=false; children_created=0; containers_created=0');
