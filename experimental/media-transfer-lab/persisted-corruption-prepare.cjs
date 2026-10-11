// Main-context generator only. Creates ONLY the new workflow; never executes tests or children.
// PERSISTED_CORRUPTION_WORKSPACE=<workspace> node -e "require('./experimental/media-transfer-lab/persisted-corruption-prepare.cjs')"
const f=require('node:fs'),c=require('node:crypto'),p=require('node:path');
const root=process.env.PERSISTED_CORRUPTION_WORKSPACE;
if(!root||!p.isAbsolute(root))throw Error('workspace_required');
const hash=n=>c.createHash('sha256').update(f.readFileSync(p.join(root,n))).digest('hex');
const priorName='.github/workflows/matrix-process-write-fault-lab.yml';
const prior=f.readFileSync(p.join(root,priorName),'utf8').match(/const pins=(\{[^\n]+?\});for\(const \[n,h\]/);
if(!prior)throw Error('guard_missing');const pins=JSON.parse(prior[1]);
if(Object.keys(pins).length!==34)throw Error('guard_count');
for(const [n,h]of Object.entries(pins))if(hash(n)!==h)throw Error('immutable34_changed');
// Both local imports are already among the immutable34. No unpinned custom imports.
for(const n of ['receiver.mjs','attachment-stream.mjs'])if(!pins['experimental/media-transfer-lab/'+n])throw Error('import_guard_missing');
const added={};for(const n of ['persisted-corruption.spec.mjs','persisted-corruption-cleanup.cjs','persisted-corruption-prepare.cjs']){const q='experimental/media-transfer-lab/'+n;added[q]=hash(q);}
const all={...pins,...added,[priorName]:hash(priorName)};
const guard=`const f=require("node:fs"),c=require("node:crypto"),o=require("node:os"),p=require("node:path"),r=process.env.PRIVATE_ATTACHMENT_ROOT;if(process.platform!=="linux")process.exit(1);const s=f.lstatSync(r);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&4095)!==448||s.uid!==process.getuid()||f.realpathSync(o.tmpdir())!==f.realpathSync(r))process.exit(1);const pins=${JSON.stringify(all)};for(const [n,h]of Object.entries(pins))if(c.createHash("sha256").update(f.readFileSync(p.join(process.env.GITHUB_WORKSPACE,n))).digest("hex")!==h)process.exit(1);`;
const yaml=`name: Synthetic persisted ciphertext corruption and conflicting retry
on:
  workflow_dispatch:
  push:
    branches: [lab-matrix-cleanup-followup]
    paths:
      - '.github/workflows/matrix-persisted-corruption-lab.yml'
      - 'experimental/media-transfer-lab/persisted-corruption.spec.mjs'
      - 'experimental/media-transfer-lab/persisted-corruption-prepare.cjs'
      - 'experimental/media-transfer-lab/persisted-corruption-cleanup.cjs'
permissions:
  contents: read
concurrency:
  group: synthetic-persisted-corruption-${'${{ github.ref }}'}
  cancel-in-progress: false
jobs:
  persisted-corruption:
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
          private_root="$(mktemp -d "\${RUNNER_TEMP:?}/synthetic-persisted-corruption.XXXXXX")"
          chmod 700 "$private_root"
          printf 'PRIVATE_ATTACHMENT_ROOT=%s\\nTMPDIR=%s\\n' "$private_root" "$private_root" >> "$GITHUB_ENV"
      - name: Immutable34 and additional file guards before tests
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          test "$GITHUB_REF" = 'refs/heads/lab-matrix-cleanup-followup'
          node -e '${guard}' > "$PRIVATE_ATTACHMENT_ROOT/guard.log" 2>&1 || { echo 'source_policy_guards=failed; raw_diagnostics_suppressed=true'; exit 1; }
          rm -- "$PRIVATE_ATTACHMENT_ROOT/guard.log"
          echo 'immutable_source_guards=34; new_file_guards=3; prior_workflow_guards=1; imported_custom_dependencies=2; all_custom_imports_pinned=true; verified=true'
      - name: Exactly six new flat corruption tests only
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          log="$PRIVATE_ATTACHMENT_ROOT/test-output.log"
          set +e
          timeout --kill-after=5s 180s node --test --test-reporter=tap --test-concurrency=1 persisted-corruption.spec.mjs > "$log" 2>&1
          result=$?
          set -e
          node -e 'const f=require("node:fs"),t=f.readFileSync(process.argv[1],"utf8"),names=["tests","pass","fail","cancelled","skipped"],counts=Object.fromEntries(names.map(n=>{const m=[...t.matchAll(new RegExp("^# "+n+" ([0-9]+)$","gm"))];return [n,m.length===1?Number(m[0][1]):null];}));const flat=[...t.matchAll(/^ok [0-9]+ -/gm)].length===6&&!/^not ok |^    (?:ok |not ok |# Subtest:)/m.test(t);const verified=counts.tests===6&&counts.pass===6&&counts.fail===0&&counts.cancelled===0&&counts.skipped===0&&flat&&process.argv[2]==="0";console.log(JSON.stringify({expected_tests:6,...counts,flat,runner_exit:Number(process.argv[2]),verified,raw_diagnostics_suppressed:true}));if(!verified)process.exit(1);' "$log" "$result"
          node persisted-corruption-cleanup.cjs --check-only
          node -e 'const f=require("node:fs"),n=f.readdirSync(process.env.PRIVATE_ATTACHMENT_ROOT);if(n.length!==1||n[0]!=="test-output.log")process.exit(1);console.log("fixture_namespaces_absent_after_tests=true");'
          echo 'new_flat_tests=6; fixture_ciphertext_bytes=8388608; chunk_bytes=262144; extension_probe_bytes=1; exact_negative_codes=invalid_stored_chunk,integrity_failed,conflicting_retry,HASH_MISMATCH,not_authorized,AUTHORIZATION_DENIED,manifest_changed; instrumented_parent_negative_plaintext_callbacks=0; instrumented_parent_negative_plaintext_bytes=0; positive_parent_sink_control=true'
          echo 'resume_length_only=true; manifest_denial_not_latched_by_core=true; initialization_denial_only_claim=true; snapshots_after_injection=true; pending_reclamation_not_in_scope=true; source_and_cache_read_retry_immutability=true; containers_created=0; suite_owned_children=0; authorization=mock_only; no_process_restart_proof=true; prior_suite_proof=separate; SDK_Android_network=false; filesystem_repair=false; physical_erasure=false; durability=false; production_changes=false; hard_runner_loss_cleanup=unverified'
      - name: Immutable guards after new tests
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          node -e '${guard}' > "$PRIVATE_ATTACHMENT_ROOT/guard.log" 2>&1 || { echo 'post_source_policy_guards=failed; raw_diagnostics_suppressed=true'; exit 1; }
          rm -- "$PRIVATE_ATTACHMENT_ROOT/guard.log"
          echo 'post_immutable_source_guards=34; additional_guards=4; verified=true'
      - name: Independent always owned-process exit and private namespace cleanup
        if: always()
        working-directory: experimental/media-transfer-lab
        shell: bash
        run: |
          set -euo pipefail
          node persisted-corruption-cleanup.cjs
`;
const target=p.join(root,'.github/workflows/matrix-persisted-corruption-lab.yml');
// Repeat validation is idempotent, never overwrite a different existing file.
if(f.existsSync(target)){if(f.readFileSync(target,'utf8')!==yaml)throw Error('workflow_exists_different');}
else f.writeFileSync(target,yaml,{flag:'wx'});
console.log('persisted_corruption_workflow_generated=true; new_flat_tests=6; immutable_source_guards=34; additional_guards=4; imported_custom_dependencies_pinned=2; tests_executed=false; children_created=0; containers_created=0');
