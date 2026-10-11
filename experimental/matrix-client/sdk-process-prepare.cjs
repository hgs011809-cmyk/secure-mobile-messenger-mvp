// Prepare isolated SYNTHETIC FOUNDATION workflow. No actual SDK/runtime claim.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=process.env.SDK_PROCESS_WORKSPACE;if(!root)throw Error('workspace_required');
const old=fs.readFileSync(path.join(root,'.github/workflows/matrix-persisted-corruption-lab.yml'),'utf8');
const match=old.match(/const pins=(\{[^\n]+?\});for\(const \[n,h\]/);if(!match)throw Error('pins_missing');
const pins=JSON.parse(match[1]);
for(const n of fs.readdirSync(path.join(root,'experimental/matrix-client')).filter(n=>n.startsWith('sdk-process-')&&/\.(mjs|cjs)$/.test(n))){const f='experimental/matrix-client/'+n;pins[f]=crypto.createHash('sha256').update(fs.readFileSync(path.join(root,f))).digest('hex');}
const guard='node -e \'const f=require("node:fs"),c=require("node:crypto"),p=require("node:path"),pins='+JSON.stringify(pins)+';for(const [n,h]of Object.entries(pins))if(c.createHash("sha256").update(f.readFileSync(p.join(process.env.GITHUB_WORKSPACE,n))).digest("hex")!==h)process.exit(1);\' > "$PRIVATE_ATTACHMENT_ROOT/guard.log" 2>&1 || { echo "source_guards=failed"; exit 1; }\n          rm -- "$PRIVATE_ATTACHMENT_ROOT/guard.log"\n          echo "source_guards='+Object.keys(pins).length+'; verified=true"';
const y=`name: Synthetic SDK-process IPC foundation (NOT actual SDK integration)
on:
  push:
    branches: [lab-matrix-cleanup-followup]
    paths: ['.github/workflows/matrix-sdk-process-lab.yml']
permissions:
  contents: read
concurrency:
  group: synthetic-sdk-process-foundation
  cancel-in-progress: false
jobs:
  foundation:
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
      - name: Owner-only namespace
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          private_root="$(mktemp -d "$RUNNER_TEMP/synthetic-sdk-process.XXXXXX")"
          printf 'PRIVATE_ATTACHMENT_ROOT=%s\\nTMPDIR=%s\\n' "$private_root" "$private_root" >> "$GITHUB_ENV"
      - name: Pre-test pinned sources
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          ${guard}
      - name: Six synthetic foundation cases only
        working-directory: experimental/matrix-client
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          log="$PRIVATE_ATTACHMENT_ROOT/test-output.log"
          set +e
          timeout --kill-after=5s 180s node --test --test-reporter=tap --test-concurrency=1 sdk-process-foundation.spec.mjs > "$log" 2>&1
          result=$?
          set -e
          node -e 'const f=require("node:fs"),t=f.readFileSync(process.argv[1],"utf8"),names=["tests","pass","fail","cancelled","skipped"],counts=Object.fromEntries(names.map(n=>{const m=[...t.matchAll(new RegExp("^# "+n+" ([0-9]+)$","gm"))];return[n,m.length===1?Number(m[0][1]):null];}));const flat=[...t.matchAll(/^ok [0-9]+ -/gm)].length===6&&!/^not ok |^    (?:ok |not ok |# Subtest:)/m.test(t);const verified=counts.tests===6&&counts.pass===6&&counts.fail===0&&counts.cancelled===0&&counts.skipped===0&&flat&&process.argv[2]==="0";console.log(JSON.stringify({expected_tests:6,...counts,flat,runner_exit:Number(process.argv[2]),verified,actualSDKIntegration:false,authorization:"synthetic_only",plaintextProof:false,raw_diagnostics_suppressed:true}));if(!verified)process.exit(1);' "$log" "$result"
          node sdk-process-cleanup.cjs --check-only
          node -e 'const f=require("node:fs"),n=f.readdirSync(process.env.PRIVATE_ATTACHMENT_ROOT);if(n.length!==1||n[0]!=="test-output.log")process.exit(1);console.log("fixture_namespaces_absent=true; containers_created=0");'
          echo 'foundation_only=true; real_native_or_SDK_revocation=false; fixture_bytes=8388608; chunk_bytes=262144; parent_alive=true; no_plaintext_callbacks_exist=true; crypto_plaintext_proof=false; powerloss=false; production_changes=false'
      - name: Post-test pinned sources
        if: always() && env.PRIVATE_ATTACHMENT_ROOT != ''
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          test -d "$PRIVATE_ATTACHMENT_ROOT"
          ${guard}
      - name: Independent always owned-process and namespace cleanup
        if: always() && env.PRIVATE_ATTACHMENT_ROOT != ''
        working-directory: experimental/matrix-client
        shell: bash
        run: |
          set -euo pipefail
          node sdk-process-cleanup.cjs
`;
fs.writeFileSync(path.join(root,'.github/workflows/matrix-sdk-process-lab.yml'),y);console.log(JSON.stringify({prepared:true,pins:Object.keys(pins).length,actualSDKIntegration:false,testsNotExecuted:true}));
