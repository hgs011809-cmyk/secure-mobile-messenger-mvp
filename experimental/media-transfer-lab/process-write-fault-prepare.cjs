// Run in main context: WRITE_FAULT_WORKSPACE=<workspace> node -e "require('./experimental/media-transfer-lab/process-write-fault-prepare.cjs')"
// Emits a standalone Linux bash runner to stdout ONLY. Does not write any workflow/container/source.
const f=require('node:fs'),c=require('node:crypto'),p=require('node:path');
const root=process.env.WRITE_FAULT_WORKSPACE;
if(!root||!p.isAbsolute(root))throw Error('workspace_required');
const hash=n=>c.createHash('sha256').update(f.readFileSync(p.join(root,n))).digest('hex');
const priorName='.github/workflows/matrix-process-restart-lab.yml',sourceName='.github/workflows/matrix-authenticated-transport-lab.yml';
const prior=f.readFileSync(p.join(root,priorName),'utf8').match(/const pins=(\{[^\n]+?\});for\(const \[n,h\]/);
const source=f.readFileSync(p.join(root,sourceName),'utf8').match(/p=(\{[^\n]+?\});for\(const \[n,h\]/);
if(!prior||!source)throw Error('guard_missing');
const pins=JSON.parse(prior[1]),sourcePins=JSON.parse(source[1]);
if(Object.keys(pins).length!==31||Object.keys(sourcePins).length!==28)throw Error('guard_count');
for(const [n,h]of Object.entries(sourcePins))if(pins[n]!==h)throw Error('prior_source_guard_mismatch');
for(const [n,h]of Object.entries(pins))if(hash(n)!==h)throw Error('immutable_source_changed');
const added={};for(const n of ['process-write-fault-worker.mjs','process-write-fault.spec.mjs','process-write-fault-cleanup.cjs','process-write-fault-prepare.cjs']){const q='experimental/media-transfer-lab/'+n;added[q]=hash(q);}
const workflows={[priorName]:hash(priorName),[sourceName]:hash(sourceName)};
const all={...pins,...added,...workflows};
const guard=`const f=require("node:fs"),c=require("node:crypto"),p=require("node:path"),o=require("node:os");if(process.platform!=="linux")process.exit(1);const r=process.env.PRIVATE_ATTACHMENT_ROOT,s=f.lstatSync(r);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&4095)!==448||s.uid!==process.getuid()||f.realpathSync(o.tmpdir())!==f.realpathSync(r))process.exit(1);const pins=${JSON.stringify(all)};for(const [n,h]of Object.entries(pins))if(c.createHash("sha256").update(f.readFileSync(p.join(process.env.WRITE_FAULT_WORKSPACE,n))).digest("hex")!==h)process.exit(1);`;
console.log(`#!/usr/bin/env bash
# Generated standalone six-case runner. Execute on existing Linux host; no container creation.
set -euo pipefail
umask 077
: "\${WRITE_FAULT_WORKSPACE:?}" "\${RUNNER_TEMP:?}"
cd "$WRITE_FAULT_WORKSPACE/experimental/media-transfer-lab"
export PRIVATE_ATTACHMENT_ROOT="$(mktemp -d "$RUNNER_TEMP/synthetic-write-fault.XXXXXX")"
export TMPDIR="$PRIVATE_ATTACHMENT_ROOT"
chmod 700 "$PRIVATE_ATTACHMENT_ROOT"
cleanup() {
  local status=$?
  trap - EXIT
  if ! node process-write-fault-cleanup.cjs; then status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
node -e '${guard}' > "$PRIVATE_ATTACHMENT_ROOT/guard.log" 2>&1 || { echo 'source_policy_guards=failed; raw_diagnostics_suppressed=true'; exit 1; }
rm -- "$PRIVATE_ATTACHMENT_ROOT/guard.log"
echo 'immutable_source_guards=31; new_file_guards=4; existing_workflow_guards=2; verified=true; production_changes=false'
log="$PRIVATE_ATTACHMENT_ROOT/test-output.log"
set +e
timeout --kill-after=5s 240s node --test --test-reporter=tap --test-concurrency=1 process-write-fault.spec.mjs > "$log" 2>&1
result=$?
set -e
node -e 'const f=require("node:fs"),t=f.readFileSync(process.argv[1],"utf8"),names=["tests","pass","fail","cancelled","skipped"],counts=Object.fromEntries(names.map(n=>{const m=[...t.matchAll(new RegExp("^# "+n+" ([0-9]+)$","gm"))];return [n,m.length===1?Number(m[0][1]):null];}));const flat=[...t.matchAll(/^ok [0-9]+ -/gm)].length===6&&!/^    (?:not )?ok /m.test(t);const ok=counts.tests===6&&counts.pass===6&&counts.fail===0&&counts.cancelled===0&&counts.skipped===0&&flat&&process.argv[2]==="0";console.log(JSON.stringify({expected_tests:6,...counts,flat,runner_exit:Number(process.argv[2]),verified:ok,raw_diagnostics_suppressed:true}));if(!ok)process.exit(1);' "$log" "$result"
node process-write-fault-cleanup.cjs --check-only
node -e 'const f=require("node:fs"),n=f.readdirSync(process.env.PRIVATE_ATTACHMENT_ROOT);if(n.length!==1||n[0]!=="test-output.log")process.exit(1);console.log("fixture_namespaces_absent_after_tests=true");'
node -e '${guard}' > "$PRIVATE_ATTACHMENT_ROOT/guard.log" 2>&1 || { echo 'post_source_policy_guards=failed; raw_diagnostics_suppressed=true'; exit 1; }
rm -- "$PRIVATE_ATTACHMENT_ROOT/guard.log"
echo 'write_fault_tests=6; partial_pending_bytes=131072; full_pending_bytes=262144; fixture_ciphertext_bytes=8388608; chunk_bytes=262144; expected_codes=ok,incomplete,not_authorized,manifest_changed,AUTHORIZATION_DENIED; keys=parent_RAM_only; private_IPC=true'
echo 'boundary=worker_local_filesystem_API; authorization=mock_only; existing_initialize_pending_reclamation=true; changed_manifest_pending_reclaimed_before_denial=true; power_loss=false; fsync_durability=false; filesystem_repair=false; Android=false; SDK_auth=false; physical_erasure=false; hard_runner_loss_cleanup=unverified'
`);
