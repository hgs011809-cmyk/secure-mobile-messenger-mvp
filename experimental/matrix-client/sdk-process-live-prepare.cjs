// NEW source-only BLOCKED workflow generator. Never runs SDK, browser or containers.
const f=require('node:fs'),p=require('node:path'),c=require('node:crypto');
const root=process.env.SDK_PROCESS_WORKSPACE;if(!root||!p.isAbsolute(root))throw Error('WORKSPACE_REQUIRED');
const pins={};
function walk(rel){for(const e of f.readdirSync(p.join(root,rel),{withFileTypes:true})){if(['runtime','dist','node_modules','.git'].includes(e.name))continue;const n=rel+'/'+e.name;if(e.isSymbolicLink())throw Error('SYMLINK_DENIED');if(e.isDirectory())walk(n);else if(/\.(?:mjs|cjs|js|json|yaml|yml|html|py)$/.test(e.name)||/Dockerfile$/.test(e.name))pins[n]=c.createHash('sha256').update(f.readFileSync(p.join(root,n))).digest('hex');}}
for(const dir of ['experimental/matrix-client','experimental/media-transfer-lab','experimental/auth-bridge','experimental/matrix-cleanup-candidate','infra/ncp/auth/src','infra/ncp/matrix-lab/ci'])walk(dir);
const guard=`node -e 'const f=require("node:fs"),c=require("node:crypto"),pins=${JSON.stringify(pins)};for(const [n,h]of Object.entries(pins))if(c.createHash("sha256").update(f.readFileSync(n)).digest("hex")!==h)process.exit(1);console.log("source_policy_pins=${Object.keys(pins).length}; verified=true");'`;
const y=`name: SDK process live feasibility BLOCKED ownership inspection (NO runtime)
on:
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: sdk-process-live-feasibility-inspection
  cancel-in-progress: false
jobs:
  blocked-source-inspection:
    if: github.ref == 'refs/heads/lab-matrix-cleanup-followup'
    runs-on: ubuntu-24.04
    timeout-minutes: 3
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - name: Empty owner-only inspection namespace
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          root="$RUNNER_TEMP/sdk-process-live-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
          test ! -e "$root"
          mkdir -m 700 -- "$root"
          printf 'PRIVATE_ATTACHMENT_ROOT=%s\\n' "$root" >> "$GITHUB_ENV"
          echo 'inspection_namespace=ready; runtime_started=false'
      - name: Pre-inspection exact immutable source and policy pins
        shell: bash
        run: |
          set -euo pipefail
          ${guard}
      - name: Fail closed before any external-service runtime setup
        shell: bash
        run: |
          echo '{"expectedPositiveCandidateGates":1,"executed":0,"pass":0,"fail":0,"cancelled":0,"skip":1,"blocked":true,"code":"STARTUP_OWNERSHIP_INSTRUMENTATION_REQUIRED","actualSDKIntegration":false,"legacyDescriptorCounted":false,"redactionAcceptance":"BLOCKED","redactionClosureCause":"UNKNOWN","redactionCounted":false,"plaintextProof":false,"rawDiagnosticsSuppressed":true}'
          exit 1
      - name: Post-inspection exact immutable source and policy pins
        if: always()
        shell: bash
        run: |
          set -euo pipefail
          ${guard}
      - name: Independent always exact reserved container absence
        if: always()
        shell: bash
        run: |
          set -euo pipefail
          umask 077
          # This inspection workflow creates NO containers and may NEVER remove one.
          # Capture Docker output only in the owner-only namespace.
          test -d "$PRIVATE_ATTACHMENT_ROOT"
          names="$PRIVATE_ATTACHMENT_ROOT/container-names"
          if ! docker ps -a --format '{{.Names}}' > "$names" 2>/dev/null; then
            rm -f -- "$names"
            echo 'reserved_container_absence=unverified; code=CONTAINER_INSPECTION_FAILED'
            exit 1
          fi
          result=0
          for suffix in synapse extract; do
            if grep -Fxq "sdk-process-live-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$suffix" "$names"; then result=1; fi
          done
          rm -f -- "$names"
          if [ "$result" -ne 0 ]; then echo 'reserved_container_absence=failed; removal_not_authorized=true'; exit 1; fi
          echo 'exact_reserved_container_names_absent=true; containers_created=0; containers_removed=0'
      - name: Independent always read-only owned process and empty namespace cleanup
        if: always() && env.PRIVATE_ATTACHMENT_ROOT != ''
        shell: bash
        run: |
          set -euo pipefail
          node experimental/matrix-client/sdk-process-live-cleanup.cjs
`;
f.writeFileSync(p.join(root,'.github/workflows/matrix-sdk-process-live-lab.yml'),y,{mode:0o600});
console.log(JSON.stringify({prepared:true,pins:Object.keys(pins).length,runtimeTests:0,CIStarted:false,blocked:true,code:'STARTUP_OWNERSHIP_INSTRUMENTATION_REQUIRED'}));
