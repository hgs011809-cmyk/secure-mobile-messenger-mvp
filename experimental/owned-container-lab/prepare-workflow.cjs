// NEW CI-only source/workflow preparation. Never modifies historical core/policy.
const f=require('node:fs'),c=require('node:crypto'),p=require('node:path'),root=process.env.CONTAINMENT_WORKSPACE;
const old=f.readFileSync(root+'/.github/workflows/matrix-process-restart-lab.yml','utf8').match(/const pins=(\{[^\n]+?\});for/);if(!old)throw Error('BASELINE_PINS_MISSING');
const pins=JSON.parse(old[1]);for(const [n,h]of Object.entries(pins))if(c.createHash('sha256').update(f.readFileSync(p.join(root,n))).digest('hex')!==h)throw Error('BASELINE_CHANGED');
const add=['container-worker.mjs','container-control.cjs','container-control.spec.cjs','Dockerfile','CONTAINMENT.md'].map(n=>'experimental/owned-container-lab/'+n).concat(['experimental/matrix-client/package.json','experimental/matrix-client/package-lock.json']);
for(const n of add)pins[n]=c.createHash('sha256').update(f.readFileSync(p.join(root,n))).digest('hex');
const y=`name: Precreated owned container child and Chromium containment
on:
  workflow_dispatch:
  push:
    branches: [lab-matrix-cleanup-followup]
    paths:
      - '.github/workflows/matrix-owned-container-lab.yml'
permissions:
  contents: read
concurrency:
  group: owned-container-proof-${'${{ github.ref }}'}
  cancel-in-progress: false
jobs:
  containment:
    if: github.ref == 'refs/heads/lab-matrix-cleanup-followup'
    runs-on: ubuntu-24.04
    timeout-minutes: 12
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - name: Private owned fixture namespace
        run: |
          set -euo pipefail
          umask 077
          root="$(mktemp -d "${'${RUNNER_TEMP:?}'}/owned-containment.XXXXXX")"
          chmod 700 "$root"
          logroot="$(mktemp -d "${'${RUNNER_TEMP:?}'}/owned-container-logs.XXXXXX")"
          chmod 700 "$logroot"
          printf 'PRIVATE_CONTAINMENT_ROOT=%s\\nPRIVATE_CONTAINMENT_LOG_ROOT=%s\\nCONTAINMENT_RUN_STARTED=0\\n' "$root" "$logroot" >> "$GITHUB_ENV"
      - name: Immutable historical source and candidate guards
        run: |
          set -euo pipefail
          umask 077
          test "$GITHUB_REF" = 'refs/heads/lab-matrix-cleanup-followup'
          node -e 'const f=require("node:fs"),c=require("node:crypto"),p=require("node:path"),pins=${JSON.stringify(pins)};for(const [n,h]of Object.entries(pins))if(c.createHash("sha256").update(f.readFileSync(p.join(process.env.GITHUB_WORKSPACE,n))).digest("hex")!==h)process.exit(1);console.log("source_policy_pins=${Object.keys(pins).length}; verified=true; existing_policy_unchanged=true");' > "$PRIVATE_CONTAINMENT_LOG_ROOT/guards.log" 2>&1 || { echo 'source_guards=failed; raw_diagnostics_suppressed=true'; exit 1; }
          rm -- "$PRIVATE_CONTAINMENT_LOG_ROOT/guards.log"
          echo 'source_policy_pins=${Object.keys(pins).length}; verified=true; existing_policy_unchanged=true'
      - name: Four exact ownership contract tests
        run: |
          set -euo pipefail
          umask 077
          log="$PRIVATE_CONTAINMENT_LOG_ROOT/contract.log"
          if ! node --test --test-concurrency=1 experimental/owned-container-lab/container-control.spec.cjs > "$log" 2>&1; then
            node -e 'const f=require("node:fs"),t=f.readFileSync(process.argv[1],"utf8");console.log(JSON.stringify({contract_failed:true,case_indexes:[...t.matchAll(/^not ok ([0-9]+) -/gm)].map(m=>Number(m[1])),raw_diagnostics_suppressed:true}));' "$log"
            exit 1
          fi
          grep -qx '# tests 4' "$log" && grep -qx '# pass 4' "$log" && grep -qx '# fail 0' "$log" && grep -qx '# cancelled 0' "$log" && grep -qx '# skipped 0' "$log"
          echo 'ownership_contract_tests=4; pass=4; fail=0; cancelled=0; skipped=0; actual_runtime_proof=false'
      - name: Resolve immutable base and build private public-source image
        run: |
          set -euo pipefail
          umask 077
          root="$PRIVATE_CONTAINMENT_LOG_ROOT"
          mkdir -p "$root/context/experimental/matrix-client" "$root/context/experimental/owned-container-lab"
          cp experimental/matrix-client/package.json experimental/matrix-client/package-lock.json "$root/context/experimental/matrix-client/"
          cp experimental/owned-container-lab/container-worker.mjs experimental/owned-container-lab/Dockerfile "$root/context/experimental/owned-container-lab/"
          if ! docker pull node:22-bookworm-slim > "$root/base-pull.log" 2>&1; then echo 'image_prepare=failed; stage=base_pull; raw_diagnostics_suppressed=true'; exit 1; fi
          docker image inspect node:22-bookworm-slim > "$root/base-inspect.json"
          node -e 'const f=require("node:fs"),x=JSON.parse(f.readFileSync(process.argv[1],"utf8"));const r=x[0]?.RepoDigests?.find(s=>/^node@sha256:[a-f0-9]{64}$/.test(s));if(!r)process.exit(1);f.writeFileSync(process.argv[2],r,{mode:384,flag:"wx"});' "$root/base-inspect.json" "$root/base.ref"
          base="$(cat "$root/base.ref")"
          if ! timeout --kill-after=10s 420s docker build --build-arg "BASE=$base" --iidfile "$root/image.id" -f "$root/context/experimental/owned-container-lab/Dockerfile" "$root/context" > "$root/build.log" 2>&1; then echo 'image_prepare=failed; stage=bounded_build; raw_diagnostics_suppressed=true'; exit 1; fi
          node -e 'const f=require("node:fs"),id=f.readFileSync(process.argv[1],"utf8").trim();if(!/^sha256:[a-f0-9]{64}$/.test(id))process.exit(1);f.appendFileSync(process.env.GITHUB_ENV,"CONTAINMENT_IMAGE_ID="+id+"\\n");' "$root/image.id"
          echo 'public_dependency_image_built=true; base_digest_resolved=true; runtime_image_exact_ID=true; workload_network_not_started=true'
      - name: Two genuine child Chromium contained lifecycle cases
        run: |
          set -euo pipefail
          umask 077
          printf 'CONTAINMENT_RUN_STARTED=1\\n' >> "$GITHUB_ENV"
          log="$PRIVATE_CONTAINMENT_LOG_ROOT/runtime.log"
          if ! timeout --kill-after=5s 180s node experimental/owned-container-lab/container-control.cjs --run > "$log" 2>&1; then
            echo 'contained_runtime=failed; raw_diagnostics_suppressed=true'
            node -e 'const f=require("node:fs"),S=["rootcheck","runempty","imageinspect","image_env_admission","intentspersisted","create","IDpersisted","created_security_admission","recordpersisted","start","gracefulwait","lingerready","probe","stop","cleanup_load","cleanup_stop","cleanup_remove","cleanup_absence","cleanup_residual","cleanup_rootremove"],G=["root","image_env","saved_record","absence","docker_cli","identity_config","env","namespace_config","bounds","tmpfs","host_mounts","ports","image_volumes","mounts","network_map","image_identity","create_id","created_state","workload_output","workload_state","persistence","private_file","cleanup_residual","root_absence","cli_args","intent"],C=["Hostname","Domainname","User","AttachStdin","AttachStdout","AttachStderr","ExposedPorts","Tty","OpenStdin","StdinOnce","Env","Cmd","Healthcheck","ArgsEscaped","Image","Volumes","WorkingDir","Entrypoint","NetworkDisabled","MacAddress","OnBuild","Labels","StopSignal","StopTimeout","Shell"],H=["Binds","ContainerIDFile","LogConfig","NetworkMode","PortBindings","RestartPolicy","AutoRemove","VolumeDriver","VolumesFrom","ConsoleSize","Annotations","CapAdd","CapDrop","CgroupnsMode","Dns","DnsOptions","DnsSearch","ExtraHosts","GroupAdd","IpcMode","Cgroup","Links","OomScoreAdj","PidMode","Privileged","PublishAllPorts","ReadonlyRootfs","SecurityOpt","StorageOpt","Tmpfs","UTSMode","UsernsMode","ShmSize","Sysctls","Runtime","Isolation","CpuShares","Memory","NanoCpus","CgroupParent","BlkioWeight","BlkioWeightDevice","BlkioDeviceReadBps","BlkioDeviceWriteBps","BlkioDeviceReadIOps","BlkioDeviceWriteIOps","CpuPeriod","CpuQuota","CpuRealtimePeriod","CpuRealtimeRuntime","CpusetCpus","CpusetMems","Devices","DeviceCgroupRules","DeviceRequests","MemoryReservation","MemorySwap","MemorySwappiness","OomKillDisable","PidsLimit","Ulimits","CpuCount","CpuPercent","IOMaximumIOps","IOMaximumBandwidth","Mounts","MaskedPaths","ReadonlyPaths","Init"];try{const r=JSON.parse(process.argv[2]==="file"?f.readFileSync(process.argv[1],"utf8"):process.argv[1]);const K=["status","reason","stage","gate","createdCount","startedCount","completedCount","networkMapObservation","imageEnvExpectedKeys","configComparison","hostConfigComparison","stateShape","changedConfigFields","changedHostConfigFields"];const field=(a,F)=>Array.isArray(a)&&a.length<=F.length+1&&new Set(a).size===a.length&&JSON.stringify(a)===JSON.stringify([...a].sort())&&a.every(s=>F.includes(s)||s==="other");if(JSON.stringify(Object.keys(r).sort())!==JSON.stringify(K.sort())||r.status!=="failed"||r.reason!=="containment_unverified"||!S.includes(r.stage)||!G.includes(r.gate)||!["empty","none_only","other","missing"].includes(r.networkMapObservation)||typeof r.imageEnvExpectedKeys!=="boolean"||![r.createdCount,r.startedCount,r.completedCount].every(n=>Number.isInteger(n)&&n>=0&&n<=2)||![r.configComparison,r.hostConfigComparison].every(s=>["not_observed","equal","different"].includes(s))||!["not_observed","valid","invalid"].includes(r.stateShape)||!field(r.changedConfigFields,C)||!field(r.changedHostConfigFields,H))throw 0;console.log(JSON.stringify({containmentFailure:true,stage:r.stage,gate:r.gate,acknowledgedCreatedCount:r.createdCount,acknowledgedStartedCount:r.startedCount,completedProofCount:r.completedCount,countScope:"current_invocation_only",networkMapObservation:r.networkMapObservation,imageEnvExpectedKeys:r.imageEnvExpectedKeys,configComparison:r.configComparison,hostConfigComparison:r.hostConfigComparison,stateShape:r.stateShape,changedConfigFields:r.changedConfigFields,changedHostConfigFields:r.changedHostConfigFields,rawDiagnosticsSuppressed:true}));}catch{console.log("fixed_field_diagnostic_unavailable=true; raw_diagnostics_suppressed=true");}' "$log" file
            exit 1
          fi
          node -e 'const f=require("node:fs"),lines=f.readFileSync(process.argv[1],"utf8").trim().split(/\\r?\\n/);if(lines.length!==1)process.exit(1);const r=JSON.parse(lines[0]);if(r.status!=="passed"||r.cases!==2||r.pass!==2||r.fail!==0||r.graceful!==true||r.timeout!==true||r.preStartOwnership!==true||r.genuineChromium!==true||r.privatePIDNamespace!==true||r.networkNone!==true||r.noHostPIDSignals!==true||r.actualSDKIntegration!==false)process.exit(1);console.log("owned_container_runtime_cases=2; pass=2; fail=0; precreated_ID_and_exact_ownership=true; genuine_Node_child_and_Chromium=true; private_PID_namespace=true; network_none=true; graceful_exit=true; owned_container_timeout_stop=true; no_host_workload_PID_signals=true; actual_SDK_integration=false; physical_erasure=false; hard_runner_loss=false; production_changes=false");' "$log"
      - name: Independent exact owned container and namespace cleanup
        if: always()
        run: |
          set -euo pipefail
          umask 077
          if [ "${'${CONTAINMENT_RUN_STARTED:-0}'}" = 1 ]; then
            if ! result="$(node experimental/owned-container-lab/container-control.cjs --cleanup 2>/dev/null)"; then
              echo 'independent_cleanup=failed; raw_diagnostics_suppressed=true'
              node -e 'const f=require("node:fs"),S=["rootcheck","runempty","imageinspect","image_env_admission","intentspersisted","create","IDpersisted","created_security_admission","recordpersisted","start","gracefulwait","lingerready","probe","stop","cleanup_load","cleanup_stop","cleanup_remove","cleanup_absence","cleanup_residual","cleanup_rootremove"],G=["root","image_env","saved_record","absence","docker_cli","identity_config","env","namespace_config","bounds","tmpfs","host_mounts","ports","image_volumes","mounts","network_map","image_identity","create_id","created_state","workload_output","workload_state","persistence","private_file","cleanup_residual","root_absence","cli_args","intent"],C=["Hostname","Domainname","User","AttachStdin","AttachStdout","AttachStderr","ExposedPorts","Tty","OpenStdin","StdinOnce","Env","Cmd","Healthcheck","ArgsEscaped","Image","Volumes","WorkingDir","Entrypoint","NetworkDisabled","MacAddress","OnBuild","Labels","StopSignal","StopTimeout","Shell"],H=["Binds","ContainerIDFile","LogConfig","NetworkMode","PortBindings","RestartPolicy","AutoRemove","VolumeDriver","VolumesFrom","ConsoleSize","Annotations","CapAdd","CapDrop","CgroupnsMode","Dns","DnsOptions","DnsSearch","ExtraHosts","GroupAdd","IpcMode","Cgroup","Links","OomScoreAdj","PidMode","Privileged","PublishAllPorts","ReadonlyRootfs","SecurityOpt","StorageOpt","Tmpfs","UTSMode","UsernsMode","ShmSize","Sysctls","Runtime","Isolation","CpuShares","Memory","NanoCpus","CgroupParent","BlkioWeight","BlkioWeightDevice","BlkioDeviceReadBps","BlkioDeviceWriteBps","BlkioDeviceReadIOps","BlkioDeviceWriteIOps","CpuPeriod","CpuQuota","CpuRealtimePeriod","CpuRealtimeRuntime","CpusetCpus","CpusetMems","Devices","DeviceCgroupRules","DeviceRequests","MemoryReservation","MemorySwap","MemorySwappiness","OomKillDisable","PidsLimit","Ulimits","CpuCount","CpuPercent","IOMaximumIOps","IOMaximumBandwidth","Mounts","MaskedPaths","ReadonlyPaths","Init"];try{const r=JSON.parse(process.argv[2]==="file"?f.readFileSync(process.argv[1],"utf8"):process.argv[1]);const K=["status","reason","stage","gate","createdCount","startedCount","completedCount","networkMapObservation","imageEnvExpectedKeys","configComparison","hostConfigComparison","stateShape","changedConfigFields","changedHostConfigFields"];const field=(a,F)=>Array.isArray(a)&&a.length<=F.length+1&&new Set(a).size===a.length&&JSON.stringify(a)===JSON.stringify([...a].sort())&&a.every(s=>F.includes(s)||s==="other");if(JSON.stringify(Object.keys(r).sort())!==JSON.stringify(K.sort())||r.status!=="failed"||r.reason!=="containment_unverified"||!S.includes(r.stage)||!G.includes(r.gate)||!["empty","none_only","other","missing"].includes(r.networkMapObservation)||typeof r.imageEnvExpectedKeys!=="boolean"||![r.createdCount,r.startedCount,r.completedCount].every(n=>Number.isInteger(n)&&n>=0&&n<=2)||![r.configComparison,r.hostConfigComparison].every(s=>["not_observed","equal","different"].includes(s))||!["not_observed","valid","invalid"].includes(r.stateShape)||!field(r.changedConfigFields,C)||!field(r.changedHostConfigFields,H))throw 0;console.log(JSON.stringify({containmentFailure:true,stage:r.stage,gate:r.gate,acknowledgedCreatedCount:r.createdCount,acknowledgedStartedCount:r.startedCount,completedProofCount:r.completedCount,countScope:"current_invocation_only",networkMapObservation:r.networkMapObservation,imageEnvExpectedKeys:r.imageEnvExpectedKeys,configComparison:r.configComparison,hostConfigComparison:r.hostConfigComparison,stateShape:r.stateShape,changedConfigFields:r.changedConfigFields,changedHostConfigFields:r.changedHostConfigFields,rawDiagnosticsSuppressed:true}));}catch{console.log("fixed_field_diagnostic_unavailable=true; raw_diagnostics_suppressed=true");}' "$result" text
              exit 1
            fi
            node -e 'const r=JSON.parse(process.argv[1]);if(r.status!=="cleanup_verified"||r.containersAbsent!==true||r.privateRootAbsent!==true)process.exit(1);console.log("independent_cleanup=verified; exact_owned_containers_absent=true; private_namespace_absent=true; host_workload_PID_signals=false; physical_erasure=false");' "$result"
          else
            node -e 'const f=require("node:fs"),p=require("node:path"),r=process.env.PRIVATE_CONTAINMENT_ROOT;if(!r||p.dirname(r)!==process.env.RUNNER_TEMP||!p.basename(r).startsWith("owned-containment."))process.exit(1);const s=f.lstatSync(r);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&4095)!==448)process.exit(1);f.rmSync(r,{recursive:true});if(f.existsSync(r))process.exit(1);console.log("runtime_not_started=true; private_namespace_absent=true; container_runtime_cleanup_claim=false");'
          fi
          node -e 'const f=require("node:fs"),p=require("node:path"),r=process.env.PRIVATE_CONTAINMENT_LOG_ROOT;if(!r||p.dirname(r)!==process.env.RUNNER_TEMP||!p.basename(r).startsWith("owned-container-logs."))process.exit(1);const s=f.lstatSync(r);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&4095)!==448)process.exit(1);f.rmSync(r,{recursive:true});if(f.existsSync(r))process.exit(1);console.log("independent_build_log_namespace_absent=true; physical_erasure=false");'
`;
f.writeFileSync(root+'/.github/workflows/matrix-owned-container-lab.yml',y);console.log(JSON.stringify({workflowPrepared:true,sourcePolicyPins:Object.keys(pins).length,actualSDKIntegration:false}));
