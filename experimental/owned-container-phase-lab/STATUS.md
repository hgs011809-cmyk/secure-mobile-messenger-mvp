# Separate phase-contract fixture: IN PROGRESS, NO RUNTIME ACCEPTANCE

## Scope and preserved history

Explicit userapproval: separate new design/implementation/independentreview/isolatedCI, only lab-matrix-cleanup-followup. Existing owned-container-lab remains unchanged BLOCKED with fivefailedruns, no acceptedcases/verifiedcleanup/SDKintegration. No main/production/NCP/daemonprovision/privilegegrant/capacity/cost/policy change.

## Verified so far

- No-container readonly engine preflight PASS: run38184483084, commitfdec23d610b92af0c14e762cc36d501d7396a0b3, observed Docker28.0.4/cgroupv2/systemd/OOM-disableunsupported; created/started0. This is NOT full runtimeprofile, nativekernelproof or cleanup.
- After PCreboot, all11then-existingphase files preserved. Final local puretests kernel90/90, worker10/10, controller160/160, publicruntime-metadata20/20; fourJSsyntaxchecks PASS. These are decoder/statecontract data tests, no actualworker/Docker/nativehelper.
- Independent staticreviews PASS: kerneluBj7m1vztRbfpJ92, workerpxZmuVyNJ2nT1IpF, controlleryOEJJJrbCF4U4lZY. Controller source/buildprovenance gate still depends on independently reviewed parentpipeline. No successful nativeC compilation or helperexecution proof. The first readonly compile attempt failed before helper or workload execution.
- Fixed workerstringcoercion schema gap; tightenedownnullCapAdd and ancillarycontrols; expectednative source/binarySHA gates required. Existinghelper.json is consistencyonly, hashes notbinaryauthentication.
- ExactMoby28.0.4 publicsource reviewed at6430e49a55babd9b8f4d08e70ecb2b68900770fe, Apache2.0. Source confirms create verification clearsunsupportedOOMpointer, create adaptation restoresfalse, start re-verification clearsnil; only this precomputedrepresentation difference isallowed. NanoCPUs1000000000 gives100000/100000, equalmemory/swap1GiB sourceconversion gives swaponly0. Actualruntime path/nativewrites remain unverified.

## First readonly compile/profile CI failed

Run38186645877, commit59a8cff481c821de6e0276f84955668c459f85b8: source_pins51 verified, existingstrictfixtureunchanged. Nextgate `native_compile=failed; raw_diagnostics_suppressed=true`, exit1. Exactcompiler causeunknown becauseprivatecapturerawdiagnosticswere deliberatelysuppressed andlogrootlogicallyremoved. No fullruntimeprofileoutput, no CIpurecount acceptance and no nativehelper/worker/containerexecution. This is a separate NO-CONTAINER preflight failure, not a sixth old lifecycle run. Keep oldfivefailedruns unchanged. No security/syscall/deadline/Werror relaxation.

Nextreadonlydiagnostic revision may project onlyboundedline/column/severity/fixedwarningclass and continueindependentpuretests/softwaremetadata evenifcompilationfails; it muststill exit1 oncompilefailure and cannotgrant any runtimeacceptance.

## Still blocked / not yet demonstrated

Full exactengineGit/API/runc/containerd profile and matchinginstalled-runtime source need readonlycollection/review. accepted-engine-profile.json is intentionallyabsent: controllerblocks beforecreate. New parentworkflowneeds sourcepins/compile/export provenance review. No compilednativeproof, no actualPID1challenge, no liveproc/cgroupFDcorrelation, no kernel-limit/lifecycle/independentcleanup acceptance. SDK remainsblocked.

Next: backupthiscode checkpointwithout runtime; bounded no-containerCI compile/puretests+exactpublicsoftwaremetadata collection; source/profile/pipeline review; only then isolatednewlifecycleCI. Any unsupportedprofile/permission/layout/schema/ownership/bounds failure staysfailclosed. No sudo/caps/setns/hostPID/mount/signaling fallback.

## Evidence limits

Trusted isolatedCIhost/daemon/runtime/image/compiler boundary; environment flags notCIauthentication. RetainedFD consistencywindow is neither atomic norcontinuousadversarialhostproof. Workerreportednamespace/mount evidence is not independentlyhostreadprotectednamespace evidence. Only two mainchildren kernelwitnessed; notallbrowserdescendants. Afterexit no livekernelrevalidation. No physicalerasure/hardrunnerloss/GB-RSS/realusers/Android/Internet/MXC/media/SDK/production claim.

## USER REQUESTED STOP: checkpoint, no further execution

Readonlypreflight2 run38187584404 / commit9e23c3ecda01a93e4336ef51d6d4506f03b0a047 FAILED asrequired: sourcepins51PASS, pure4suites280/280PASS, native_compile=false. Compileraggregate line71 col16 error/unused matchedignoredwrite-result fallback. Minimalpatchconsumeswrite result/rejectserrororpartial andstillreturnsfailure; independentstaticPASS ONLY, NOTcompiled/retested. -Werror/syscalls/deadlines/securityunchanged.

ObservedmetadataONLY: Docker28.0.4/Git6430e49/API1.48/cgroup2/systemd/defaultRuntime runc; runc1.5.1/Gitv1.5.1-0-g8f2685a4; containerdv2.3.6/Gitee2735368117d2eb259779949d5e75cdafec9761; OOMdisableCapabilityfalse. No helper/worker/container execution, ownership/limits/cleanup/lifecycle proof or SDKintegration. Newlifecycleaccepted0; oldstrictfivefailuresunchanged. accepted-engine-profile.json remainsABSENT.

Partialpublicsource review only: runc v1.5.1 tag resolves8f2685a471d3347a686ad3909783d8aafc6bb208; containerd v2.3.6 resolves ee2735368117d2eb259779949d5e75cdafec9761; Apache2; source-pair support reported. Exactresource/path andinstalledbuild/provenance review INCOMPLETE, no profile acceptance.

UseraskedSAVEANDSTOP. No additionalCI/compiler/helper/worker/container/source investigation authorizedwhilepaused. Backupcommitmust[skip ci]. Resumeonlyafteruserrequest: reviewcheckpoint/pendingCfix, exactsource/runtime/build gates and independentreview before any newreadonlyCI; lifecycle/SDK remainblocked.

## Explicit resume: readonly native compile PASS

Run38217074965 / commit7444dd988ec96ce76bfea584b4e0ebce50333fa0 passed compile -std=c11 -O2 -Wall -Wextra -Werror andpure4suites280/280; readonlysoftwaremetadataunchanged. Savedwrite-resultfix nowhascompilerproof ONLY. Nativehelper/workerexecutionfalse, containers0, ownership/limits/lifecycle/cleanup/SDKproofNONE. Both earliernewreadonlyfailures andoldstrictfivefailures preserved.

engine-profile-candidate.json is anUNACCEPTED17field candidate: observed11softwarefields plus6PREDECLAREDlayout/CPUexpectations, notactualkernel/path evidence. accepted-engine-profile.json staysABSENT. Pidsrequire128 throughoutcontract/controller/kernel, no reductionto64. Parent source/build digest-export gates beingprepared separately; no lifecycle yet.

## Build-integrity/export gate prepared

Two new modules and30synthetic tests, localdirect30/30; firstNode--test discoveryfailed beforetests, retainednotpass. ControlledCLI module independentstaticPASS; candidate-schema/framingPASS; parent56pin compile/exportworkflowstaticPASS. SyntheticexportVM25/25 andpriorprojector20/20, noactualenvwrite/compiler/helper/container. FutureCIexportsONLYreviewedliteralCsourceSHA+just-builtELFbyteSHA aftersuccess; no binaryauth/semantic/malicioushost proof. NO-CONTAINERCIverificationpending; acceptedprofileabsent/lifecycle0/SDKblocked.
