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
