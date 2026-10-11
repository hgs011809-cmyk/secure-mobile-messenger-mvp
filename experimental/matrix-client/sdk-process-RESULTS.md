# Synthetic ciphertext-only IPC foundation

## Inspected Linux proof
- Run https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38158717874 , job114526955635. Sourceca0ef1f9ea059137544b606e902f9d3809a476d0; workflowec3cf78e9fa439b830983b6c1e0e690d36402460. One run only.
- Actual aggregate:6 tests,6 pass,0 fail/cancelled/skipped,flattrue,runnerexit0.44 pins verified both before and after runtime. Aggregate UI and public raw aggregate lines inspected, not greenbadge inference.
- Independent always cleanup:owned workers absent,private fixture namespace absent,forced cleanup0. Containers created0; no container teardown claim. Logical cleanup,not physical erase/hardrunnerloss.

## Six boundaries, synthetic authority ONLY
1.8MiB ciphertext/256KiB chunks, fresh callbacks aggregate>100, different PID after observed clean exit,exactresume16/idempotentretry/full hash. Child minimalenv TZonly; parentsecret sentinelabsent assertedwithoutvalue disclosure.
2. Ordinary authfalse exactnot_authorized thenSESSION_DENIED; invalidmanifest then validinitialize remainsSESSION_DENIED.
3. Stalerequest/wronggeneration/deadlinemismatch/outofordercheckpoint each SESSION_CLOSED with observedexit. These are fieldfaults,not complete replay/expiry coverage.
4. Missingauthorityreply spontaneously timesout andexits; SESSION_CLOSED, no explicitclose causesexit.
5. Unresolved abort-aware parentauthority callback automatically childexit,abortsignalobserved,postexit commandsdenied. An arbitrary ignoring-AbortSignal callback is not proven cancelled.
6. Same-lengthpersistedmutation lengthonlyresume32,finalizeintegrity_failed,retryconflicting_retry;postdamagecache/source unchanged, no repair.

## Review and failures retained
ImplementerA92R3SAa3nq5AGar; independentreviewnx9aaScAATxMMaK0 initialISSUES(timeout/latch/environment/guardmode/schema), correctedre-reviewPASS for foundationCIonly. Sixsource syntaxcompiled Node22maincontext. DirectWindows --check EPERM is a failedattempt,notpass. No Windowsruntime test. ActionNode20deprecated/forcedNode24 and punycodewarnings observed,separate fromNode22suite; no actionupgrade.

## Not established
Actual SDK receipt/BOTH current nativeleases/exactimmutableACTIVEbindings/device-room-eventauthorityadapter UNIMPLEMENTED. Child IPC callback tests are synthetic,notactualSDK orrevocation proof. No plaintextcallback exists,so structuralciphertext-only vocabulary is NOT cryptographiczero-plaintext proof. Earlier actualSDK5/5,processACKidle4/4,writefault6/6,corruption6/6 remain separate. No wholeapp/runnerrestart/keyrestore/powerloss/MXC/Internet/Android/GB/RSS/atomicrevocation/physicalerase orproductionchange. Consumedvaliddecisionreplay,actualexpiredtiming,unsolicited/malformedresults,independentdisconnect andintentionallyfailedguardcleanup notseparatelyexecuted.

Next scheduledrun may implement ONE NEW actualSDKauthorityadapter candidate with exactinitialbinding snapshot and abortablefreshparentcallbacks; noexistingpolicy/corechanges. If unsafe choosecoldrecipient/quota alternative. Boundedstepcomplete,nofurtherphase thisrun.
