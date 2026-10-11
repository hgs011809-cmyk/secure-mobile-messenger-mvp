# Persisted ciphertext corruption and conflicting retry: Linux verified

## Inspected runtime proof
- Run https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38156343209 ; job114520000959; workflowe6aa9d93021f7a491f93530c623e92ac2bd8aea0, source3421bc8dfb831df235e780384f97334c1e87d5cd. Lab branch only. Run14s/job10s/tests2s.
- Actual aggregate: NEW6/pass6/fail0/cancelled0/skipped0, flattrue/runnerexit0. 34unchanged source/policy +3newfile+1priorworkflow=38guards before AND after.
- Separate always cleanup: owned test processes alive0/stopped0, suite children0, containers created0, private namespace absenttrue. No container teardown claim (none created); logical unlink, not physical erasure or hardrunnerloss guarantee.

## Exact six cases, eight MiB ciphertext, 256KiB chunks
1. Persisted chunk shortened1byte: resume/retry/finalize invalid_stored_chunk; direct actualstream decrypt HASH_MISMATCH,0plaintext callbacks/bytes.
2. Persisted chunk extended1byte: same exact denials, bounded extension only.
3. Same-length flipped ciphertext: resume still lists32chunks/8MiB (LENGTHONLY); originalretry conflicting_retry; finalize integrity_failed; actualstream HASH_MISMATCH,0plaintext.
4. Altered retry payload with its own validhash: conflicting_retry leavescache/source unchanged; original lostACK retry repeatedtrue; fullcipherhash and realplaintext length/hash positivecontrol valid.
5. MOCKfalse authorization precedescorruption: not_authorized; independent actualstream AUTHORIZATION_DENIED,0plaintext.
6. Changedbinding manifest: initialize manifest_changed only; originalmanifest still finalizes/decryptsvalid. No subsequent-method-denial claim.

Post-injection fingerprints independently include every manifest/chunk length/mode/uid/hash and sender ciphertext; negative reads/retries preserve damagedcache/source, not repair. Real parent plaintextsink instrumented and positivecontrolled; receiver-stage denials stop beforedecrypt, independent actualdecrypt negatives separately exercised. Keys/descriptorRAMonly; no plaintext/key files or public rawlogs/artifacts.

## Existing boundaries / proposals only
Resume doesnot verifywholecipherhash; verified finalization/trusted descriptor gate required before release. Bare receiver initialization failure is NOTlatched: callers must gate subsequentoperations. Any core enforcement requires separate approved change/review; untouchedduringwindow. No newcrypto/policy or trustweakening.

## Review, diagnostics and limits
Independent read-only review vaiH1ur5fWbRXV4y: no criticalfindings,38/38pinsmatch. Implementer BCARqP3aYUnSeJBa: three sources/four embeddedNode commands parse/generator idempotence only, no Windowsruntime claim. Initial Actions run discovery delayed: allruns/branchfilter/workflowlist/commit showednothing; read-only YAMLdiagnosis inconclusive. Originalpush later appearedand completed; NOduplicate trigger/retry, no runtimefailure/timeout/skip. CIactionsNode20deprecated/forcedNode24warning, testsNode22; no upgradechange.

Synthetic/mockauth+clockonly, singleownertrustedlocalfilesystem, no childprocess or actualSDK in thissuite. Prior pendingwrite6/6, ACKidle4/4 and actualSDK5/5 separate; no composedSDKcrashproof. No actualMXC/Internet/Android/GB/RSS/repair/durability/wholeapp/powerloss/physicalerase/atomicrevocation proof. main/Pages/app/NCP/deploy/cost/capacity/policies unchanged. Nextscheduledrun read-only actualSDK->privateIPCreceiver feasibility; no new phase now.
