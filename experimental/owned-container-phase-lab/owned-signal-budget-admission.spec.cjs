'use strict';
// Pure proc-record/acceptance policy checks; no procfs, subprocess or network runtime.
const assert=require('node:assert/strict'),api=require('./owned-signal-budget-admission.cjs');let passed=0,failed=0;
function test(n,f){try{f();passed++;console.log('ok '+n);}catch{failed++;console.log('FAIL '+n);}}
function stat(pid=200,ppid=100,pgrp=100,session=100,start='42',comm='node'){const fields=['S',String(ppid),String(pgrp),String(session),'-1',...Array(15).fill('0')];fields[19]=start;return pid+' ('+comm+') '+fields.join(' ')+'\n';}
const self=api.parseProcStat(stat()),parent=api.parseProcStat(stat(100,50,100,100,'40','timeout'));
for(const comm of ['node','node with spaces','node (nested)','node ) ending)','(both) ()'])test('comm_'+comm,()=>assert.equal(api.parseProcStat(stat(200,100,100,100,'42',comm)).pid,200));
test('negative_opaque_field',()=>assert.equal(self.ppid,100));
test('owned_group_relationship',()=>assert.equal(api.validateRelationships(self,parent,200,100),true));
for(const [name,text] of [['empty',''],['missing_close','200 (node S 1'],['bad_pid',stat(0)],['oversized',stat()+'x'.repeat(4097)],['nul',stat().replace('node','no\0de')],['zero_ppid',stat(200,0)],['leadingzero',stat().replace('200 (','0200 (')],['truncated',stat().split(' ').slice(0,8).join(' ')],['negativezero',stat().replace(' -1 ',' -0 ')],['bad_start',stat(200,100,100,100,'18446744073709551616')],['exponent',stat().replace(' 100 ',' 1e2 ')],['newline_tail',stat()+'extra\n']])test('stat_reject_'+name,()=>assert.throws(()=>api.parseProcStat(text)));
for(const k of ['pid','ppid','pgrp','session'])test('self_mismatch_'+k,()=>assert.throws(()=>api.validateRelationships({...self,[k]:999},parent,200,100)));
for(const k of ['pid','pgrp','session'])test('parent_mismatch_'+k,()=>assert.throws(()=>api.validateRelationships(self,{...parent,[k]:999},200,100)));
for(const state of ['Z','X','D','T','t','I'])test('state_reject_'+state,()=>assert.throws(()=>api.validateRelationships(self,{...parent,state},200,100)));
const fd={attempted:5,succeeded:5,failed:0,allClosed:true};
const admission={kind:'owned_signal_budget_admission_v1',privateSessionGroupObserved:true,parentMonitorIdentityMatched:true,nodeIdentityMatched:true,parentStarttimeStableObserved:true,rootIdentityMatched:true,bootstrapSha256:'a'.repeat(64),termSeconds:95,conditionalKillGraceSeconds:5,guaranteedTermination:false,descendantCleanup:false,atomicFutureLivenessLease:false,fdCleanup:fd};
test('admission_pass',()=>assert.equal(api.validateAdmission(admission),true));
for(const k of ['privateSessionGroupObserved','parentMonitorIdentityMatched','nodeIdentityMatched','parentStarttimeStableObserved','rootIdentityMatched'])test('admission_false_'+k,()=>assert.throws(()=>api.validateAdmission({...admission,[k]:false})));
for(const k of ['guaranteedTermination','descendantCleanup','atomicFutureLivenessLease'])test('overclaim_'+k,()=>assert.throws(()=>api.validateAdmission({...admission,[k]:true})));
for(const patch of [{failed:1},{succeeded:4},{allClosed:false},{attempted:0,succeeded:0},{attempted:65,succeeded:65},{attempted:1.5}])test('fd_reject_'+JSON.stringify(patch),()=>assert.throws(()=>api.fdCounts({...fd,...patch})));
const anchor={kind:'ubuntu_anchor_runtime_preflight_candidate',status:'prerequisite_probe_only_verified',ownerTask:'IcUJ8UMoJUKXJWiB',cryptographicVerification:true,rawDiagnosticsSuppressed:true,fullChainAcceptance:false,currentSignerAllowlistAcceptance:false,freshnessAcceptance:false,fullDebianTrust:false,buildProof:false,packageInstallations:0,containersCreated:0,keyDownloads:0,keyImports:0,gpgvObserved:{spawned:true,exitObserved:true,closed:true,exitCode:0,signalPresent:false},signatures:{verified:true},scope:{expectedNobleScope:true,checksumChainVerified:false},packageIdentity:{localDatabaseAssertionOnly:true,independentAuthentication:false},publicStatus:{rawStatusRetained:false},fdCleanup:fd,ownedBudgetAdmission:admission};
test('anchor_prerequisite_only_pass',()=>assert.equal(api.validateAnchorGate(anchor),true));
for(const k of ['fullChainAcceptance','currentSignerAllowlistAcceptance','freshnessAcceptance','fullDebianTrust','buildProof'])test('anchor_overclaim_'+k,()=>assert.throws(()=>api.validateAnchorGate({...anchor,[k]:true})));
for(const k of ['spawned','exitObserved','closed'])test('anchor_child_missing_'+k,()=>assert.throws(()=>api.validateAnchorGate({...anchor,gpgvObserved:{...anchor.gpgvObserved,[k]:false}})));
test('anchor_signal_rejected',()=>assert.throws(()=>api.validateAnchorGate({...anchor,gpgvObserved:{...anchor.gpgvObserved,signalPresent:true}})));
test('anchor_failure_rejected',()=>assert.throws(()=>api.validateAnchorGate({...anchor,failureClass:'fd_cleanup'})));
test('anchor_unknown_child_rejected',()=>assert.throws(()=>api.validateAnchorGate({...anchor,childFailureObservation:{closed:false}})));
test('anchor_rawstatus_rejected',()=>assert.throws(()=>api.validateAnchorGate({...anchor,publicStatus:{rawStatusRetained:true}})));
test('bad_bootstrap_versions_pre_io',()=>assert.throws(()=>api.prepareBootstrap('/',{setsid:'unknown',timeout:'unknown'})));
test('bad_bootstrap_sha_pre_io',()=>assert.throws(()=>api.admit('/','invalid')));
console.log(JSON.stringify({kind:'owned_signal_budget_pure_spec',passed,failed,total:passed+failed,realChildren:0,procfsReads:0,networkRequests:0,cryptographicEvidence:false,monitorRuntimeEvidence:false}));if(failed)process.exitCode=1;
