// Four flat POSIX-only unit tests. Mock receipt/authorize only: NOT Matrix SDK
// receipt verification or native fresh-session authorization evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {prepareTransportFixture,attachTransportReceiver} from './transport-pipeline.mjs';

const POSIX={skip:process.platform==='win32'};
const TOTAL=8*1024*1024,CHUNK=256*1024;
const check=(value,label)=>assert.ok(value===true,label);
async function withFixture(run) {
  let root,fixture,session;
  try {
    root=await fs.mkdtemp(path.join(os.tmpdir(),'transport-unit-'));
    await fs.chmod(root,0o700);
    fixture=await prepareTransportFixture(root);
    const receipt=Object.freeze({eventId:'$mock-transport-event',roomId:'!mock-room:example.invalid',
      senderUserId:'@mock-peer:example.invalid',senderDeviceId:'MOCK_DEVICE',descriptor:fixture.descriptor});
    const control={allowed:true,calls:0};
    session=attachTransportReceiver(fixture,receipt,async actual=>{
      control.calls++;check(actual===receipt,'injected gate receives original mock receipt');
      return control.allowed;
    });
    await run({fixture,session,control,root});
  } finally {
    // Attempt every cleanup independently. No descriptor/path/ciphertext logs.
    let good=true;
    if(session)try{await session.cleanup();}catch{good=false;}
    if(fixture)try{await fixture.dispose();}catch{good=false;}
    if(root)try{await fs.rm(root,{recursive:true,force:true});}catch{good=false;}
    check(good,'independent local cleanup completed');
  }
}
function preserved(result) {
  check(result.sourcePreserved&&result.receiverPreserved&&result.quarantineEmpty,
    'source and receiver immutable RAM baselines match; quarantine absent');
}
async function exactRejection(promise,code) {
  let matched=false;
  try{await promise;}catch(e){matched=e?.code===code&&e?.message===code;}
  check(matched,'exact static rejection code');
}

test('01 eight-MiB half-transfer recreation and lost-ack retry decrypt full digest',POSIX,async()=>{
  await withFixture(async({session,control})=>{
    const m=await session.completeResumedTransfer();
    check(m.descriptorMatches&&m.restarted&&m.lostAckRepeated&&m.complete&&m.presentSegments===32,
      'real synthetic receiver restart, resume and repeated sender acknowledgment');
    check(m.bytes===TOTAL&&m.chunkBytes===CHUNK&&m.policyBytes===64*1024*1024&&m.logicalPayloadCeiling===3*TOTAL,
      'bounded logical ciphertext policy, not physical allocation or RSS');
    check(m.bindingKind==='LOCAL_CONTEXT_IDENTIFIER_NOT_AUTH_MAC'&&/^[a-f0-9]{64}$/.test(m.bindingId)&&
      /^[a-f0-9]{32}$/.test(m.transferId),'safe local context and random transfer identifiers');
    check(Object.isFrozen(m)&&control.calls>0,'fresh injected unit gate exercised');
    const out=await session.decrypt();
    check(out.bytes===TOTAL&&out.digestMatches&&out.plaintextCallbacks===32,'full plaintext digest and bounded callbacks');
    preserved(await session.checkPreserved());
  });
});

test('02 copied-stream corruption proves exact HASH_MISMATCH with zero plaintext and intact caches',POSIX,async()=>{
  await withFixture(async({session})=>{
    await session.completeResumedTransfer();
    const denial=await session.denialProbe({expectedCode:'HASH_MISMATCH',corruptSource:true});
    check(denial.code==='HASH_MISMATCH'&&denial.bytes===0&&denial.plaintextCallbacks===0,
      'exact complete ciphertext SHA256 denial before plaintext');
    preserved(await session.checkPreserved());
    // Generic failures/wrong expected codes cannot count as denial evidence.
    await exactRejection(session.denialProbe({expectedCode:'AUTHORIZATION_DENIED',corruptSource:true}),'DENIAL_PROBE_FAILED');
    await exactRejection(session.denialProbe({expectedCode:'SOURCE_FAILED',corruptSource:true}),'INVALID_PROBE');
    const out=await session.decrypt();
    check(out.bytes===TOTAL&&out.digestMatches,'stored receiver ciphertext was not corrupted or repaired');
    preserved(await session.checkPreserved());
  });
});

test('03 injected authorization false gives exact denial and preserves both ciphertext copies',POSIX,async()=>{
  await withFixture(async({session,control})=>{
    await session.completeResumedTransfer();const before=control.calls;
    control.allowed=false; // mock-only revocation, never a real auth proof
    const denial=await session.denialProbe({expectedCode:'AUTHORIZATION_DENIED'});
    check(denial.code==='AUTHORIZATION_DENIED'&&denial.bytes===0&&denial.plaintextCallbacks===0&&control.calls>before,
      'fresh injected false gate and zero plaintext');
    await exactRejection(session.decrypt(),'AUTHORIZATION_DENIED');
    preserved(await session.checkPreserved());
  });
});

test('04 existing receiver erase marker and independent logical namespace cleanup close session',POSIX,async()=>{
  await withFixture(async({session,fixture,root})=>{
    await session.completeResumedTransfer();
    const result=await session.cleanup();
    check(result.receiverTombstoned&&result.namespacesRemoved&&result.physicalErasure===false,
      'existing erase API marker verified before independent namespace removal');
    check((await fs.readdir(root)).length===0,'all private namespaces absent');
    check(session.metrics().closed,'logical session closed');
    await exactRejection(session.decrypt(),'SESSION_CLOSED');
    await exactRejection(session.completeResumedTransfer(),'SESSION_CLOSED');
    const repeated=await fixture.dispose();
    check(repeated.namespacesRemoved&&repeated.physicalErasure===false,'idempotent fixture disposal without secure-erasure claim');
  });
});
