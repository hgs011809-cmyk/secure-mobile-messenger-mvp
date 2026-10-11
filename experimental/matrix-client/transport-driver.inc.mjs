// Actual SDK control plane, private in-process ciphertext data plane; not MXC transport.
const transportAuthority=event=>async receipt=>{
 try{
  if(receipt.eventId!==event||receipt.roomId!==room||receipt.senderUserId!==a.userId||receipt.senderDeviceId!==a.deviceId)return false;
  const receiverSession=await resolve(b.accessToken),senderSession=await resolve(a.accessToken);
  if(!receiverSession||!senderSession||receiverSession.userId!==b.userId||receiverSession.matrixDeviceId!==b.deviceId||receiverSession.deviceId!==ids[1]||senderSession.userId!==a.userId||senderSession.matrixDeviceId!==a.deviceId||senderSession.deviceId!==ids[0])return false;
  const current=await binding();
  if(current.roomId!==room||current.devices.length!==2||current.devices.some(d=>!d.active)||!current.devices.some(d=>d.userId===b.userId&&d.matrixDeviceId===b.deviceId&&d.deviceId===ids[1])||!current.devices.some(d=>d.userId===a.userId&&d.matrixDeviceId===a.deviceId&&d.deviceId===ids[0]))return false;
  const sdk=await call(bob,'transportAuthorityStatus',{event});
  return sdk.allowed===true&&sdk.stage==='LIVE';
 }catch{return false;}
};
stage='authenticated transport resumed stream';
let activeFixture=await prepareTransportFixture(tmpdir());transportFixtures.add(activeFixture);
let transportEvent=await call(alice,'descriptorSend',{descriptor:activeFixture.descriptor});
let transportReceipt=sealTransportReceipt(await call(bob,'transportExport',{event:transportEvent}));
let transportSession=await attachTransportReceiver(activeFixture,transportReceipt,transportAuthority(transportEvent));
const resumedMetrics=await transportSession.completeResumedTransfer();
assert(resumedMetrics.restarted&&resumedMetrics.lostAckRepeated&&resumedMetrics.complete&&resumedMetrics.bytes===8388608&&resumedMetrics.chunkBytes===262144&&resumedMetrics.logicalPayloadCeiling===25165824);
const streamed=await transportSession.decrypt();
assert(streamed.bytes===8388608&&streamed.digestMatches&&streamed.plaintextCallbacks>0);
assert(await transportSession.checkPreserved());
transportGates.push('actual-SDK-receipt-to-preserving-receiver-restart-retry-stream-decrypt');
transportGates.push('native-latest-two-session-and-active-registry-plus-SDK-rechecks');
stage='authenticated transport tampered source';
const tampered=await transportSession.denialProbe({expectedCode:'HASH_MISMATCH',corruptSource:true});
assert(tampered.code==='HASH_MISMATCH'&&tampered.plaintextCallbacks===0&&tampered.bytes===0&&await transportSession.checkPreserved());
transportGates.push('tampered-stream-full-hash-denial-zero-plaintext-cache-preserved');
stage='authenticated transport actual descriptor redaction';
await call(bob,'remove',{event:transportEvent});await call(bob,'deleted',{event:transportEvent});
const beforeDeleteNative=await resolve(b.accessToken);assert(beforeDeleteNative&&await resolve(a.accessToken));
const deletedSdk=await call(bob,'transportAuthorityStatus',{event:transportEvent});assert(!deletedSdk.allowed&&deletedSdk.stage==='REDACTED');
const deletedTransport=await transportSession.denialProbe({expectedCode:'AUTHORIZATION_DENIED'});
assert(deletedTransport.code==='AUTHORIZATION_DENIED'&&deletedTransport.plaintextCallbacks===0&&deletedTransport.bytes===0&&await transportSession.checkPreserved());
transportGates.push('actual-SDK-redaction-denies-node-stream-while-native-leases-active');
const firstTransportCleanup=await transportSession.cleanup();assert(firstTransportCleanup.namespacesRemoved&&firstTransportCleanup.receiverTombstoned&&firstTransportCleanup.physicalErasure===false);transportFixtures.delete(activeFixture);
stage='authenticated transport native revocation preparation';
activeFixture=await prepareTransportFixture(tmpdir());transportFixtures.add(activeFixture);
transportEvent=await call(alice,'descriptorSend',{descriptor:activeFixture.descriptor});
transportReceipt=sealTransportReceipt(await call(bob,'transportExport',{event:transportEvent}));
transportSession=await attachTransportReceiver(activeFixture,transportReceipt,transportAuthority(transportEvent));
await transportSession.completeResumedTransfer();
const preRevoke=await transportSession.decrypt();assert(preRevoke.bytes===8388608&&preRevoke.digestMatches);
assert(await transportSession.checkPreserved());
// Kept until original coordinated-revocation stage; then exact cached-decrypt denial.
