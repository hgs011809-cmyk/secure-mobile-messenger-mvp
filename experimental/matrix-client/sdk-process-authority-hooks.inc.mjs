// NEW companion fragment for a NEW composed browser harness only.
// Insert in existing trusted module scope; expose explicitly in NEW window.lab.
// No native credentials/descriptors/keys persisted or logged. Public SDK device
// keys remain private parent/browser memory and never enter receiver child IPC.
async function sdkProcessAuthorityCrossBinding({event}){
 const fail=()=>{throw new Error('SDK_CROSS_BINDING_DENIED');};
 try{
  const c=requireClient(),conversation=requireConversation(),found=timelineEvent(event);
  if(!found)fail();
  const snapshot=()=>{
   const recipientUserId=c.getUserId(),recipientDeviceId=c.getDeviceId();
   if(!recipientUserId||!recipientDeviceId||conversation.client!==c||conversation.ready!==true||
      conversation.roomId!==bound.room||conversation.peerUserId!==bound.peer||conversation.peerDeviceId!==bound.device||
      found.getId()!==event||found.getRoomId()!==conversation.roomId||found.getSender()!==conversation.peerUserId||
      found.isRedacted()||found.isEncrypted()!==true||found.isDecryptionFailure()!==false||found.getType()!=='m.room.message'||
      conversation.hiddenIds.has(event))fail();
   return {recipientUserId,recipientDeviceId,roomId:conversation.roomId,peerUserId:conversation.peerUserId,
    peerDeviceId:conversation.peerDeviceId,eventId:found.getId(),eventSenderUserId:found.getSender(),
    eventSenderCurve25519:found.getSenderKey(),eventSenderEd25519:found.getClaimedEd25519Key()};
  };
  const initial=snapshot(),identity=JSON.stringify(initial);
  const check=()=>{if(requireClient()!==c||requireConversation()!==conversation||timelineEvent(event)!==found||JSON.stringify(snapshot())!==identity)fail();};
  await receiveDescriptor(conversation,found);check();
  const crypto=c.getCrypto();if(!crypto)fail();
  const devices=await crypto.getUserDeviceInfo([initial.recipientUserId,initial.peerUserId],true);check();
  const pair=(userId,matrixDeviceId)=>{
   const map=devices.get(userId),device=map?.get(matrixDeviceId);
   if(map?.size!==1||!device)fail();
   const ed25519=device.getFingerprint(),curve25519=device.getIdentityKey();
   if(typeof ed25519!=='string'||!ed25519||typeof curve25519!=='string'||!curve25519)fail();
   return {userId,matrixDeviceId,ed25519,curve25519};
  };
  const recipient=pair(initial.recipientUserId,initial.recipientDeviceId),sender=pair(initial.peerUserId,initial.peerDeviceId);
  if(initial.eventSenderCurve25519!==sender.curve25519||initial.eventSenderEd25519!==sender.ed25519)fail();
  await receiveDescriptor(conversation,found);check();
  return {...initial,devices:[recipient,sender]};
 }catch{throw new Error('SDK_CROSS_BINDING_DENIED');}
}
// NEW harness generator must register sdkProcessAuthorityCrossBinding on its
// window.lab object AFTER that object exists. No existing harness edited here.
