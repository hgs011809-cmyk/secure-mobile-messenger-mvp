// Inserted into a separate copy of live-browser.html; not a production module.
const {receiveDescriptor,validateFileDescriptor}=await import('./descriptor-receipt.mjs');
let descriptorDecryptCalls=0;
function descriptorB64(bytes){let s='';for(const x of bytes)s+=String.fromCharCode(x);return btoa(s).replace(/=+$/,'');}
function descriptorBytes(text){const s=atob(text);return Uint8Array.from(s,c=>c.charCodeAt(0));}
async function descriptorFound(id){
  let found;
  await wait(async()=>{found=timelineEvent(id);if(!found)return false;
    if(found.isRedacted())return true;
    try{await client.decryptEventIfNeeded(found);}catch{return false;}
    return !found.isDecryptionFailure()&&found.getType()==='m.room.message';},'descriptor_event');
  return found;
}
async function descriptorSend({descriptor,invalid=false}){
  const copied=validateFileDescriptor(descriptor);
  await requireConversation().assertSendAllowed();
  const file={...copied,url:'mxc://synthetic.invalid/descriptor-only'};
  if(invalid)file.v='v3';
  return (await client.sendEvent(bound.room,'m.room.message',{msgtype:'m.file',body:'synthetic.bin',file})).event_id;
}
async function descriptorReceive({event,ciphertext,expectedDigest}){
  const target=requireConversation(),found=await descriptorFound(event);
  const receipt=await receiveDescriptor(target,found);
  if(!Array.isArray(ciphertext)||ciphertext.length>65536||!ciphertext.every(x=>Number.isInteger(x)&&x>=0&&x<=255))throw new Error('descriptor_fixture_byte_limit');
  const bytes=new Uint8Array(ciphertext);
  const hash=descriptorB64(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));
  if(hash!==receipt.descriptor.hashes.sha256)throw new Error('descriptor_ciphertext_hash_mismatch');
  await receiveDescriptor(target,found);
  const key=await crypto.subtle.importKey('jwk',receipt.descriptor.key,{name:'AES-CTR'},false,['decrypt']);
  await receiveDescriptor(target,found);
  descriptorDecryptCalls++;
  const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-CTR',counter:descriptorBytes(receipt.descriptor.iv),length:64},key,bytes));
  try{
    await receiveDescriptor(target,found);
    const digest=descriptorB64(new Uint8Array(await crypto.subtle.digest('SHA-256',plain)));
    await receiveDescriptor(target,found);
    return {sdkDerivedDescriptor:true,wholeHashBeforeDecrypt:true,plaintextDigestMatches:digest===expectedDigest,
      textRendererExcluded:!target.snapshot().some(m=>m.id===event),fixtureBytes:plain.length};
  }finally{plain.fill(0);}
}
async function descriptorDenied({expectedError,...args}){
  if(!['INVALID_DESCRIPTOR','REDACTED','descriptor_ciphertext_hash_mismatch'].includes(expectedError))throw new Error('invalid_negative_probe');
  const before=descriptorDecryptCalls;let rejected=false;
  try{await descriptorReceive(args);}catch(error){rejected=error?.code===expectedError||error?.message===expectedError;}
  // Timeout, network/trust or unrelated failure is NOT expected-rejection proof.
  const found=timelineEvent(args.event);
  const intendedEventState=Boolean(found&&(expectedError==='REDACTED'?found.isRedacted():found.isEncrypted()&&!found.isDecryptionFailure()&&found.getType()==='m.room.message'));
  return {rejected,noDecrypt:before===descriptorDecryptCalls,intendedEventState};
}
