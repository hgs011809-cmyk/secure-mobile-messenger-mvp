import {createPublicKey,verify} from 'node:crypto';
function canonical(v){if(v===null||typeof v!=='object')return JSON.stringify(v);if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';}
const content=v=>Object.fromEntries(Object.entries(v).filter(([k])=>k!=='signatures'&&k!=='unsigned'));
const object=v=>v&&typeof v==='object'&&!Array.isArray(v);
const keyObject=pub=>createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(pub,'base64')]),format:'der',type:'spki'});
// Runtime post-SAS signing of ONLY the two already-pinned master identities.
export function authorizePinnedSignatures({method,target,body,identity,binding}){
 try{
  if(method!=='POST'||target!=='/_matrix/client/v3/keys/signatures/upload'||!identity||!object(body)||Object.keys(body).length<1||Object.keys(body).length>2)return null;
  const signer=binding.ownerSigning?.[identity.userId]?.userSigning;const signerKeys=object(signer?.keys)?Object.values(signer.keys):[];if(signerKeys.length!==1)return null;
  const pub=signerKeys[0];if(typeof pub!=='string'||Buffer.from(pub,'base64').length!==32)return null;
  for(const [uid,targets]of Object.entries(body)){
   const peer=binding.devices.find(d=>d.userId===uid);if(!peer||peer.active===false||!object(targets)||Object.keys(targets).length!==1)return null;
   const expected=binding.ownerSigning?.[uid]?.master;if(!object(expected))return null;
   const [id,card]=Object.entries(targets)[0];const master=Object.values(expected.keys||{})[0];
   if(![master,'ed25519:'+master].includes(id)||!object(card)||canonical(content(card))!==canonical(content(expected))||!object(card.signatures))return null;
   for(const [owner,signatures]of Object.entries(card.signatures)){
    if(!object(signatures))return null;
    for(const [key,sig]of Object.entries(signatures)){
     if(owner===identity.userId&&key==='ed25519:'+pub){if(typeof sig!=='string'||!verify(null,Buffer.from(canonical(content(card))),keyObject(pub),Buffer.from(sig,'base64')))return null;}
     else if(expected.signatures?.[owner]?.[key]!==sig)return null;
    }
   }
   if(typeof card.signatures[identity.userId]?.['ed25519:'+pub]!=='string')return null;
  }
  return {method,path:target,body};
 }catch{return null;}
}
