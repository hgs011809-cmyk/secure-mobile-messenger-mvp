import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {authorizePinnedSignatures} from './signature-policy.mjs';
// Real ephemeral Ed25519 keys, retained only in memory and never printed.
const pair=()=>generateKeyPairSync('ed25519');
const pub=p=>p.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64').replace(/=+$/, '');
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const content=v=>Object.fromEntries(Object.entries(v).filter(([k])=>k!=='signatures'&&k!=='unsigned'));
const own='@own:matrix.ci',peer='@peer:matrix.ci';
function fixture(){
 const signing=pair(),otherSigning=pair(),masterPair=pair(),ownMaster=pair();
 const userSigning={user_id:own,usage:['user_signing'],keys:{['ed25519:'+pub(signing)]:pub(signing)}};
 const master={user_id:peer,usage:['master'],keys:{['ed25519:'+pub(masterPair)]:pub(masterPair)}};
 master.signatures={[peer]:{['ed25519:'+pub(masterPair)]:sign(null,Buffer.from(canonical(master)),masterPair.privateKey).toString('base64').replace(/=+$/, '')}};
 const ownCard={user_id:own,usage:['master'],keys:{['ed25519:'+pub(ownMaster)]:pub(ownMaster)}};
 const binding={devices:[{userId:own,matrixDeviceId:'OWN'},{userId:peer,matrixDeviceId:'PEER'}],ownerSigning:{[own]:{userSigning,master:ownCard},[peer]:{master,userSigning:{user_id:peer,usage:['user_signing'],keys:{['ed25519:'+pub(otherSigning)]:pub(otherSigning)}}}}};
 const card=structuredClone(master);card.signatures[own]={['ed25519:'+pub(signing)]:sign(null,Buffer.from(canonical(content(card))),signing.privateKey).toString('base64').replace(/=+$/, '')};
 const body={[peer]:{[pub(masterPair)]:card}};
 const input={method:'POST',target:'/_matrix/client/v3/keys/signatures/upload',identity:{userId:own,deviceId:'bridge-own',matrixDeviceId:'OWN'},binding,body};
 return {input,card,body,masterPair,signing,otherSigning};
}
test('real own user-signing signature accepts exact pinned peer master for both native key IDs',()=>{const f=fixture(),before=structuredClone(f.input);const r=authorizePinnedSignatures(f.input);assert.ok(r);assert.equal(r.path,f.input.target);assert.deepEqual(r.body,f.body);assert.deepEqual(f.input,before);const alternate={[peer]:{['ed25519:'+pub(f.masterPair)]:f.card}};assert.ok(authorizePinnedSignatures({...f.input,body:alternate}));});
test('extra target or unexpected target key is denied',()=>{const f=fixture();assert.equal(authorizePinnedSignatures({...f.input,body:{[peer]:{...f.body[peer],extra:f.card}}}),null);assert.equal(authorizePinnedSignatures({...f.input,body:{[peer]:{'ed25519:OTHER':f.card}}}),null);});
test('mutated master content rejected even if re-signed by own user-signing key',()=>{const f=fixture();f.card.keys={['ed25519:'+pub(f.otherSigning)]:pub(f.otherSigning)};f.card.signatures[own]['ed25519:'+pub(f.signing)]=sign(null,Buffer.from(canonical(content(f.card))),f.signing.privateKey).toString('base64');assert.equal(authorizePinnedSignatures(f.input),null);});
test('wrong signer, corrupt signature and missing own signature rejected',()=>{for(const mode of ['wrongSigner','corrupt','missing']){const f=fixture(),key='ed25519:'+pub(f.signing);if(mode==='wrongSigner')f.card.signatures[own][key]=sign(null,Buffer.from(canonical(content(f.card))),f.otherSigning.privateKey).toString('base64');if(mode==='corrupt')f.card.signatures[own][key]=Buffer.alloc(64).toString('base64');if(mode==='missing')delete f.card.signatures[own];assert.equal(authorizePinnedSignatures(f.input),null,mode);}});
test('third UID denied whether target or signature owner',()=>{const f=fixture();assert.equal(authorizePinnedSignatures({...f.input,body:{'@third:matrix.ci':f.body[peer]}}),null);f.card.signatures['@third:matrix.ci']={'ed25519:third':Buffer.alloc(64).toString('base64')};assert.equal(authorizePinnedSignatures(f.input),null);});
test('changed preexisting master signature and revoked target rejected',()=>{const f=fixture();f.card.signatures[peer]['ed25519:'+pub(f.masterPair)]=Buffer.alloc(64).toString('base64');assert.equal(authorizePinnedSignatures(f.input),null);const g=fixture();g.input.binding.devices[1].active=false;assert.equal(authorizePinnedSignatures(g.input),null);});
test('wrong method, route and absent identity denied',()=>{const f=fixture();for(const extra of [{method:'PUT'},{target:f.input.target+'?x=1'},{identity:null}])assert.equal(authorizePinnedSignatures({...f.input,...extra}),null);});
