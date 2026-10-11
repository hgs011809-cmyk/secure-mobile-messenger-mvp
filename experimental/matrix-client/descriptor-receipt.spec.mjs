import test from 'node:test';
import assert from 'node:assert/strict';
import {validateFileDescriptor,receiveDescriptor} from './descriptor-receipt.mjs';

// Explicit unit fixtures, NOT actual Matrix SDK/Synapse/browser composition proof.
// Publicly known all-zero synthetic test key; RAM only, never secret material.
const PUBLIC_SYNTHETIC_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
function cryptoFixture() {
  return {v:'v2',key:{kty:'oct',alg:'A256CTR',ext:true,key_ops:['encrypt','decrypt'],k:PUBLIC_SYNTHETIC_KEY},iv:'AAAAAAAAAAAAAAAAAAAAAA',hashes:{sha256:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}};
}
function fixture() {
  const state={roomId:'!fixture:example.invalid',eventId:'$fixture',sender:'@peer:example.invalid',encrypted:true,failure:false,redacted:false,type:'m.room.message',tombstone:null,gates:0,lookups:0};
  const content={msgtype:'m.file',body:'Synthetic attachment fixture',file:{...cryptoFixture(),url:'mxc://example.invalid/synthetic_fixture'}};
  const event={getContent:()=>content,getRoomId:()=>state.roomId,getId:()=>state.eventId,getSender:()=>state.sender,isEncrypted:()=>state.encrypted,isDecryptionFailure:()=>state.failure,isRedacted:()=>state.redacted,getType:()=>state.type};
  const conversation={ready:true,roomId:state.roomId,peerUserId:state.sender,peerDeviceId:'SYNTHETIC_DEVICE',hiddenIds:new Set(),ledger:{async get(){state.lookups++;await state.onLookup?.(state.lookups);return state.tombstone;}},async assertReceiveAllowed(e){if(e!==event)throw new Error('fixture_denial');state.gates++;await state.onGate?.(state.gates);}};
  return {state,content,event,conversation};
}
const denied=(f,code)=>assert.rejects(receiveDescriptor(f.conversation,f.event),e=>e.code===code&&e.message===code);
const invalid=d=>assert.throws(()=>validateFileDescriptor(d),e=>e.code==='INVALID_DESCRIPTOR'&&e.message==='INVALID_DESCRIPTOR');

test('positive immutable copy from actual fixture event content',async()=>{
  const f=fixture(),r=await receiveDescriptor(f.conversation,f.event);
  assert.deepEqual(Object.keys(r).sort(),['descriptor','eventId','roomId','senderDeviceId','senderUserId'].sort());
  assert.equal(r.eventId,'$fixture');assert.equal(r.roomId,'!fixture:example.invalid');
  assert.equal(r.senderUserId,'@peer:example.invalid');assert.equal(r.senderDeviceId,'SYNTHETIC_DEVICE');
  assert.ok(Object.isFrozen(r)&&Object.isFrozen(r.descriptor)&&Object.isFrozen(r.descriptor.key)&&Object.isFrozen(r.descriptor.key.key_ops)&&Object.isFrozen(r.descriptor.hashes));
  assert.ok(r.descriptor!==f.content.file&&r.descriptor.key!==f.content.file.key&&r.descriptor.hashes!==f.content.file.hashes&&r.descriptor.key.key_ops!==f.content.file.key.key_ops);
  f.content.file.v='changed';f.content.file.key.key_ops[0]='changed';
  assert.equal(r.descriptor.v,'v2');assert.deepEqual(r.descriptor.key.key_ops,['encrypt','decrypt']);
  assert.ok(f.state.gates>=2&&f.state.lookups>=2);
  const nullProto=Object.assign(Object.create(null),cryptoFixture());
  nullProto.key.key_ops.reverse();assert.ok(Object.isFrozen(validateFileDescriptor(nullProto)));
});

test('plaintext event rejected',async()=>{
  const f=fixture();f.state.encrypted=false;await denied(f,'PLAINTEXT');assert.equal(f.state.gates,0);
});

test('undecrypted or decryption-failed event rejected',async()=>{
  const a=fixture();a.state.failure=true;await denied(a,'UNDECRYPTED');
  const b=fixture();b.state.type='m.room.encrypted';await denied(b,'UNDECRYPTED');
});

test('wrong room and changed room binding rejected',async()=>{
  const a=fixture();a.state.roomId='!other:example.invalid';await denied(a,'WRONG_ROOM');
  const b=fixture();b.state.onGate=async()=>{b.conversation.roomId='!other:example.invalid';};await denied(b,'WRONG_ROOM');
});

test('wrong peer including self sender rejected',async()=>{
  const a=fixture();a.state.sender='@self:example.invalid';await denied(a,'WRONG_PEER');
  const b=fixture();b.state.onGate=async()=>{b.state.sender='@other:example.invalid';};await denied(b,'WRONG_PEER');
});

test('redacted event rejected before and after async trust',async()=>{
  const a=fixture();a.state.redacted=true;await denied(a,'REDACTED');
  const b=fixture();b.state.onGate=async n=>{if(n===2)b.state.redacted=true;};await denied(b,'REDACTED');
});

test('durable tombstone and existing local hidden ID rejected',async()=>{
  const a=fixture();a.state.tombstone={status:'pending_server'};await denied(a,'DELETED');
  const b=fixture();b.state.tombstone={status:'server_redacted'};await denied(b,'DELETED');
  const c=fixture();c.conversation.hiddenIds.add('$fixture');await denied(c,'DELETED');
  const d=fixture();d.state.onLookup=async()=>{throw new Error('untrusted fixture exception');};await denied(d,'LEDGER_FAILED');
});

test('trust denial sanitized at initial and fresh post-validation gate',async()=>{
  for(const gate of [1,2,3]) {
    const f=fixture();f.state.onGate=async n=>{if(n===gate)throw new Error('untrusted fixture exception');};await denied(f,'TRUST_DENIED');
  }
  const unready=fixture();unready.conversation.ready=false;await denied(unready,'NOT_INITIALIZED');
});

test('deletion during asynchronous gates and ledger lookup wins',async()=>{
  for(const gate of [1,2,3]) {
    const local=fixture();local.state.onGate=async n=>{if(n===gate)local.conversation.hiddenIds.add('$fixture');};await denied(local,'DELETED');
    const durable=fixture();durable.state.onGate=async n=>{if(n===gate)durable.state.tombstone={status:'pending_server'};};await denied(durable,'DELETED');
  }
  const lookup=fixture();lookup.state.onLookup=async()=>{lookup.conversation.hiddenIds.add('$fixture');};await denied(lookup,'DELETED');
});

test('descriptor content URL and event context mutation during await rejected',async()=>{
  const changes=[f=>{f.content.file.hashes.sha256='AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';},f=>{f.content.file.url='mxc://example.invalid/changed';},f=>{f.content.body='Changed synthetic body';},f=>{f.state.eventId='$changed';},f=>{f.conversation.peerDeviceId='CHANGED_DEVICE';}];
  for(const change of changes) {
    const f=fixture();f.state.onGate=async()=>{change(f);};
    await assert.rejects(receiveDescriptor(f.conversation,f.event),e=>['CONTENT_CHANGED','EVENT_CHANGED'].includes(e.code)&&e.message===e.code);
  }
  const late=fixture();late.state.onLookup=async n=>{if(n===3)late.content.file.url='mxc://example.invalid/late';};await denied(late,'CONTENT_CHANGED');
});

test('invalid canonical crypto encodings and Matrix v2 constraints rejected',()=>{
  const changes=[d=>{d.v='v1';},d=>{d.key.kty='RSA';},d=>{d.key.alg='A256GCM';},d=>{d.key.ext=false;},d=>{d.key.key_ops=['encrypt','encrypt'];},d=>{d.key.k+='=';},d=>{d.key.k='A'.repeat(42)+'B';},d=>{d.key.k='A'.repeat(42)+'+';},d=>{d.iv+='==';},d=>{d.iv='A'.repeat(21)+'B';},d=>{d.iv='AAAAAAAAAAAAAAAAAAAAAQ';},d=>{d.hashes.sha256+='=';},d=>{d.hashes.sha256='A'.repeat(42)+'B';},d=>{d.hashes.sha256='A'.repeat(42)+'_';}];
  for(const change of changes) {const d=cryptoFixture();change(d);invalid(d);}
});

test('extra symbols inherited shapes and accessor properties rejected without getter execution',async()=>{
  let calls=0;
  const changes=[d=>{d.extra=true;},d=>{d[Symbol('extra')]=true;},d=>{d.key.extra=true;},d=>{d.hashes.extra=true;},d=>{d.key.key_ops.extra=true;},d=>{Object.setPrototypeOf(d,{inherited:true});},d=>{Object.defineProperty(d,'iv',{get(){calls++;return 'unused';}});},d=>{Object.defineProperty(d.key,'k',{get(){calls++;return 'unused';}});},d=>{Object.defineProperty(d.key.key_ops,'0',{get(){calls++;return 'encrypt';}});}];
  for(const change of changes) {const d=cryptoFixture();change(d);invalid(d);}
  const f=fixture();f.content.file.extra=true;await denied(f,'INVALID_CONTENT');
  const g=fixture();Object.defineProperty(g.content,'file',{get(){calls++;return {};}});await denied(g,'INVALID_CONTENT');
  assert.equal(calls,0);
});
