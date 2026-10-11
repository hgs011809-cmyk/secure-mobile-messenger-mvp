import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { authorizeSdkRequest } from './sdk-policy.mjs';

// Disposable fixture keys, never production credentials.
const pair = generateKeyPairSync('ed25519');
const otherPair = generateKeyPairSync('ed25519');
const b64 = n => Buffer.alloc(32, n).toString('base64').replace(/=+$/, '');
const pub = p => p.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64').replace(/=+$/, '');
const binding = { roomId: '!private:lab', devices: [
  { userId: '@a:lab', matrixDeviceId: 'A', ed25519: pub(pair), curve25519: b64(1) },
  { userId: '@b:lab', matrixDeviceId: 'B', ed25519: pub(otherPair), curve25519: b64(2) }
] };
const identity = { userId: '@a:lab', matrixDeviceId: 'A', deviceId: 'bridge-A' };
const root = '/_matrix/client/v3';
const room = `${root}/rooms/${encodeURIComponent(binding.roomId)}`;
const request = (method, target, body, extras = {}) => authorizeSdkRequest({method, target, body, identity, binding, ...extras});
const canonical = x => Array.isArray(x) ? '[' + x.map(canonical).join(',') + ']' : x && typeof x === 'object' ? '{' + Object.keys(x).sort().map(k => JSON.stringify(k)+':'+canonical(x[k])).join(',') + '}' : JSON.stringify(x);
function signed(x) {
  return {...x, signatures:{'@a:lab':{'ed25519:A':sign(null, Buffer.from(canonical(x)), pair.privateKey).toString('base64').replace(/=+$/, '')}}};
}
const deviceKeys = () => signed({user_id: '@a:lab', device_id:'A', algorithms:['m.olm.v1.curve25519-aes-sha2','m.megolm.v1.aes-sha2'], keys:{'ed25519:A':pub(pair),'curve25519:A':b64(1)}});
const megolm = () => ({algorithm:'m.megolm.v1.aes-sha2',device_id:'A',sender_key:b64(1),session_id:b64(3),ciphertext:b64(4)});
const toDevice = c => ({messages:{'@b:lab':{B:c}}});

test('public versions only; authenticated startup reads and schema', () => {
  assert.deepEqual(authorizeSdkRequest({method:'GET',target:'/_matrix/client/versions'}),{path:'/_matrix/client/versions',method:'GET',body:null,public:true});
  for (const route of ['/account/whoami','/devices','/capabilities','/pushrules','/pushrules/']) {
    assert.deepEqual(request('GET',root+route),{path:root+route,method:'GET',body:null});
    assert.equal(request('GET',root+route,null,{identity:null}),null);
  }
  assert.equal(request('GET',root+'/devices',{}),null);
});
test('default deny all privilege and lifecycle endpoints', () => {
  for (const route of ['login','register','refresh','logout','devices/A','delete_devices','dehydrated_device','createRoom','join/!other:lab','rooms/x/invite','rooms/x/leave','account/3pid','account/password','room_keys/version','keys/device_signing/upload','keys/signatures/upload','keys/changes','user/@a:lab/account_data/x']) {
    for (const method of ['GET','POST','PUT','DELETE']) assert.equal(request(method,root+'/'+route,{}),null,method+' '+route);
  }
  assert.equal(request('PUT',room+'/state/m.room.power_levels',{}),null);
  assert.equal(request('GET','/_synapse/admin/v1/users'),null);
});
test('canonical path and query restrictions fail closed', () => {
  for (const path of [room.replace('%3A','%253A')+'/state',room.replace('%3A','%2F')+'/state',root+'/rooms/../state',root+'//devices',root+'/%64evices',root+'/devices?access_token=x',root+'/devices?x=y',root+'/devices#fragment',root+'/devices?',root+'/devices?x=%ZZ',root+'/devices?x=one+two']) assert.equal(request('GET',path),null,path);
  assert.equal(request('GET',root+'/sync?timeout=1&timeout=2'),null);
  assert.equal(request('GET',root+'/sync?set_presence=online'),null);
  assert.equal(request('GET',root+'/sync?timeout=30001'),null);
});
test('sync always replaces client filter with fixed-room and sender/type filter', () => {
  const r = request('GET',root+'/sync?since=s1&timeout=100&filter=arbitrary');
  const q = new URL('http://lab'+r.path).searchParams, f = JSON.parse(q.get('filter'));
  assert.equal(q.get('since'),'s1'); assert.equal(q.get('timeout'),'100');
  assert.deepEqual(f.room.rooms,[binding.roomId]); assert.equal(f.room.include_leave,false);
  assert.deepEqual(f.to_device.senders,['@a:lab','@b:lab']);
  assert.equal(f.to_device.types.includes('m.room.encrypted'),true);
  assert.equal(f.to_device.types.includes('m.room_key'),false);
  assert.ok(request('GET',root+'/sync'));
});
test('client filter POST is rewritten and detached, not accepted verbatim', () => {
  const input = {room:{rooms:['!elsewhere:lab']}};
  const r = request('POST',root+'/user/%40a%3Alab/filter',input);
  assert.deepEqual(r.body.room.rooms,[binding.roomId]); assert.deepEqual(input.room.rooms,['!elsewhere:lab']);
  assert.equal(request('POST',root+'/user/%40b%3Alab/filter',input),null);
  assert.equal(request('GET',root+'/user/%40a%3Alab/filter/1'),null);
});
test('room reads are exact bound room, bounded query values survive', () => {
  for (const path of [room+'/state',room+'/members?at=s1',room+'/messages?dir=b&limit=100&from=s1',room+'/event/%24e%3Alab']) assert.equal(request('GET',path).path,path);
  for (const path of [root+'/rooms/%21other%3Alab/state',room+'/messages?dir=b&limit=101',room+'/messages?dir=b&filter=x',room+'/messages',room+'/state?x=y']) assert.equal(request('GET',path),null);
});
test('device upload checks pinned keys, canonical Ed25519 signature and exact fields', () => {
  assert.ok(request('POST',root+'/keys/upload',{device_keys:deviceKeys()}));
  const reordered = deviceKeys(); reordered.keys = {'curve25519:A':b64(1),'ed25519:A':pub(pair)};
  assert.ok(request('POST',root+'/keys/upload',{device_keys:reordered}));
  for (const edit of [d=>d.keys['curve25519:A']=b64(9),d=>d.device_id='B',d=>d.algorithms.push('plaintext'),d=>d.signatures['@a:lab']['ed25519:A']=Buffer.alloc(64).toString('base64'),d=>d.unsigned={},d=>d.keys.extra=b64(1)]) {
    const d=deviceKeys();edit(d);assert.equal(request('POST',root+'/keys/upload',{device_keys:d}),null);
  }
  assert.equal(request('POST',root+'/keys/upload',{device_keys:deviceKeys(),auth:{}}),null);
});
test('signed OTK and fallback keys bounded and signature checked', () => {
  const k = signed({key:b64(8)}), fallback=signed({key:b64(9),fallback:true});
  assert.ok(request('POST',root+'/keys/upload',{one_time_keys:{'signed_curve25519:1':k},fallback_keys:{'signed_curve25519:f':fallback}}));
  assert.equal(request('POST',root+'/keys/upload',{one_time_keys:{'curve25519:1':b64(8)}}),null);
  assert.equal(request('POST',root+'/keys/upload',{fallback_keys:{'signed_curve25519:f':k}}),null);
  assert.equal(request('POST',root+'/keys/upload',{one_time_keys:Object.fromEntries(Array.from({length:101},(_,i)=>['signed_curve25519:'+i,k]))}),null);
  const forged=structuredClone(k); forged.key=b64(1);
  assert.equal(request('POST',root+'/keys/upload',{one_time_keys:{'signed_curve25519:1':forged}}),null);
});
test('key query and claim only explicit admitted devices', () => {
  assert.ok(request('POST',root+'/keys/query',{device_keys:{'@a:lab':['A'],'@b:lab':['B']},timeout:100,token:'s1'}));
  assert.ok(request('POST',root+'/keys/claim',{one_time_keys:{'@b:lab':{B:'signed_curve25519'}},timeout:100}));
  const sdkQuery={device_keys:{'@a:lab':[],'@b:lab':[]}};
  assert.deepEqual(request('POST',root+'/keys/query',sdkQuery).body.device_keys,{'@a:lab':['A'],'@b:lab':['B']});
  assert.deepEqual(sdkQuery.device_keys,{'@a:lab':[],'@b:lab':[]});
  for (const body of [{device_keys:{'@b:lab':['*']}},{device_keys:{'@b:lab':['B','C']}},{device_keys:{'@x:lab':['B']}},{device_keys:{},extra:1}]) assert.equal(request('POST',root+'/keys/query',body),null);
  assert.equal(request('POST',root+'/keys/claim',{one_time_keys:{'@b:lab':{B:'curve25519'}}}),null);
});
test('Olm to-device sender and exact recipient envelopes', () => {
  const c={algorithm:'m.olm.v1.curve25519-aes-sha2',sender_key:b64(1),ciphertext:{[b64(2)]:{type:0,body:b64(8)}}};
  const path=root+'/sendToDevice/m.room.encrypted/txn';
  assert.ok(request('PUT',path,toDevice(c)));
  for (const edit of [v=>v.sender_key=b64(9),v=>v.ciphertext[b64(1)]=v.ciphertext[b64(2)],v=>v.ciphertext[b64(2)].type=2,v=>v.extra='fallback',v=>v.ciphertext[b64(2)].body='not base64']) {
    const v=structuredClone(c);edit(v);assert.equal(request('PUT',path,toDevice(v)),null);
  }
  assert.equal(request('PUT',path,{messages:{'@b:lab':{'*':c}}}),null);
  assert.equal(request('PUT',path,{messages:{'@a:lab':{A:c}}}),null);
  assert.equal(request('PUT',root+'/sendToDevice/m.room_key/txn',toDevice({})),null);
});
test('SAS type schemas enforce own from_device and forbid arbitrary content', () => {
  const samples={request:{from_device:'A',methods:['m.sas.v1'],timestamp:1},ready:{from_device:'A',methods:['m.sas.v1']},start:{from_device:'A',method:'m.sas.v1',key_agreement_protocols:['curve25519-hkdf-sha256'],hashes:['sha256'],message_authentication_codes:['hkdf-hmac-sha256.v2'],short_authentication_string:['decimal']},accept:{method:'m.sas.v1',key_agreement_protocol:'curve25519-hkdf-sha256',hash:'sha256',message_authentication_code:'hkdf-hmac-sha256.v2',short_authentication_string:['decimal'],commitment:b64(1)},key:{key:b64(1)},mac:{mac:{'ed25519:A':b64(1)},keys:b64(1)},done:{},cancel:{code:'m.user',reason:'User canceled'}};
  for (const [name, sample] of Object.entries(samples)) {
    const path=root+'/sendToDevice/m.key.verification.'+name+'/txn', content={...sample,transaction_id:'t1'};
    assert.ok(request('PUT',path,toDevice(content)),name);
    assert.equal(request('PUT',path,toDevice({...content,plaintext:'bad'})),null);
  }
  assert.equal(request('PUT',root+'/sendToDevice/m.key.verification.ready/txn',toDevice({from_device:'B',methods:['m.sas.v1'],transaction_id:'t1'})),null);
});
test('room send Megolm only and redaction empty body with bounded IDs', () => {
  const path=room+'/send/m.room.encrypted/txn';
  assert.ok(request('PUT',path,megolm()));
  for (const edit of [v=>v.device_id='B',v=>v.sender_key=b64(2),v=>v.algorithm='m.olm.v1.curve25519-aes-sha2',v=>v.ciphertext='hello world',v=>v.body='plaintext',v=>v.session_id='invalid']) {const v=megolm();edit(v);assert.equal(request('PUT',path,v),null);}
  assert.equal(request('PUT',room+'/send/m.room.message/txn',{body:'hello'}),null);
  assert.ok(request('PUT',room+'/redact/%24event%3Alab/txn',{}));
  assert.equal(request('PUT',room+'/redact/%24event%3Alab/txn',{reason:'x'}),null);
  assert.equal(request('PUT',room+'/redact/%24event%3Alab/'+'x'.repeat(129),{}),null);
});
test('malformed bindings, bodies and identity fail closed without mutation', () => {
  assert.equal(request('GET',root+'/sync',null,{binding:{...binding,devices:[binding.devices[0]]}}),null);
  assert.equal(request('GET',root+'/devices',null,{identity:{...identity,matrixDeviceId:'wrong'}}),null);
  const cyclic={};cyclic.self=cyclic;assert.equal(request('POST',root+'/keys/upload',cyclic),null);
  assert.equal(request('POST',root+'/keys/upload',{one_time_keys:undefined}),null);
  const body=megolm(), copy=structuredClone(body); const r=request('PUT',room+'/send/m.room.encrypted/txn',body); r.body.ciphertext=b64(9);assert.deepEqual(body,copy);
});

test('inactive peer prevents claims and sends but active caller retains reads/redaction', () => {
  const revoked={...binding,devices:[binding.devices[0],{...binding.devices[1],active:false}]};
  const options={binding:revoked};
  assert.ok(request('GET',room+'/state',null,options));
  assert.ok(request('PUT',room+'/redact/%24event%3Alab/txn',{},options));
  assert.equal(request('PUT',room+'/send/m.room.encrypted/txn',megolm(),options),null);
  assert.equal(request('POST',root+'/keys/claim',{one_time_keys:{'@b:lab':{B:'signed_curve25519'}}},options),null);
  assert.equal(request('PUT',root+'/sendToDevice/m.key.verification.done/txn',toDevice({transaction_id:'t1'}),options),null);
  assert.equal(request('GET',root+'/devices',null,{binding:{...binding,devices:[{...binding.devices[0],active:false},binding.devices[1]]}}),null);
});

test('additional owner self-signature requires pinned signer plus mandatory device signature',()=>{
 const ss=generateKeyPairSync('ed25519'),p=pub(ss),d=deviceKeys(),frame=Object.fromEntries(Object.entries(d).filter(([k])=>k!=='signatures'));
 d.signatures[identity.userId]['ed25519:'+p]=sign(null,Buffer.from(canonical(frame)),ss.privateKey).toString('base64').replace(/=+$/,'');
 const pins={...binding,ownerSigning:{[identity.userId]:{selfSigning:{keys:{['ed25519:'+p]:p}}}}};
 assert.ok(request('POST',root+'/keys/upload',{device_keys:d},{binding:pins}));assert.equal(request('POST',root+'/keys/upload',{device_keys:d}),null);
 const bad=structuredClone(d);bad.signatures[identity.userId]['ed25519:'+p]=Buffer.alloc(64).toString('base64').replace(/=+$/,'');assert.equal(request('POST',root+'/keys/upload',{device_keys:bad},{binding:pins}),null);
 delete d.signatures[identity.userId]['ed25519:A'];assert.equal(request('POST',root+'/keys/upload',{device_keys:d},{binding:pins}),null);
});

test('fixed-room sync timeline preserves policy state and never plaintext room messages',()=>{
 const r=request('GET',root+'/sync');const f=JSON.parse(new URL('http://lab'+r.path).searchParams.get('filter'));
 for(const type of ['m.room.create','m.room.encryption','m.room.history_visibility','m.room.join_rules','m.room.member','m.room.power_levels'])assert.ok(f.room.timeline.types.includes(type));
 assert.deepEqual(f.room.timeline.rooms,[binding.roomId]);assert.equal(f.room.timeline.types.includes('m.room.message'),false);assert.equal(f.room.timeline.types.includes('*'),false);
});

test('SDK to-device optional message id stays bounded without widening recipients or content',()=>{
 const path=root+'/sendToDevice/m.key.verification.request/tx1',c={from_device:'A',methods:['m.sas.v1'],timestamp:1,transaction_id:'tx1','org.matrix.msgid':'sdk-message-1'};
 assert.ok(request('PUT',path,toDevice(c)));
 for(const value of ['',42,'x'.repeat(129),'unsafe/id'])assert.equal(request('PUT',path,toDevice({...c,'org.matrix.msgid':value})),null);
 assert.equal(request('PUT',path,toDevice({...c,plaintext:'forbidden'})),null);assert.equal(request('PUT',path,{messages:{'@b:lab':{'*':c}}}),null);
 const encrypted={algorithm:'m.olm.v1.curve25519-aes-sha2',sender_key:b64(1),ciphertext:{[b64(2)]:{type:0,body:b64(3)}},'org.matrix.msgid':'sdk-message-2'};
 assert.ok(request('PUT',root+'/sendToDevice/m.room.encrypted/tx2',toDevice(encrypted)));assert.equal(request('PUT',root+'/sendToDevice/m.room.encrypted/tx2',toDevice({...encrypted,'org.matrix.msgid':null})),null);
});

test('SAS v2 compatibility name and opaque JSON transaction id do not widen URI or algorithms',()=>{
 const p=root+'/sendToDevice/m.key.verification.start/tx-safe',c={from_device:'A',method:'m.sas.v1',key_agreement_protocols:['curve25519-hkdf-sha256'],hashes:['sha256'],message_authentication_codes:['hkdf-hmac-sha256.v2','org.matrix.msc3783.hkdf-hmac-sha256'],short_authentication_string:['decimal','emoji'],transaction_id:'opaque/JSON+id=='};
 assert.ok(request('PUT',p,toDevice(c)));assert.equal(request('PUT',p,toDevice({...c,message_authentication_codes:['unknown-mac']})),null);
 for(const value of ['',null,'x'.repeat(129),'unsafe\u0000id'])assert.equal(request('PUT',p,toDevice({...c,transaction_id:value})),null);
 assert.equal(request('PUT',p.replace('tx-safe','unsafe%2Fid'),toDevice(c)),null);assert.equal(request('PUT',p,{messages:{'@b:lab':{'*':c}}}),null);
});

test('Rust SAS accept may omit method but cannot omit cryptographic negotiation fields',()=>{
 const p=root+'/sendToDevice/m.key.verification.accept/tx-accept',c={key_agreement_protocol:'curve25519-hkdf-sha256',hash:'sha256',message_authentication_code:'hkdf-hmac-sha256.v2',short_authentication_string:['decimal'],commitment:b64(1),transaction_id:'flow-1'};
 assert.ok(request('PUT',p,toDevice(c)));assert.ok(request('PUT',p,toDevice({...c,method:'m.sas.v1'})));assert.equal(request('PUT',p,toDevice({...c,method:'unknown-method'})),null);
 for(const name of ['key_agreement_protocol','hash','message_authentication_code','short_authentication_string','commitment','transaction_id']){const bad={...c};delete bad[name];assert.equal(request('PUT',p,toDevice(bad)),null);}
 assert.equal(request('PUT',p,toDevice({...c,message_authentication_code:'unknown-mac'})),null);
});
