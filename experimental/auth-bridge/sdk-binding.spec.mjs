import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {SdkBindingRegistry} from './sdk-binding.mjs';
import {fingerprintSpki} from '../../infra/ncp/auth/src/crypto.js';
// Disposable fixture keys are generated in memory and never logged.
const pin=n=>Buffer.alloc(32,n).toString('base64').replace(/=+$/, '');
async function fixture(t){
 const dir=await mkdtemp(join(tmpdir(),'sdk-binding-test-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 let clock=1000;const devices=new Map(),pairs=new Map();
 for(let n=1;n<=3;n++){const p=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pub=p.publicKey.export({format:'der',type:'spki'}).toString('base64url');pairs.set(n,p);devices.set('bridge-'+n,{publicKeySpkiB64:pub,fingerprint:fingerprintSpki(pub)});}
 const options={file:join(dir,'binding.json'),getDevice:async id=>devices.get(id)||null,now:()=>clock},registry=new SdkBindingRegistry(options);
 const keys=n=>({ed25519:pin(n),curve25519:pin(n+10)});
 const challenge=(n,k=keys(n))=>registry.challenge({deviceId:'bridge-'+n,userId:'@u'+n+':matrix.ci',matrixDeviceId:'D'+n},k);
 const signature=(c,n)=>sign('sha256',Buffer.from(c.text),{key:pairs.get(n).privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
 const approve=async n=>{const c=await challenge(n);return registry.approve(c.id,signature(c,n));};
 return {registry,options,devices,keys,challenge,signature,approve,advance:n=>{clock+=n;}};
}
test('real P256 approval persists exact pins',{timeout:5000},async t=>{const f=await fixture(t);assert.equal(await f.approve(1),true);const d=await f.registry.read();assert.deepEqual(d.devices,[{deviceId:'bridge-1',userId:'@u1:matrix.ci',matrixDeviceId:'D1',...f.keys(1)}]);assert.deepEqual(await new SdkBindingRegistry(f.options).read(),d);});
test('approval is single-use',{timeout:5000},async t=>{const f=await fixture(t),c=await f.challenge(1),sig=f.signature(c,1);await f.registry.approve(c.id,sig);await assert.rejects(f.registry.approve(c.id,sig),/binding_challenge_expired/);});
test('wrong signature denies and consumes challenge',{timeout:5000},async t=>{const f=await fixture(t),c=await f.challenge(1);await assert.rejects(f.registry.approve(c.id,f.signature(c,2)),/binding_signature_invalid/);assert.equal((await f.registry.read()).devices.length,0);await assert.rejects(f.registry.approve(c.id,f.signature(c,1)),/binding_challenge_expired/);});
test('challenge expires at exact 30 second boundary',{timeout:5000},async t=>{const f=await fixture(t),c=await f.challenge(1);f.advance(30000);await assert.rejects(f.registry.approve(c.id,f.signature(c,1)),/binding_challenge_expired/);assert.equal((await f.registry.read()).devices.length,0);});
test('current device revoked after challenge is denied',{timeout:5000},async t=>{const f=await fixture(t),c=await f.challenge(1);f.devices.delete('bridge-1');await assert.rejects(f.registry.approve(c.id,f.signature(c,1)),/binding_signature_invalid/);await assert.rejects(f.challenge(1),/not_enrolled/);assert.equal((await f.registry.read()).devices.length,0);});
test('current enrollment key replacement invalidates approval',{timeout:5000},async t=>{const f=await fixture(t),c=await f.challenge(1);f.devices.set('bridge-1',f.devices.get('bridge-2'));await assert.rejects(f.registry.approve(c.id,f.signature(c,1)),/binding_signature_invalid/);});
test('pins immutable and identical approval idempotent',{timeout:5000},async t=>{const f=await fixture(t);await f.approve(1);const before=await f.registry.read(),c=await f.challenge(1,f.keys(3));await assert.rejects(f.registry.approve(c.id,f.signature(c,1)),/binding_replacement_denied/);await f.approve(1);assert.deepEqual(await f.registry.read(),before);});
test('maximum two devices persist and room lock immutable',{timeout:5000},async t=>{const f=await fixture(t);await f.approve(1);await assert.rejects(f.registry.bindRoom('!room0001:matrix.ci'),/room_binding_locked/);await f.approve(2);await assert.rejects(f.approve(3),/binding_capacity/);await f.registry.bindRoom('!room0001:matrix.ci');await f.registry.bindRoom('!room0001:matrix.ci');await assert.rejects(f.registry.bindRoom('!room0002:matrix.ci'),/room_binding_locked/);const d=await new SdkBindingRegistry(f.options).read();assert.equal(d.devices.length,2);assert.equal(d.roomId,'!room0001:matrix.ci');});
