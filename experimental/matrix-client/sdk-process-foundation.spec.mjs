// Six synthetic FOUNDATION cases. No actual SDK/native auth, plaintext or crypto proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {promises as fs} from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {openCiphertextSession} from './sdk-process-session.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex'),SIZE=8388608,CHUNK=262144;
const opts={skip:process.platform!=='linux',timeout:60000};
async function fixture(fn){
 const base=process.env.PRIVATE_ATTACHMENT_ROOT;if(!base)throw Error('PRIVATE_ROOT_REQUIRED');
 const root=await fs.mkdtemp(path.join(base,'sdk-process-'));await fs.chmod(root,0o700);
 const data=randomBytes(SIZE),source=path.join(root,'source.bin');await fs.writeFile(source,data,{mode:0o600});
 const manifest={version:1,transferId:randomBytes(16).toString('hex'),bindingId:randomBytes(32).toString('hex'),totalBytes:SIZE,chunkBytes:CHUNK,sha256:sha(data),expiresAt:Date.now()+120000};
 const sessions=[];let checks=0;
 const open=async(extra={})=>{const s=await openCiphertextSession({root,manifest,authorize:async()=>{checks++;return true;},...extra});sessions.push(s);return s;};
 const accept=(s,i)=>s.command('accept',{index:i,offset:i*CHUNK,hex:data.subarray(i*CHUNK,(i+1)*CHUNK).toString('hex'),sha256:sha(data.subarray(i*CHUNK,(i+1)*CHUNK))});
 const cache=async()=>{const d=path.join(root,manifest.transferId);const result={};for(const n of (await fs.readdir(d)).sort())result[n]=sha(await fs.readFile(path.join(d,n)));return result;};
 try{await fn({root,manifest,data,open,accept,cache,checks:()=>checks});assert.equal(sha(await fs.readFile(source)),sha(data));}finally{for(const s of sessions)await s.close();await fs.rm(root,{recursive:true});await assert.rejects(()=>fs.lstat(root),{code:'ENOENT'});}
}
test('synthetic fresh authority, different PID exact resume, duplicate ACK and whole ciphertext hash',opts,async()=>fixture(async({open,accept,checks,manifest})=>{
 const prior=process.env.SDK_PROCESS_PARENT_SECRET;process.env.SDK_PROCESS_PARENT_SECRET=randomBytes(32).toString('hex');let s;try{s=await open();assert.equal(s.initialized,true);}finally{if(prior===undefined)delete process.env.SDK_PROCESS_PARENT_SECRET;else process.env.SDK_PROCESS_PARENT_SECRET=prior;}await s.command('initialize',{manifest});for(let i=0;i<16;i++)await accept(s,i);const first=s.pid;await s.close();s=await open();assert.notEqual(s.pid,first);await s.command('initialize',{manifest});assert.deepEqual((await s.command('resume')).present,Array.from({length:16},(_,i)=>i));assert.equal((await accept(s,15)).repeated,true);for(let i=16;i<32;i++)await accept(s,i);assert.deepEqual(await s.command('finalize'),{complete:true,totalBytes:SIZE});assert.ok(checks()>100);
}));
test('synthetic initialize denial permanently latches NEW wrapper',opts,async()=>fixture(async({open,manifest})=>{
 const s=await open({authorize:async()=>false});await assert.rejects(s.command('initialize',{manifest}),{message:'not_authorized'});await assert.rejects(s.command('resume'),{message:'SESSION_DENIED'});const invalid=await open();await assert.rejects(invalid.command('initialize',{manifest:{...manifest,version:2}}),{message:'invalid_manifest'});await assert.rejects(invalid.command('initialize',{manifest}),{message:'SESSION_DENIED'});
}));
test('synthetic stale wrong-generation deadline-mismatch and out-of-order IPC decisions fail closed',opts,async()=>{
 for(const fault of [r=>({...r,request:r.request-1}),r=>({...r,context:{...r.context,generation:'0'.repeat(64)}}),r=>({...r,deadline:r.deadline-10000}),r=>({...r,checkpoint:r.checkpoint+1})])await fixture(async({open,manifest})=>{const s=await open({syntheticDecisionFault:fault});await assert.rejects(s.command('initialize',{manifest}),{message:'SESSION_CLOSED'});await s.exited;await assert.rejects(s.command('resume'),{message:'SESSION_CLOSED'});});
});
test('synthetic missing authority reply times out, initialize remains denied, exit observed',opts,async()=>fixture(async({open,manifest})=>{
 const s=await open({syntheticDecisionFault:()=>null});await assert.rejects(s.command('initialize',{manifest}),{message:'SESSION_CLOSED'});await s.exited;await assert.rejects(s.command('resume'),{message:'SESSION_CLOSED'});
}));
test('synthetic unresolved authority automatically exits child and aborts parent callback',opts,async()=>fixture(async({open,manifest})=>{
 let entered,aborted=false;const called=new Promise(resolve=>{entered=resolve;});const s=await open({authorize:async(_q,signal)=>{entered();return new Promise(resolve=>{if(signal.aborted)resolve(false);else signal.addEventListener('abort',()=>{aborted=true;resolve(false);},{once:true});});}});const p=s.command('initialize',{manifest});const denial=assert.rejects(p,{message:'SESSION_CLOSED'});await called;await denial;await s.exited;assert.equal(aborted,true);await assert.rejects(s.command('resume'),{message:'SESSION_CLOSED'});
}));
test('same-length persisted mutation rejects whole hash and conflicting retry, preserves damaged cache',opts,async()=>fixture(async({open,accept,cache,root,manifest})=>{
 const s=await open();await s.command('initialize',{manifest});for(let i=0;i<32;i++)await accept(s,i);const file=path.join(root,manifest.transferId,'chunk-0.bin');const b=await fs.readFile(file);b[0]^=1;await fs.writeFile(file,b);const damaged=await cache();assert.equal((await s.command('resume')).present.length,32);await assert.rejects(s.command('finalize'),{message:'integrity_failed'});await assert.rejects(accept(s,0),{message:'conflicting_retry'});assert.deepEqual(await cache(),damaged);
}));
