import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, createCipheriv, randomBytes } from 'node:crypto';
import { SyntheticReceiver, validateManifest, MAX_BYTES } from './receiver.mjs';
const sha = b => createHash('sha256').update(b).digest('hex');
const block=65536;
const manifest=(b,over={})=>({version:1,transferId:'a'.repeat(32),bindingId:'b'.repeat(64),totalBytes:b.length,chunkBytes:block,sha256:sha(b),expiresAt:2000,...over});
async function fixture(t,b=Buffer.alloc(block,9),over={}){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'synthetic-cipher-'));await fs.chmod(root,0o700);
  t.after(async()=>{await fs.rm(root,{recursive:true,force:true});await assert.rejects(fs.stat(root),{code:'ENOENT'});});
  let active=true,now=1000;const m=manifest(b,over);
  const config={root,manifest:m,authorize:async binding=>active&&binding===m.bindingId,clock:()=>now};
  const r=new SyntheticReceiver(config);await r.initialize();
  return {r,root,b,m,config,setActive:x=>active=x,setTime:x=>now=x};
}
const send=(r,b,index=0)=>r.accept({index,offset:index*r.m.chunkBytes,bytes:b,sha256:sha(b)});
test('immutable manifest rejects traversal, overflow, unknown fields and invalid geometry',()=>{
  const b=Buffer.alloc(1),m=manifest(b);assert.equal(Object.isFrozen(validateManifest(m)),true);
  for(const over of [{transferId:'../escape'},{bindingId:'x'},{totalBytes:MAX_BYTES+1},{totalBytes:0},{totalBytes:1.5},{chunkBytes:0},{chunkBytes:1048577},{sha256:'bad'},{version:2},{extra:true}])assert.throws(()=>validateManifest({...m,...over}),/invalid_manifest/);
});
test('single and short final chunk reconstructed',async t=>{const f=await fixture(t,Buffer.alloc(17,4));await send(f.r,f.b);assert.deepEqual(await f.r.finalize(),{complete:true,totalBytes:17});});
test('exact chunk geometry; duplicate retry is idempotent',async t=>{const f=await fixture(t);assert.equal((await send(f.r,f.b)).repeated,false);assert.equal((await send(f.r,f.b)).repeated,true);assert.equal((await f.r.finalize()).complete,true);});
test('conflicting duplicate does not overwrite bytes',async t=>{const f=await fixture(t);await send(f.r,f.b);await assert.rejects(send(f.r,Buffer.alloc(block,2)),/conflicting_retry/);assert.equal((await f.r.finalize()).complete,true);});
test('wrong indices, offsets, size and hash rejected before persistence',async t=>{const f=await fixture(t);for(const index of [-1,0.5,1,Number.MAX_SAFE_INTEGER])await assert.rejects(f.r.accept({index,offset:0,bytes:f.b,sha256:sha(f.b)}),/invalid_index/);for(const over of [{offset:1},{bytes:Buffer.alloc(block-1)},{bytes:Buffer.alloc(block+1)},{sha256:'0'.repeat(64)}])await assert.rejects(f.r.accept({index:0,offset:0,bytes:f.b,sha256:sha(f.b),...over}),/invalid_chunk/);assert.equal((await f.r.resume()).totalBytes,0);});
test('caller buffer mutation during authorization cannot alter accepted bytes',async t=>{const f=await fixture(t);const b=Buffer.from(f.b);const p=send(f.r,b);b.fill(0);await p;assert.equal((await f.r.finalize()).complete,true);});
test('out-of-order holes cannot finalize',async t=>{const f=await fixture(t,Buffer.alloc(block*2+3,5));await send(f.r,f.b.subarray(block,block*2),1);await assert.rejects(f.r.finalize(),/incomplete/);await send(f.r,f.b.subarray(0,block),0);await send(f.r,f.b.subarray(block*2),2);assert.equal((await f.r.finalize()).complete,true);});
test('receiver reconstruction resumes durable chunks without trusting checkpoint bitmap',async t=>{const f=await fixture(t,Buffer.alloc(block*2,7));await send(f.r,f.b.subarray(0,block));await fs.writeFile(path.join(f.r.dir,'checkpoint.json'),JSON.stringify({complete:true,present:[0,1],path:'../../escape'}));const next=new SyntheticReceiver(f.config);await next.initialize();assert.deepEqual((await next.resume()).present,[0]);await assert.rejects(next.finalize(),/incomplete/);await send(next,f.b.subarray(block),1);assert.equal((await next.finalize()).complete,true);});
test('partial pending file never counts as committed; recovery removes it',async t=>{const f=await fixture(t);await fs.writeFile(f.r.file(0)+'.pending',Buffer.alloc(17));const next=new SyntheticReceiver(f.config);await next.initialize();assert.equal((await next.resume()).totalBytes,0);await assert.rejects(fs.stat(f.r.file(0)+'.pending'),{code:'ENOENT'});await send(next,f.b);});
test('changed disk manifest cannot become authority',async t=>{const f=await fixture(t);await fs.writeFile(path.join(f.r.dir,'manifest.json'),JSON.stringify({...f.m,sha256:'0'.repeat(64)}));await assert.rejects(new SyntheticReceiver(f.config).initialize(),/manifest_changed/);});
test('same-length post-write corruption rejected by trusted whole-file hash',async t=>{const f=await fixture(t);await send(f.r,f.b);await fs.writeFile(f.r.file(0),Buffer.alloc(block,1));await assert.rejects(f.r.finalize(),/integrity_failed/);});
test('truncated stored chunk rejected on resume',async t=>{const f=await fixture(t);await send(f.r,f.b);await fs.truncate(f.r.file(0),block-1);await assert.rejects(f.r.resume(),/invalid_stored_chunk/);});
test('revoked binding blocks upload, resume and finalize',async t=>{const f=await fixture(t);await send(f.r,f.b);f.setActive(false);await assert.rejects(send(f.r,f.b),/not_authorized/);await assert.rejects(f.r.resume(),/not_authorized/);await assert.rejects(f.r.finalize(),/not_authorized/);});
test('binding changed during await cannot return acknowledgement',async t=>{const f=await fixture(t);let checks=0;const r=new SyntheticReceiver({...f.config,authorize:async()=>++checks<3});await assert.rejects(send(r,f.b),/not_authorized/);});
test('expiry at exact deadline is denied; local safety deletion still allowed',async t=>{const f=await fixture(t);f.setTime(2000);await assert.rejects(send(f.r,f.b),/expired/);assert.equal((await f.r.erase()).deleted,true);});
test('durable tombstone prevents resurrection even with stale manifest',async t=>{const f=await fixture(t);await send(f.r,f.b);assert.deepEqual(await f.r.erase(),{deleted:true,physicalErasure:false});await assert.rejects(fs.stat(f.r.dir),{code:'ENOENT'});await assert.rejects(new SyntheticReceiver(f.config).initialize(),/deleted/);await assert.rejects(f.r.resume(),/deleted/);});
test('pre-existing tombstone fails closed even when chunk cleanup was interrupted',async t=>{const f=await fixture(t);await send(f.r,f.b);await fs.writeFile(f.r.tomb,'');await assert.rejects(f.r.finalize(),/deleted/);await f.r.erase();await assert.rejects(fs.stat(f.r.dir),{code:'ENOENT'});});
test('bounded queue denies a third outstanding chunk; serialized duplicates succeed',async t=>{const f=await fixture(t);const a=send(f.r,f.b),b=send(f.r,f.b),c=send(f.r,f.b);await assert.rejects(c,/backpressure/);const result=await Promise.all([a,b]);assert.equal(result[1].repeated,true);});
test('Linux private fixture and transfer files have owner-only modes', {skip:process.platform==='win32'},async t=>{const f=await fixture(t);await send(f.r,f.b);for(const p of [f.root,f.r.dir,path.join(f.r.dir,'manifest.json'),f.r.file(0)])assert.equal((await fs.stat(p)).mode&0o077,0);});
test('Linux symlink chunk cannot access an external fixture', {skip:process.platform==='win32'},async t=>{const f=await fixture(t);const other=path.join(f.root,'other.bin');await fs.writeFile(other,f.b);await fs.symlink(other,f.r.file(0));await assert.rejects(f.r.resume(),{code:'ELOOP'});});
test('64 MiB actual ciphertext fixture: 256 KiB chunks, interrupted resume and final integrity',async t=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'synthetic-large-cipher-'));await fs.chmod(root,0o700);
  t.after(async()=>{await fs.rm(root,{recursive:true,force:true});await assert.rejects(fs.stat(root),{code:'ENOENT'});});
  const total=64*1024*1024,chunk=256*1024,source=path.join(root,'ciphertext.bin');
  // Standard Node AES-256-CTR is used only to generate a complete-file test fixture.
  // No custom chunk encryption, no Matrix SDK encryption/integration, no key/IV persistence or logging.
  const key=randomBytes(32),iv=randomBytes(16),cipher=createCipheriv('aes-256-ctr',key,iv),digest=createHash('sha256');
  const out=await fs.open(source,'wx',0o600);try{for(let n=0;n<total;n+=chunk){const plain=Buffer.alloc(chunk,n/chunk%251),encrypted=cipher.update(plain);digest.update(encrypted);await out.writeFile(encrypted);plain.fill(0);}const last=cipher.final();digest.update(last);await out.writeFile(last);await out.sync();}finally{await out.close();key.fill(0);iv.fill(0);}
  const m={version:1,transferId:'c'.repeat(32),bindingId:'d'.repeat(64),totalBytes:total,chunkBytes:chunk,sha256:digest.digest('hex'),expiresAt:2000};
  const config={root,manifest:m,authorize:async b=>b===m.bindingId,clock:()=>1000};let r=new SyntheticReceiver(config);await r.initialize();
  const h=await fs.open(source,'r');try{for(let i=0;i<total/chunk;i++){const b=Buffer.alloc(chunk);const {bytesRead}=await h.read(b,0,chunk,i*chunk);assert.equal(bytesRead,chunk);await send(r,b,i);if(i===31){r=new SyntheticReceiver(config);await r.initialize();assert.equal((await r.resume()).totalBytes,32*chunk);}}}finally{await h.close();}
  const result=await r.finalize();assert.equal(result.totalBytes,total);assert.equal(r.maxPayloadBytes,chunk);
  // This bounds a processed payload, not RSS/GC, concurrency, browser heap or product size limit.
});
