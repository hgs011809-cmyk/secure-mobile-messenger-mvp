// Six flat Linux synthetic persisted-ciphertext tests. No child processes in this suite.
// Single owner, MOCK authorization, trusted local filesystem. No core changes or repair.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {encryptStream,decryptVerifiedStream} from './attachment-stream.mjs';
import {SyntheticReceiver,validateManifest} from './receiver.mjs';
const CHUNK=262144,TOTAL=8388608,COUNT=32;
const OPTIONS={skip:process.platform!=='linux'?'Linux owner-private filesystem required':false,timeout:30000};
const fixtures=new Set();
const check=(v,label)=>assert.ok(v===true,label);
const sha=b=>createHash('sha256').update(b).digest('hex');
async function absent(p){try{await fs.lstat(p);return false;}catch(e){if(e.code==='ENOENT')return true;throw Error('ABSENCE_CHECK_FAILED');}}
async function mode(p,want,dir=false){const s=await fs.lstat(p);check(!s.isSymbolicLink()&&(dir?s.isDirectory():s.isFile())&&(s.mode&4095)===want&&s.uid===process.getuid(),'owner-private fixture');return s;}
async function directory(p){await fs.mkdir(p,{mode:0o700});await fs.chmod(p,0o700);await mode(p,0o700,true);}
async function cleanup(f){let good=true;for(const p of [f.sourceRoot,f.receiverRoot,f.decryptRoot,f.root]){try{await fs.rm(p,{recursive:true,force:true});if(!await absent(p))good=false;}catch{good=false;}}if(good)fixtures.delete(f);check(good,'independent fixture roots absent');}
test.after(async()=>{let good=true;for(const f of [...fixtures])try{await cleanup(f);}catch{good=false;}check(good&&fixtures.size===0,'all fixture namespaces absent; suite-owned children zero');});
async function fixture(run){
  let f;
  try{
    const base=process.env.PRIVATE_ATTACHMENT_ROOT;
    check(typeof base==='string'&&path.isAbsolute(base),'private namespace required');await mode(base,0o700,true);
    const root=await fs.mkdtemp(path.join(base,'persisted-corruption-'));
    f={root,sourceRoot:path.join(root,'source'),receiverRoot:path.join(root,'receiver'),decryptRoot:path.join(root,'decrypt')};fixtures.add(f);
    await fs.chmod(root,0o700);await mode(root,0o700,true);
    for(const p of [f.sourceRoot,f.receiverRoot,f.decryptRoot])await directory(p);
    const expected=createHash('sha256');let index=0;
    async function* generate(){for(let i=0;i<COUNT;i++){const b=Buffer.alloc(CHUNK);for(let j=0;j<CHUNK;j++)b[j]=(i*29+j*13+7)&255;expected.update(b);try{yield b;}finally{b.fill(0);}}}
    const enc=await encryptStream({source:generate(),maxBytes:TOTAL,chunkBytes:CHUNK,authorize:async()=>true,writeCiphertext:async b=>{
      check(b.length===CHUNK,'bounded ciphertext source');const p=path.join(f.sourceRoot,'cipher-'+index++),h=await fs.open(p,'wx',0o600);try{await h.writeFile(b);await h.sync();}finally{await h.close();}await mode(p,0o600);
    }});
    check(enc.bytes===TOTAL&&index===COUNT&&enc.maxPayload<=CHUNK,'eight MiB bounded fixture');
    f.descriptor=enc.descriptor;f.expected=expected.digest('hex'); // Keys/descriptors/digests in parent RAM only.
    f.manifest=validateManifest({version:1,transferId:'a'.repeat(32),bindingId:'b'.repeat(64),totalBytes:TOTAL,chunkBytes:CHUNK,sha256:Buffer.from(enc.descriptor.hashes.sha256,'base64').toString('hex'),expiresAt:2000});
    f.dir=path.join(f.receiverRoot,f.manifest.transferId);
    const receiver=fresh(f);await receiver.initialize();
    for(let i=0;i<COUNT;i++){const ack=await receiver.accept(await input(f,i));check(ack.accepted&&!ack.repeated&&ack.index===i,'committed original ciphertext');}
    check((await receiver.finalize()).complete,'valid persisted fixture before fault');
    await run(f);
  }finally{if(f)await cleanup(f);}
}
function fresh(f,allowed=true,manifest=f.manifest){return new SyntheticReceiver({root:f.receiverRoot,manifest,authorize:async()=>allowed,clock:()=>1000});}
async function input(f,i){const p=path.join(f.sourceRoot,'cipher-'+i);const s=await mode(p,0o600);check(s.size===CHUNK,'exact source length');const bytes=await fs.readFile(p);return {index:i,offset:i*CHUNK,bytes,sha256:sha(bytes)};}
// Include lengths, modes, owner and bytes of EVERY retained manifest/chunk; no pending files in these cases.
// Snapshot AFTER deliberate corruption. Failure/read/retry must preserve that exact state, not repair it.
async function fingerprint(root){const entries=[];async function walk(p,rel=''){await mode(p,0o700,true);for(const name of (await fs.readdir(p)).sort()){const q=path.join(p,name),s=await fs.lstat(q);check(!s.isSymbolicLink(),'no symlink');if(s.isDirectory()){entries.push(rel+'/'+name+':directory');await walk(q,rel+'/'+name);}else{await mode(q,0o600);check(/^(manifest\.json|cipher-\d+|chunk-\d+\.bin)$/.test(name),'only expected retained files');check(s.size<=(name==='manifest.json'?2048:CHUNK+1),'bounded fingerprint');const h=await fs.open(q,'r'),d=createHash('sha256'),b=Buffer.alloc(CHUNK);try{for(;;){const r=await h.read(b,0,b.length,null);if(!r.bytesRead)break;d.update(b.subarray(0,r.bytesRead));}}finally{await h.close();}entries.push(rel+'/'+name+':'+s.size+':'+s.mode+':'+s.uid+':'+d.digest('hex'));}}}await walk(root);return entries.join('|');}
async function snapshots(f){return {source:await fingerprint(f.sourceRoot),receiver:await fingerprint(f.receiverRoot)};}
async function unchanged(f,before){check(await fingerprint(f.sourceRoot)===before.source,'source independently immutable');check(await fingerprint(f.receiverRoot)===before.receiver,'persisted manifest/cache independently immutable');check((await fs.readdir(f.decryptRoot)).length===0,'decrypt ciphertext spool absent');}
async function exact(run,code){let caught=null;try{await run();}catch(e){caught=e;}check(caught!==null&&(caught.code??caught.message)===code,'exact expected negative code');}
async function* persistedSource(f){for(let i=0;i<COUNT;i++){const p=path.join(f.dir,'chunk-'+i+'.bin');const s=await mode(p,0o600);check(s.size<=CHUNK+1,'bounded deliberately corrupted file');const h=await fs.open(p,'r');try{for(;;){const b=Buffer.alloc(CHUNK),r=await h.read(b,0,CHUNK,null);if(!r.bytesRead)break;yield b.subarray(0,r.bytesRead);}}finally{await h.close();}}}
function instrument(f,allowed=true){const stats={calls:0,bytes:0,max:0},digest=createHash('sha256');return {stats,digest,run:()=>decryptVerifiedStream({source:persistedSource(f),descriptor:f.descriptor,tempRoot:f.decryptRoot,maxBytes:TOTAL+1,chunkBytes:CHUNK,authorize:async()=>allowed,writePlaintext:async b=>{stats.calls++;stats.bytes+=b.length;stats.max=Math.max(stats.max,b.length);digest.update(b);}})};}
async function noPlaintext(f,code,beforeDecrypt=async()=>{},allowed=true){
  const meter=instrument(f,allowed);
  // Actual parent sink is connected to the real decrypt function, not a worker-reported zero.
  await exact(async()=>{await beforeDecrypt();await meter.run();},code);
  check(meter.stats.calls===0&&meter.stats.bytes===0,'actual parent negative sink callbacks and bytes zero');
  check((await fs.readdir(f.decryptRoot)).length===0,'negative decrypt spool cleaned');
}
async function positive(f){const meter=instrument(f);const d=await meter.run();check(d.bytes===TOTAL&&meter.stats.calls===COUNT&&meter.stats.bytes===TOTAL&&meter.stats.max<=CHUNK&&meter.digest.digest('hex')===f.expected,'real parent positive sink validates instrumentation and full plaintext hash');}
async function mutate(f,i,kind){const p=path.join(f.dir,'chunk-'+i+'.bin');await mode(p,0o600);const h=await fs.open(p,'r+');try{if(kind==='truncate')await h.truncate(CHUNK-1);else if(kind==='extend')await h.write(Buffer.from([91]),0,1,CHUNK);else{const b=Buffer.alloc(1);await h.read(b,0,1,17);b[0]^=1;await h.write(b,0,1,17);}await h.sync();}finally{await h.close();}}
for(const [i,kind] of ['truncate','extend'].entries())test('0'+(i+1)+' persisted '+kind+' length rejects resume, retry, finalization and direct decrypt',OPTIONS,async()=>fixture(async f=>{
  await mutate(f,16,kind);const before=await snapshots(f),r=fresh(f);await r.initialize();await unchanged(f,before);
  await exact(()=>r.resume(),'invalid_stored_chunk');await unchanged(f,before);
  await exact(async()=>r.accept(await input(f,16)),'invalid_stored_chunk');await unchanged(f,before);
  await noPlaintext(f,'invalid_stored_chunk',()=>r.finalize());await unchanged(f,before);
  await noPlaintext(f,'HASH_MISMATCH');await unchanged(f,before);
}));
test('03 same-length persisted hash corruption: resume is length-only, finalize and decrypt fail closed',OPTIONS,async()=>fixture(async f=>{
  await mutate(f,16,'flip');const before=await snapshots(f),r=fresh(f);await r.initialize();
  const resumed=await r.resume();check(resumed.present.length===COUNT&&resumed.totalBytes===TOTAL,'existing resume does not validate whole ciphertext hash');await unchanged(f,before);
  await noPlaintext(f,'conflicting_retry',async()=>r.accept(await input(f,16)));await unchanged(f,before);
  await noPlaintext(f,'integrity_failed',()=>r.finalize());await unchanged(f,before);
  await noPlaintext(f,'HASH_MISMATCH');await unchanged(f,before);
}));
test('04 valid-hash conflicting retry cannot replace committed cache; original lost-ACK retry remains valid',OPTIONS,async()=>fixture(async f=>{
  const before=await snapshots(f),r=fresh(f);await r.initialize();const changed=await input(f,16);changed.bytes[17]^=1;changed.sha256=sha(changed.bytes);
  await noPlaintext(f,'conflicting_retry',()=>r.accept(changed));await unchanged(f,before);
  const repeated=await r.accept(await input(f,16));check(repeated.accepted&&repeated.repeated&&repeated.index===16,'original exact lost-ACK retry succeeds');await unchanged(f,before);
  check((await r.finalize()).complete,'original cache remains valid');await positive(f);await unchanged(f,before);
}));
test('05 MOCK authorization denial precedes stored corruption and preserves cache, parent decrypt independently denies',OPTIONS,async()=>fixture(async f=>{
  await mutate(f,16,'flip');const before=await snapshots(f),r=fresh(f,false);
  await noPlaintext(f,'not_authorized',()=>r.initialize());await unchanged(f,before);
  await exact(()=>r.resume(),'not_authorized');await exact(async()=>r.accept(await input(f,16)),'not_authorized');
  await noPlaintext(f,'not_authorized',()=>r.finalize());await unchanged(f,before);
  await noPlaintext(f,'AUTHORIZATION_DENIED',async()=>{},false);await unchanged(f,before);
}));
test('06 changed binding manifest rejects initialization without mutating persisted cache or releasing plaintext',OPTIONS,async()=>fixture(async f=>{
  const before=await snapshots(f),changed={...f.manifest,bindingId:'c'.repeat(64)},r=fresh(f,true,changed);
  // Only initialization is claimed: receiver itself does not latch an initialization denial.
  await noPlaintext(f,'manifest_changed',()=>r.initialize());await unchanged(f,before);
  const valid=fresh(f);await valid.initialize();check((await valid.finalize()).complete,'original manifest still works');await positive(f);await unchanged(f,before);
}));
