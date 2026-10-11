// Exactly four flat POSIX SYNTHETIC tests. Real fork/exit only at acknowledged idle.
// No kill-during-write, power-loss, filesystem durability, production authorization,
// network/media/Android/GB/RSS or physical-erasure claim. No module modifications.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {fork} from 'node:child_process';
import {createHash} from 'node:crypto';
import {encryptStream} from './attachment-stream.mjs';
import {validateManifest} from './receiver.mjs';
const CHUNK=256*1024,TOTAL=8*1024*1024,COUNT=32,HALF=16;
const IPC_MS=10000,EXIT_MS=5000;
const OPTIONS={skip:process.platform==='win32'?'requires POSIX owner modes and SIGKILL':false,timeout:180000};
const WORKER=fileURLToPath(new URL('./process-restart-worker.mjs',import.meta.url));
const fixtures=new Set(),children=new Set();
const check=(b,label)=>assert.ok(b===true,label);
const sha=b=>createHash('sha256').update(b).digest('hex');
const safeError=code=>new Error(code);
async function absent(p) {
  try {await fs.lstat(p);return false;} catch(e) {if(e?.code==='ENOENT')return true;throw safeError('ABSENCE_CHECK_FAILED');}
}
async function mode(p,want,dir=false) {
  const s=await fs.lstat(p);
  check(!s.isSymbolicLink()&&(dir?s.isDirectory():s.isFile())&&
    (s.mode&0o7777)===want&&s.uid===process.getuid(),'owner-private fixture');
}
async function directory(p) {await fs.mkdir(p,{mode:0o700});await fs.chmod(p,0o700);await mode(p,0o700,true);}
async function boundedRead(p) {
  await mode(p,0o600);
  const h=await fs.open(p,'r');
  try {
    check((await h.stat()).size===CHUNK,'exact bounded ciphertext file');
    const b=Buffer.alloc(CHUNK);let n=0;
    while(n<CHUNK) {const r=await h.read(b,n,CHUNK-n,n);check(r.bytesRead>0,'complete bounded read');n+=r.bytesRead;}
    return b;
  } finally {await h.close();}
}
function deadline(p,ms,code) {
  let timer;
  return Promise.race([p,new Promise((_,reject)=>{timer=setTimeout(()=>reject(safeError(code)),ms);})])
    .finally(()=>clearTimeout(timer));
}
// Fixed response vocabulary: no arrays, arbitrary strings, exceptions or secret fields.
const RESPONSE=['id','code','pid','accepted','repeated','count','totalBytes','contiguous','complete',
  'hashMatches','plaintextCalls','plaintextBytes','maxPayload','idle'].sort().join(',');
function validResponse(m,id,pid) {
  if(!m||Object.getPrototypeOf(m)!==Object.prototype||Object.keys(m).sort().join(',')!==RESPONSE||
    m.id!==id||m.pid!==pid||!['ok','not_authorized','manifest_changed','WORKER_FAILED'].includes(m.code))return false;
  for(const k of ['accepted','repeated','contiguous','complete','hashMatches','idle'])if(typeof m[k]!=='boolean')return false;
  for(const [k,max] of [['count',COUNT],['totalBytes',TOTAL],['plaintextCalls',COUNT],['plaintextBytes',TOTAL],['maxPayload',CHUNK]])
    if(!Number.isSafeInteger(m[k])||m[k]<0||m[k]>max)return false;
  return m.idle===true;
}
function spawn(f) {
  const cp=fork(WORKER,['--lab-process-root='+f.root],{
    execArgv:[],serialization:'advanced',stdio:['ignore','ignore','ignore','ipc']});
  const c={cp,pid:cp.pid,id:0,pending:null,dead:false,exit:null,failed:false};
  children.add(c);f.children.add(c);
  let resolveExit;
  c.exited=new Promise(resolve=>{resolveExit=resolve;});
  cp.on('error',()=>{c.failed=true;if(c.pending)c.pending.reject(safeError('CHILD_ERROR'));});
  cp.on('exit',(code,signal)=>{
    c.dead=true;c.exit={code,signal};resolveExit(c.exit);
    if(c.pending)c.pending.reject(safeError('CHILD_EXIT_BEFORE_RESPONSE'));
  });
  cp.on('message',m=>{
    const p=c.pending;
    if(!p||!validResponse(m,p.id,c.pid)) {
      c.failed=true;if(p)p.reject(safeError('INVALID_IPC_RESPONSE'));
      if(!c.dead)cp.kill('SIGKILL');return;
    }
    c.pending=null;p.resolve(m);
  });
  check(Number.isSafeInteger(c.pid)&&c.pid>0,'real child PID');return c;
}
const COMMANDS=new Set(['initialize','accept','resume','finish','shutdown']);
async function request(c,command,payload={}) {
  check(COMMANDS.has(command)&&!c.dead&&!c.failed&&!c.pending,'trusted serial bounded IPC');
  const id=++c.id;
  const p=new Promise((resolve,reject)=>{
    c.pending={id,resolve,reject};
    try {c.cp.send({id,command,...payload},error=>{if(error&&c.pending?.id===id)c.pending.reject(safeError('IPC_SEND_FAILED'));});}
    catch {reject(safeError('IPC_SEND_FAILED'));}
  });
  try {return await deadline(p,IPC_MS,'IPC_TIMEOUT');}
  finally {if(c.pending?.id===id)c.pending=null;}
}
async function waitExit(c) {
  const e=await deadline(c.exited,EXIT_MS,'CHILD_EXIT_TIMEOUT');
  check(c.dead,'real exit observed');return e;
}
async function graceful(c) {
  check(!c.dead,'child alive before graceful shutdown');
  const r=await request(c,'shutdown');check(r.code==='ok'&&r.idle,'shutdown acknowledged');
  const e=await waitExit(c);check(e.code===0&&e.signal===null&&!c.failed,'clean actual child exit');
}
async function killIdle(c) {
  // Caller has awaited the half-transfer ACK. No operation or write is in flight.
  check(!c.pending&&!c.dead&&!c.failed,'acknowledged idle kill boundary');
  check(c.cp.kill('SIGKILL'),'SIGKILL delivered');
  const e=await waitExit(c);check(e.code===null&&e.signal==='SIGKILL','real SIGKILL exit observed');
}
async function stopForCleanup(c) {
  if(c.dead)return true;
  try {await graceful(c);return true;} catch {
    try {if(!c.dead)c.cp.kill('SIGKILL');await waitExit(c);return c.dead;} catch {return false;}
  }
}
async function cleanup(f) {
  let good=true;
  // Attempt every child and every independent root even when an earlier step fails.
  for(const c of f.children)if(!await stopForCleanup(c))good=false;
  for(const p of [f.sourceRoot,f.receiverRoot,f.decryptRoot,f.root]) {
    try {await fs.rm(p,{recursive:true,force:true});} catch {good=false;}
    try {if(!await absent(p))good=false;} catch {good=false;}
  }
  if(good)fixtures.delete(f);
  check(good,'all children exited and all fixture roots absent');
}
test.after(async()=>{
  let good=true;
  for(const c of children)if(!await stopForCleanup(c))good=false;
  for(const f of [...fixtures])try {await cleanup(f);} catch {good=false;}
  check(good&&[...children].every(c=>c.dead),'after-all no leaked children or namespaces');
});
async function fixture(run) {
  let f;
  try {
    // CI may provide a private parent namespace; no descriptor/key/ID in argv.
    const base=process.env.PRIVATE_ATTACHMENT_ROOT||os.tmpdir();
    if(process.env.PRIVATE_ATTACHMENT_ROOT)await mode(base,0o700,true);
    const root=await fs.mkdtemp(path.join(base,'process-restart-'));
    f={root,sourceRoot:path.join(root,'source'),receiverRoot:path.join(root,'receiver'),
      decryptRoot:path.join(root,'decrypt'),children:new Set()};fixtures.add(f);
    await fs.chmod(root,0o700);await mode(root,0o700,true);
    for(const p of [f.sourceRoot,f.receiverRoot,f.decryptRoot])await directory(p);
    const expected=createHash('sha256');let index=0;
    async function* generate() {
      for(let i=0;i<COUNT;i++) {
        const b=Buffer.alloc(CHUNK);
        for(let j=0;j<CHUNK;j++)b[j]=(i*29+j*13+7)&255;
        expected.update(b);try {yield b;} finally {b.fill(0);}
      }
    }
    const enc=await encryptStream({source:generate(),maxBytes:TOTAL,chunkBytes:CHUNK,authorize:async()=>true,
      writeCiphertext:async b=>{
        check(b.length===CHUNK,'bounded encrypted source');
        const p=path.join(f.sourceRoot,'cipher-'+index++),h=await fs.open(p,'wx',0o600);
        try {await h.writeFile(b);await h.sync();} finally {await h.close();}
        await mode(p,0o600);
      }});
    check(enc.bytes===TOTAL&&enc.maxPayload<=CHUNK&&index===COUNT,'eight MiB encrypted stream');
    f.descriptor=enc.descriptor;f.expected=expected.digest('hex'); // RAM and trusted IPC only.
    f.manifest=validateManifest({version:1,transferId:'a'.repeat(32),bindingId:'b'.repeat(64),
      totalBytes:TOTAL,chunkBytes:CHUNK,sha256:Buffer.from(enc.descriptor.hashes.sha256,'base64').toString('hex'),expiresAt:2000});
    f.dir=path.join(f.receiverRoot,f.manifest.transferId);
    await run(f);
  } catch {throw safeError('PROCESS_RESTART_CASE_FAILED');}
  finally {if(f)await cleanup(f);}
}
async function initialize(f,c,mockAllowed=true,manifest=f.manifest) {
  return request(c,'initialize',{root:f.receiverRoot,tempRoot:f.decryptRoot,manifest,
    descriptor:f.descriptor,expected:f.expected,mockAllowed});
}
async function started(f,previous=null,mockAllowed=true,manifest=f.manifest) {
  if(previous)check(previous.dead&&previous.exit!==null,'old child dead before restart');
  const c=spawn(f);
  if(previous)check(c.pid!==previous.pid,'fresh PID differs from prior PID');
  const r=await initialize(f,c,mockAllowed,manifest);return {c,r};
}
async function deliver(f,c,i,repeated=false) {
  const r=await request(c,'accept',{index:i,bytes:await boundedRead(path.join(f.sourceRoot,'cipher-'+i))});
  check(r.code==='ok'&&r.accepted&&r.repeated===repeated&&r.idle&&r.maxPayload<=CHUNK,'committed idle ACK');
  await mode(path.join(f.dir,'chunk-'+i+'.bin'),0o600);return r;
}
async function half(f) {
  const {c,r}=await started(f);check(r.code==='ok','initial child initialized');
  for(let i=0;i<HALF;i++)await deliver(f,c,i);
  return c;
}
// Hash every retained file, including exact manifest, and reject unexpected files.
// Hashes and paths remain parent RAM; assertions never include their values.
async function fingerprint(root) {
  const entries=[];
  async function walk(p,relative='') {
    await mode(p,0o700,true);
    for(const name of (await fs.readdir(p)).sort()) {
      const q=path.join(p,name),rel=relative+'/'+name,st=await fs.lstat(q);
      check(!st.isSymbolicLink(),'no fixture symlink');
      if(st.isDirectory())await walk(q,rel);
      else {
        await mode(q,0o600);
        if(name==='manifest.json') {
          check(st.size<=2048,'bounded manifest');entries.push(rel+':'+sha(await fs.readFile(q)));
        } else {
          check(/^cipher-\d+$|^chunk-\d+\.bin$/.test(name),'only retained ciphertext and manifest');
          entries.push(rel+':'+sha(await boundedRead(q)));
        }
      }
    }
  }
  await walk(root);return entries.join('|');
}
async function snapshots(f) {return {source:await fingerprint(f.sourceRoot),receiver:await fingerprint(f.receiverRoot)};}
async function unchanged(f,before) {
  check(await fingerprint(f.sourceRoot)===before.source,'sender source independently unchanged');
  check(await fingerprint(f.receiverRoot)===before.receiver,'receiver manifest and chunks unchanged');
  check((await fs.readdir(f.decryptRoot)).length===0,'no plaintext or decrypt spool retained');
}
async function resumeHalf(c) {
  const r=await request(c,'resume');
  check(r.code==='ok'&&r.count===HALF&&r.totalBytes===HALF*CHUNK&&r.contiguous,'exact sixteen-segment resume');
}
async function finish(f,c,halfSnapshot) {
  await resumeHalf(c);
  await deliver(f,c,HALF-1,true);await unchanged(f,halfSnapshot);
  for(let i=HALF;i<COUNT;i++)await deliver(f,c,i);
  const before=await snapshots(f);
  const fullEntries=new Set(before.receiver.split('|'));
  check(halfSnapshot.receiver.split('|').every(entry=>fullEntries.has(entry)),
    'all prior committed chunks and manifest unchanged while completing');
  const r=await request(c,'finish');
  check(r.code==='ok'&&r.complete&&r.hashMatches&&r.totalBytes===TOTAL&&r.plaintextBytes===TOTAL&&
    r.plaintextCalls===COUNT&&r.maxPayload<=CHUNK,'whole ciphertext hash and expected bounded eight-MiB plaintext');
  await unchanged(f,before);
  check(before.source===halfSnapshot.source,'original source cache preserved through completion');
  await graceful(c);
}
async function denial(f,c,code) {
  const ack=await request(c,'accept',{index:HALF,bytes:await boundedRead(path.join(f.sourceRoot,'cipher-'+HALF))});
  check(ack.code===code&&!ack.accepted&&!ack.repeated&&ack.plaintextCalls===0&&ack.plaintextBytes===0,
    'denied initialization cannot ACK additional ciphertext');
  const r=await request(c,'finish');
  check(r.code===code&&!r.accepted&&!r.complete&&!r.hashMatches&&r.plaintextCalls===0&&
    r.plaintextBytes===0&&r.totalBytes===0,'denied initialization cannot release plaintext or ACK');
}
test('01 clean real child exit, fresh PID, sixteen-segment resume and lost-ACK retry',OPTIONS,async()=>{
  await fixture(async f=>{
    const old=await half(f),before=await snapshots(f);await graceful(old);
    const {c,r}=await started(f,old);check(r.code==='ok','same-manifest restart initialized');
    await unchanged(f,before);await finish(f,c,before);
  });
});
test('02 SIGKILL at acknowledged idle, real signal exit, fresh PID and full bounded decrypt',OPTIONS,async()=>{
  await fixture(async f=>{
    const old=await half(f),before=await snapshots(f);await killIdle(old);
    const {c,r}=await started(f,old);check(r.code==='ok','idle-kill restart initialized');
    await unchanged(f,before);await finish(f,c,before);
  });
});
test('03 fresh injected MOCK authorization false denies initialize, no ACK or plaintext',OPTIONS,async()=>{
  await fixture(async f=>{
    const old=await half(f),before=await snapshots(f);await graceful(old);
    const {c,r}=await started(f,old,false);
    check(r.code==='not_authorized'&&!r.accepted&&r.plaintextCalls===0&&r.plaintextBytes===0,'exact MOCK authorization denial');
    await denial(f,c,'not_authorized');await unchanged(f,before);await graceful(c);
  });
});
test('04 allowed same context with changed bindingId fails manifest_changed, no cache mutation',OPTIONS,async()=>{
  await fixture(async f=>{
    const old=await half(f),before=await snapshots(f);await graceful(old);
    const changed={...f.manifest,bindingId:'c'.repeat(64)};
    const {c,r}=await started(f,old,true,changed);
    check(r.code==='manifest_changed'&&!r.accepted&&r.plaintextCalls===0&&r.plaintextBytes===0,'exact manifest mismatch, not authorization denial');
    await denial(f,c,'manifest_changed');await unchanged(f,before);await graceful(c);
  });
});
