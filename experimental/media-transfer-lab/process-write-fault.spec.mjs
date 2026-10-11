// Six flat Linux process-write boundary tests. Single owner only. No durability/repair claims.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {fork} from 'node:child_process';
import {createHash} from 'node:crypto';
import {encryptStream,decryptVerifiedStream} from './attachment-stream.mjs';
import {validateManifest} from './receiver.mjs';
const CHUNK=256*1024,TOTAL=8*1024*1024,COUNT=32,HALF=16;
const IPC_MS=10000,EXIT_MS=5000;
const OPTIONS={skip:process.platform!=='linux'?'requires Linux /proc, private owner modes and SIGKILL':false,timeout:180000};
const WORKER=fileURLToPath(new URL('./process-write-fault-worker.mjs',import.meta.url));
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
  'hashMatches','plaintextCalls','plaintextBytes','maxPayload','idle','boundaryLength'].sort().join(',');
function validResponse(m,id,pid) {
  if(!m||Object.getPrototypeOf(m)!==Object.prototype||Object.keys(m).sort().join(',')!==RESPONSE||
    m.id!==id||m.pid!==pid||!['ok','not_authorized','manifest_changed','incomplete','integrity_failed','conflicting_retry','boundary','WORKER_FAILED'].includes(m.code))return false;
  for(const k of ['accepted','repeated','contiguous','complete','hashMatches','idle'])if(typeof m[k]!=='boolean')return false;
  for(const [k,max] of [['count',COUNT],['totalBytes',TOTAL],['plaintextCalls',COUNT],['plaintextBytes',TOTAL],['maxPayload',CHUNK],['boundaryLength',CHUNK]])
    if(!Number.isSafeInteger(m[k])||m[k]<0||m[k]>max)return false;
  return m.code==='boundary' ? m.idle===false&&m.boundaryLength>0&&!m.accepted : m.idle===true&&m.boundaryLength===0;
}
async function spawn(f) {
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
  check(Number.isSafeInteger(c.pid)&&c.pid>0,'real child PID');
  const stat=await fs.readFile('/proc/'+c.pid+'/stat','utf8');
  const start=stat.slice(stat.lastIndexOf(')')+2).split(' ')[19];
  c.marker=path.join(f.root,'owned-child-'+c.pid+'.json');
  await fs.writeFile(c.marker,JSON.stringify({pid:c.pid,start,root:f.root}),{flag:'wx',mode:0o600});
  await mode(c.marker,0o600);return c;
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
  check(c.dead,'real exit observed');if(c.marker)await fs.rm(c.marker,{force:true});return e;
}
async function graceful(c) {
  check(!c.dead,'child alive before graceful shutdown');
  const r=await request(c,'shutdown');check(r.code==='ok'&&r.idle,'shutdown acknowledged');
  const e=await waitExit(c);check(e.code===0&&e.signal===null&&!c.failed,'clean actual child exit');
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
  for(const p of [f.sourceRoot,f.receiverRoot,f.decryptRoot,...(good?[f.root]:[])]) {
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
    const root=await fs.mkdtemp(path.join(base,'process-write-fault-'));
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
    f.descriptor=enc.descriptor;f.expected=expected.digest('hex'); // Parent RAM only; never IPC, argv, stdout or files.
    f.manifest=validateManifest({version:1,transferId:'a'.repeat(32),bindingId:'b'.repeat(64),
      totalBytes:TOTAL,chunkBytes:CHUNK,sha256:Buffer.from(enc.descriptor.hashes.sha256,'base64').toString('hex'),expiresAt:2000});
    f.dir=path.join(f.receiverRoot,f.manifest.transferId);
    await run(f);
  } finally {if(f)await cleanup(f);}
}
async function initialize(f,c,mockAllowed=true,manifest=f.manifest,fault='none') {
  return request(c,'initialize',{root:f.receiverRoot,manifest,fault,mockAllowed});
}
async function started(f,previous=null,mockAllowed=true,manifest=f.manifest,fault='none') {
  if(previous)check(previous.dead&&previous.exit!==null,'old child dead before restart');
  const c=await spawn(f);
  if(previous)check(c.pid!==previous.pid,'fresh PID differs from prior PID');
  const r=await initialize(f,c,mockAllowed,manifest,fault);return {c,r};
}
async function deliver(f,c,i,repeated=false) {
  const r=await request(c,'accept',{index:i,bytes:await boundedRead(path.join(f.sourceRoot,'cipher-'+i))});
  check(r.code==='ok'&&r.accepted&&r.repeated===repeated&&r.idle&&r.maxPayload<=CHUNK,'committed idle ACK');
  await mode(path.join(f.dir,'chunk-'+i+'.bin'),0o600);return r;
}
async function half(f) {
  const {c,r}=await started(f,null,true,f.manifest,f.fault);check(r.code==='ok','initial child initialized');
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
        if(/^chunk-16\.bin\.pending$/.test(name)) {
          check(st.size===CHUNK/2||st.size===CHUNK,'exact fault pending length');
          entries.push(rel+':'+sha(await fs.readFile(q)));
        } else if(name==='manifest.json') {
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
  check(r.code==='ok'&&r.complete&&r.hashMatches&&r.totalBytes===TOTAL&&r.plaintextBytes===0&&
    r.plaintextCalls===0&&r.maxPayload<=CHUNK,'whole ciphertext hash and expected bounded eight-MiB plaintext');
  let calls=0,bytes=0;const actual=createHash('sha256');
  async function* source(){for(let i=0;i<COUNT;i++)yield await boundedRead(path.join(f.dir,'chunk-'+i+'.bin'));}
  const dec=await decryptVerifiedStream({source:source(),descriptor:f.descriptor,tempRoot:f.decryptRoot,maxBytes:TOTAL,chunkBytes:CHUNK,
    authorize:async()=>true,writePlaintext:async b=>{check(b.length<=CHUNK,'bounded parent decrypt');calls++;bytes+=b.length;actual.update(b);}});
  check(calls===COUNT&&bytes===TOTAL&&dec.bytes===TOTAL&&actual.digest('hex')===f.expected,'parent-only keys complete plaintext hash');
  await unchanged(f,before);
  check(before.source===halfSnapshot.source,'original source cache preserved through completion');
  await graceful(c);
}
async function denial(f,c,code) {
  const ack=await request(c,'accept',{index:HALF,bytes:await boundedRead(path.join(f.sourceRoot,'cipher-'+HALF))});
  check(ack.code===code&&!ack.accepted&&!ack.repeated&&ack.plaintextCalls===0&&ack.plaintextBytes===0,
    'denied initialization cannot ACK additional ciphertext');
  const resume=await request(c,'resume');check(resume.code===code&&resume.count===0&&resume.totalBytes===0,'exact denied resume');
  const r=await request(c,'finish');
  check(r.code===code&&!r.accepted&&!r.complete&&!r.hashMatches&&r.plaintextCalls===0&&
    r.plaintextBytes===0&&r.totalBytes===0,'denied initialization cannot release plaintext or ACK');
}

async function killedBoundary(f,fault) {
  f.fault=fault;
  const old=await half(f),committed=await snapshots(f);
  const r=await request(old,'accept',{index:HALF,bytes:await boundedRead(path.join(f.sourceRoot,'cipher-'+HALF))});
  const length=fault==='partial'?CHUNK/2:CHUNK,pending=path.join(f.dir,'chunk-16.bin.pending');
  check(r.code==='boundary'&&!r.idle&&!r.accepted&&r.boundaryLength===length,'exact write boundary IPC without ACK');
  await mode(pending,0o600);
  check((await fs.lstat(pending)).size===length,'parent observed exact pending length before kill');
  check(await absent(path.join(f.dir,'chunk-16.bin')),'no rename at boundary');
  const input=await boundedRead(path.join(f.sourceRoot,'cipher-16'));
  check(sha(await fs.readFile(pending))===sha(input.subarray(0,length)),'pending exact ciphertext prefix');
  check(!old.dead&&!old.pending&&old.cp.kill('SIGKILL'),'actual live child kill');
  const e=await waitExit(old);
  check(e.code===null&&e.signal==='SIGKILL','SIGKILL exit before any fresh PID');
  check((await fs.lstat(pending)).size===length,'exact pending length retained after exit');
  const interrupted=await snapshots(f);
  check(interrupted.source===committed.source,'source immutable across write kill');
  const entries=new Set(interrupted.receiver.split('|'));
  check(committed.receiver.split('|').every(v=>entries.has(v)),'committed cache immutable across write kill');
  return {old,committed,interrupted,pending};
}
for(const [offset,fault] of ['partial','full'].entries()) {
  test(String(offset*3+1).padStart(2,'0')+' '+fault+' .pending SIGKILL, fresh PID, reclaim/resume/retry/hash',OPTIONS,async()=>fixture(async f=>{
    const {old,committed,pending}=await killedBoundary(f,fault);
    const {c,r}=await started(f,old);
    check(r.code==='ok','same manifest authorized restart');
    check(await absent(pending),'existing initialize reclaims only uncommitted pending');
    await unchanged(f,committed);
    const incomplete=await request(c,'finish');check(incomplete.code==='incomplete'&&incomplete.plaintextBytes===0,'exact incomplete before retransmit');
    await finish(f,c,committed);
  }));
  test(String(offset*3+2).padStart(2,'0')+' '+fault+' unauthorized restart fail-closed, immutable cache and zero plaintext',OPTIONS,async()=>fixture(async f=>{
    const {old,interrupted}=await killedBoundary(f,fault);
    const {c,r}=await started(f,old,false);
    check(r.code==='not_authorized'&&r.plaintextCalls===0&&r.plaintextBytes===0,'exact not_authorized');
    await denial(f,c,'not_authorized');await unchanged(f,interrupted);
    let calls=0,bytes=0,code='';
    try {await decryptVerifiedStream({source:(async function*(){yield await boundedRead(path.join(f.sourceRoot,'cipher-0'));})(),
      descriptor:f.descriptor,tempRoot:f.decryptRoot,maxBytes:TOTAL,chunkBytes:CHUNK,authorize:async()=>false,
      writePlaintext:async b=>{calls++;bytes+=b.length;}});}catch(e){code=e.code;}
    check(code==='AUTHORIZATION_DENIED'&&calls===0&&bytes===0,'exact parent crypto denial and zero plaintext callbacks');
    await unchanged(f,interrupted);await graceful(c);
  }));
  test(String(offset*3+3).padStart(2,'0')+' '+fault+' changed manifest fail-closed without committed-cache repair',OPTIONS,async()=>fixture(async f=>{
    const {old,committed,pending}=await killedBoundary(f,fault);
    const {c,r}=await started(f,old,true,{...f.manifest,bindingId:'c'.repeat(64)});
    check(r.code==='manifest_changed','exact existing manifest mismatch');
    // Existing setup unlinks pending before checking manifest equality. Do not claim whole cache unchanged.
    check(await absent(pending),'documented pending reclamation precedes manifest_changed');
    await denial(f,c,'manifest_changed');await unchanged(f,committed);await graceful(c);
  }));
}
