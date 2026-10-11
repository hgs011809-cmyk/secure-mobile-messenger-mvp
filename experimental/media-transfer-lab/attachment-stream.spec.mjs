// Public-safe assertions: never print keys, descriptors, bytes, hashes or raw errors.
// 32 top-level tests; 12 POSIX spool cases skip Windows (mode bits != ACL proof).
// Synthetic trusted private roots; trusted ancestors and physical owner assumption.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createHash,timingSafeEqual} from 'node:crypto';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {encryptStream,decryptVerifiedStream,validateDescriptor,AttachmentStreamError} from './attachment-stream.mjs';
const allow=async()=>true;
const posix={skip:process.platform==='win32'};
const eq=(a,b)=>assert.ok(Buffer.from(a).equals(Buffer.from(b)),'byte comparison');
const rejected=(promise,code)=>assert.rejects(promise,e=>e instanceof AttachmentStreamError&&e.code===code&&e.message===code);
async function* segments(bytes,sizes=[1,15,16,17]) {
  let p=0,i=0;
  while(p<bytes.length) {const n=Math.min(sizes[i++%sizes.length],bytes.length-p);yield bytes.subarray(p,p+n);p+=n;}
}
async function encrypted(bytes=Buffer.alloc(97,0x35),sizes) {
  const chunks=[];
  const result=await encryptStream({source:segments(bytes,sizes),writeCiphertext:async b=>{chunks.push(Buffer.from(b));},authorize:allow});
  return {...result,ciphertext:Buffer.concat(chunks),plain:bytes};
}
async function rootFixture(fn) {
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'attachment-spec-'));
  try {await fs.chmod(root,0o700);return await fn(root);}
  finally {
    await fs.rm(root,{recursive:true,force:false});
    await assert.rejects(fs.lstat(root),e=>e.code==='ENOENT');
  }
}
const clone=d=>JSON.parse(JSON.stringify(d));
const b64=b=>Buffer.from(b).toString('base64').replace(/=+$/,'');
async function dec(f,root,overrides={}) {
  const output=[];
  const result=await decryptVerifiedStream({source:segments(f.ciphertext),descriptor:f.descriptor,tempRoot:root,authorize:allow,writePlaintext:async b=>{output.push(Buffer.from(b));},...overrides});
  return {...result,output:Buffer.concat(output)};
}
async function emptyRoot(root) {assert.ok((await fs.readdir(root)).length===0,'namespace removed');}

test('01 fresh canonical key and nonce each call',async()=>{
  const a=await encrypted(),b=await encrypted();
  assert.ok(a.descriptor.key.k!==b.descriptor.key.k&&a.descriptor.iv!==b.descriptor.iv,'fresh material');
  assert.ok(Buffer.from(a.descriptor.key.k,'base64url').length===32);
  assert.ok(Buffer.from(a.descriptor.iv,'base64').subarray(8).every(x=>x===0));
});
test('02 independent WebCrypto CTR64 decrypts generated ciphertext',async()=>{
  const f=await encrypted();
  const key=await webcrypto.subtle.importKey('jwk',f.descriptor.key,{name:'AES-CTR'},false,['decrypt']);
  const plain=await webcrypto.subtle.decrypt({name:'AES-CTR',counter:Buffer.from(f.descriptor.iv,'base64'),length:64},key,f.ciphertext);
  eq(new Uint8Array(plain),f.plain);
  eq(createHash('sha256').update(f.ciphertext).digest(),Buffer.from(f.descriptor.hashes.sha256,'base64'));
});
test('03 independent WebCrypto CTR64 encrypts for spool decrypt',posix,async()=>rootFixture(async root=>{
  const f=await encrypted();
  const key=await webcrypto.subtle.importKey('jwk',f.descriptor.key,{name:'AES-CTR'},false,['encrypt']);
  const ciphertext=Buffer.from(await webcrypto.subtle.encrypt({name:'AES-CTR',counter:Buffer.from(f.descriptor.iv,'base64'),length:64},key,f.plain));
  eq(ciphertext,f.ciphertext);
  const d=clone(f.descriptor);d.hashes.sha256=b64(createHash('sha256').update(ciphertext).digest());
  eq((await dec({...f,ciphertext,descriptor:d},root)).output,f.plain);await emptyRoot(root);
}));
test('04 arbitrary 1/15/16/17 boundaries differ across streams',posix,async()=>rootFixture(async root=>{
  const f=await encrypted(Buffer.alloc(4097,0x27),[17,1,16,15]);
  const out=await dec(f,root,{source:segments(f.ciphertext,[15,17,1,16])});
  eq(out.output,f.plain);assert.ok(out.bytes===4097&&out.maxPayload<=17);await emptyRoot(root);
}));
test('05 zero length file no plaintext callbacks',posix,async()=>rootFixture(async root=>{
  const f=await encrypted(Buffer.alloc(0));let calls=0;
  const out=await dec(f,root,{writePlaintext:async()=>{calls++;}});
  assert.ok(out.bytes===0&&out.maxPayload===0&&calls===0);await emptyRoot(root);
}));
test('06 sixteen MiB generated stream, disk ciphertext, complete digest',posix,async()=>rootFixture(async root=>{
  const total=16*1024*1024,chunk=64*1024,file=path.join(root,'fixture-ciphertext');
  const handle=await fs.open(file,'wx+',0o600);
  try {
    const expected=createHash('sha256');let offset=0,peak=0;
    async function* generate() {
      for(let p=0;p<total;p+=chunk) {
        const b=Buffer.alloc(chunk);for(let i=0;i<b.length;i++) b[i]=((p+i)*13+7)&255;
        expected.update(b);yield b;
      }
    }
    const enc=await encryptStream({source:generate(),authorize:allow,chunkBytes:chunk,writeCiphertext:async b=>{
      peak=Math.max(peak,b.length);let n=0;
      while(n<b.length) {const r=await handle.write(b,n,b.length-n,offset+n);assert.ok(r.bytesWritten>0);n+=r.bytesWritten;}offset+=b.length;
    }});
    async function* diskSource() {
      for(let p=0;p<total;p+=chunk) {
        const b=Buffer.alloc(chunk);let n=0;
        while(n<chunk) {const r=await handle.read(b,n,chunk-n,p+n);assert.ok(r.bytesRead>0);n+=r.bytesRead;}yield b;
      }
    }
    const actual=createHash('sha256');let released=0;
    const out=await decryptVerifiedStream({source:diskSource(),descriptor:enc.descriptor,tempRoot:root,authorize:allow,chunkBytes:chunk,writePlaintext:async b=>{actual.update(b);released+=b.length;}});
    assert.ok(timingSafeEqual(expected.digest(),actual.digest()),'complete digest matches');
    assert.ok(released===total&&out.bytes===total&&enc.bytes===total&&peak<=chunk&&out.maxPayload<=chunk);
    assert.ok((await fs.readdir(root)).length===1,'only fixture remains');
  } finally {await handle.close();}
}));
test('07 descriptor copied deeply and frozen',async()=>{
  const f=await encrypted(),d=clone(f.descriptor),copy=validateDescriptor(d);
  d.key.k='invalid';d.key.key_ops[0]='invalid';d.hashes.sha256='invalid';
  assert.ok(copy.key.k===f.descriptor.key.k&&Object.isFrozen(copy)&&Object.isFrozen(copy.key)&&Object.isFrozen(copy.key.key_ops)&&Object.isFrozen(copy.hashes));
});
test('08 malformed and noncanonical keys reject',async()=>{
  const f=await encrypted();
  for(const k of ['','!',f.descriptor.key.k+'=',b64(Buffer.alloc(31)),b64(Buffer.alloc(33)), 'A'.repeat(42)+'B']) {
    const d=clone(f.descriptor);d.key.k=k;assert.throws(()=>validateDescriptor(d),e=>e.code==='INVALID_DESCRIPTOR');
  }
});
test('09 malformed IV encodings lengths counter reject',async()=>{
  const f=await encrypted();const counter=Buffer.alloc(16);counter[15]=1;
  for(const iv of ['',f.descriptor.iv+'=',b64(Buffer.alloc(15)),b64(counter),'A'.repeat(21)+'B','_'.repeat(22)]) {
    const d=clone(f.descriptor);d.iv=iv;assert.throws(()=>validateDescriptor(d),e=>e.code==='INVALID_DESCRIPTOR');
  }
});
test('10 malformed hash encodings lengths reject',async()=>{
  const f=await encrypted();
  for(const h of ['',f.descriptor.hashes.sha256+'=',b64(Buffer.alloc(31)),'A'.repeat(42)+'B','_'.repeat(43)]) {
    const d=clone(f.descriptor);d.hashes.sha256=h;assert.throws(()=>validateDescriptor(d),e=>e.code==='INVALID_DESCRIPTOR');
  }
});
test('11 version algorithms flags operations and unknown fields reject',async()=>{
  const f=await encrypted();
  const edits=[d=>d.v='v1',d=>d.key.alg='A256GCM',d=>d.key.kty='RSA',d=>d.key.ext=false,d=>d.key.key_ops=['encrypt','encrypt'],d=>d.key.key_ops.push('sign'),d=>d.url='excluded',d=>d.key.extra=1,d=>d.hashes.extra=1,d=>delete d.iv,d=>d[Symbol('extra')]=1];
  for(const edit of edits) {const d=clone(f.descriptor);edit(d);assert.throws(()=>validateDescriptor(d),e=>e.code==='INVALID_DESCRIPTOR');}
});
test('12 accessors inherited fields and proxies rejected without traps',async()=>{
  const f=await encrypted();let touched=0;
  const accessor=clone(f.descriptor);Object.defineProperty(accessor,'iv',{get(){touched++;return '';}});
  const nested=clone(f.descriptor);Object.defineProperty(nested.key,'k',{get(){touched++;return '';}});
  const ops=clone(f.descriptor);Object.defineProperty(ops.key.key_ops,'0',{get(){touched++;return 'encrypt';}});
  const proxy=new Proxy(f.descriptor,{ownKeys(){touched++;throw new Error('private');}});
  const nestedProxy=clone(f.descriptor);nestedProxy.key=new Proxy(nestedProxy.key,{});
  const inherited=Object.create(f.descriptor);
  for(const d of [accessor,nested,ops,proxy,nestedProxy,inherited]) assert.throws(()=>validateDescriptor(d),e=>e.code==='INVALID_DESCRIPTOR');
  assert.ok(touched===0,'no accessor or proxy trap execution');
});
test('13 complete ciphertext corruption rejects before output',posix,async()=>rootFixture(async root=>{
  const f=await encrypted(),bad=Buffer.from(f.ciphertext);bad[bad.length-1]^=1;let calls=0;
  await rejected(dec(f,root,{source:segments(bad),writePlaintext:async()=>{calls++;}}),'HASH_MISMATCH');
  assert.ok(calls===0);await emptyRoot(root);
}));
test('14 trusted hash mismatch rejects before output',posix,async()=>rootFixture(async root=>{
  const f=await encrypted(),d=clone(f.descriptor);d.hashes.sha256=b64(Buffer.alloc(32));let calls=0;
  await rejected(dec(f,root,{descriptor:d,writePlaintext:async()=>{calls++;}}),'HASH_MISMATCH');assert.ok(calls===0);await emptyRoot(root);
}));
test('15 cache mutation at verify/decrypt boundary blocks release',posix,async()=>rootFixture(async root=>{
  const f=await encrypted();let done=false,gates=0,mutated=false,calls=0;
  async function* source(){yield f.ciphertext;done=true;}
  await rejected(dec(f,root,{source:source(),writePlaintext:async()=>{calls++;},authorize:async()=>{
    if(done&&++gates===6) {
      const names=await fs.readdir(root);const filename=path.join(root,names[0],'ciphertext');
      const fd=await fs.open(filename,'r+');try {await fd.write(Buffer.from([f.ciphertext[0]^1]),0,1,0);}finally{await fd.close();}mutated=true;
    }return true;
  }}),'CACHE_TAMPERED');
  assert.ok(mutated&&calls===0);await emptyRoot(root);
}));
test('16 same fd survives pathname substitution',posix,async()=>rootFixture(async root=>{
  const f=await encrypted();let done=false,gates=0,changed=false;
  async function* source(){yield f.ciphertext;done=true;}
  const out=await dec(f,root,{source:source(),authorize:async()=>{
    if(done&&++gates===6) {
      const names=await fs.readdir(root),filename=path.join(root,names[0],'ciphertext');
      await fs.rename(filename,filename+'.old');await fs.writeFile(filename,Buffer.alloc(f.ciphertext.length),{mode:0o600,flag:'wx'});changed=true;
    }return true;
  }});
  assert.ok(changed);eq(out.output,f.plain);await emptyRoot(root);
}));
test('17 encryption backpressure strictly serialized',async()=>{
  let active=0,peak=0,calls=0,next=0;
  async function* source(){for(let i=0;i<5;i++){assert.ok(active===0);next++;yield Buffer.alloc(17);}}
  await encryptStream({source:source(),authorize:allow,writeCiphertext:async()=>{
    active++;peak=Math.max(peak,active);const seen=next;
    await new Promise(resolve=>setImmediate(resolve));assert.ok(next===seen);active--;calls++;
  }});assert.ok(peak===1&&calls===5);
});
test('18 oversized byte chunk and segment limits',async()=>{
  const base={authorize:allow,writeCiphertext:async()=>{}};
  await rejected(encryptStream({...base,source:segments(Buffer.alloc(18),[18]),chunkBytes:17}),'CHUNK_LIMIT');
  await rejected(encryptStream({...base,source:segments(Buffer.alloc(18),[9]),maxBytes:17}),'BYTE_LIMIT');
  async function* tiny(){for(let i=0;i<4097;i++)yield Buffer.alloc(0);}
  await rejected(encryptStream({...base,source:tiny()}),'SEGMENT_LIMIT');
});
test('19 invalid options chunks and counterfeit AbortSignal',async()=>{
  const base={source:segments(Buffer.alloc(1)),writeCiphertext:async()=>{},authorize:allow};
  for(const change of [{authorize:undefined},{maxBytes:64*1024*1024+1},{chunkBytes:256*1024+1},{chunkBytes:0},{maxBytes:-1},{signal:{aborted:false}}]) await rejected(encryptStream({...base,...change}),'INVALID_OPTIONS');
  async function* invalid(){yield 'private';}
  await rejected(encryptStream({...base,source:invalid()}),'INVALID_CHUNK');
});
test('20 abort while source awaits prevents later ciphertext',async()=>{
  const c=new AbortController();let calls=0;
  async function* source(){await new Promise(resolve=>setImmediate(()=>{c.abort();resolve();}));yield Buffer.alloc(1);}
  await rejected(encryptStream({source:source(),signal:c.signal,authorize:allow,writeCiphertext:async()=>{calls++;}}),'ABORTED');assert.ok(calls===0);
});
test('21 authorization expires while source awaits',async()=>{
  let valid=true,calls=0;
  async function* source(){await new Promise(resolve=>setImmediate(()=>{valid=false;resolve();}));yield Buffer.alloc(1);}
  await rejected(encryptStream({source:source(),authorize:async()=>valid,writeCiphertext:async()=>{calls++;}}),'AUTHORIZATION_DENIED');assert.ok(calls===0);
});
test('22 abort during authorizer await prevents source or sink',async()=>{
  const c=new AbortController();let sourceCalls=0,sinkCalls=0;
  async function* source(){sourceCalls++;yield Buffer.alloc(1);}
  await rejected(encryptStream({source:source(),signal:c.signal,authorize:async()=>{await new Promise(resolve=>setImmediate(()=>{c.abort();resolve();}));return true;},writeCiphertext:async()=>{sinkCalls++;}}),'ABORTED');assert.ok(sourceCalls===0&&sinkCalls===0);
});
test('23 revocation immediately before descriptor publication',async()=>{
  let done=false,gates=0;
  async function* source(){yield Buffer.alloc(1);done=true;}
  await rejected(encryptStream({source:source(),authorize:async()=>!done||++gates<2,writeCiphertext:async()=>{}}),'AUTHORIZATION_DENIED');
});
test('24 abort/revoke after awaited encryption sink stops release',async()=>{
  for(const mode of ['abort','revoke']) {
    const c=new AbortController();let valid=true,calls=0;
    await rejected(encryptStream({source:segments(Buffer.alloc(3),[1]),signal:c.signal,authorize:async()=>valid,writeCiphertext:async()=>{
      calls++;await new Promise(resolve=>setImmediate(()=>{if(mode==='abort')c.abort();else valid=false;resolve();}));
    }}),mode==='abort'?'ABORTED':'AUTHORIZATION_DENIED');assert.ok(calls===1);
  }
});
test('25 source and sink exceptions sanitized',async()=>{
  async function* source(){throw new Error('private source body');}
  await rejected(encryptStream({source:source(),authorize:allow,writeCiphertext:async()=>{}}),'SOURCE_FAILED');
  await rejected(encryptStream({source:segments(Buffer.alloc(1)),authorize:allow,writeCiphertext:async()=>{throw new Error('private sink body');}}),'SINK_FAILED');
});
test('26 decrypt sink errors or revocation clean namespace',posix,async()=>rootFixture(async root=>{
  const f=await encrypted();
  await rejected(dec(f,root,{writePlaintext:async()=>{throw new Error('private');}}),'SINK_FAILED');await emptyRoot(root);
  let valid=true,calls=0;
  await rejected(dec(f,root,{authorize:async()=>valid,writePlaintext:async()=>{calls++;await new Promise(resolve=>setImmediate(()=>{valid=false;resolve();}));}}),'AUTHORIZATION_DENIED');
  assert.ok(calls===1);await emptyRoot(root);
  const c=new AbortController();calls=0;
  await rejected(dec(f,root,{signal:c.signal,writePlaintext:async()=>{calls++;await new Promise(resolve=>setImmediate(()=>{c.abort();resolve();}));}}),'ABORTED');
  assert.ok(calls===1);await emptyRoot(root);
}));
test('27 temp root security and ciphertext-only namespace',posix,async()=>rootFixture(async root=>{
  const f=await encrypted();await fs.chmod(root,0o755);
  await rejected(dec(f,root),'INVALID_TEMP_ROOT');await fs.chmod(root,0o700);
  const alias=path.join(root,'alias');await fs.symlink(root,alias);
  await rejected(dec(f,alias),'INVALID_TEMP_ROOT');await fs.unlink(alias);
  let inspected=false,done=false;
  async function* source(){yield f.ciphertext;done=true;}
  await dec(f,root,{source:source(),authorize:async()=>{
    if(done&&!inspected) {
      const names=await fs.readdir(root),ns=path.join(root,names[0]),filename=path.join(ns,'ciphertext');
      assert.ok(names.length===1&&((await fs.stat(ns)).mode&0o7777)===0o700&&((await fs.stat(filename)).mode&0o7777)===0o600);
      eq(await fs.readFile(filename),f.ciphertext);inspected=true;
    }return true;
  }});assert.ok(inspected);await emptyRoot(root);
}));
test('28 cleanup failure surfaced, not successful deletion claim',posix,async()=>rootFixture(async root=>{
  const f=await encrypted();let moved=false;
  await rejected(dec(f,root,{writePlaintext:async()=>{
    if(!moved){const names=await fs.readdir(root);await fs.rename(path.join(root,names[0]),path.join(root,'displaced'));moved=true;}
  }}),'CLEANUP_FAILED');
  assert.ok(moved&&(await fs.readdir(root)).includes('displaced'),'fixture attack residue explicit');
}));

test('29 generator finally executes on chunk byte auth and sink failure',async()=>{
  for(const mode of ['chunk','byte','auth','sink']) {
    let finalized=false,valid=true;
    async function* source() {
      try {
        yield Buffer.alloc(mode==='chunk'?2:1);
        if(mode==='auth') valid=false;
        yield Buffer.alloc(1);
      } finally {finalized=true;}
    }
    const options={source:source(),authorize:async()=>valid,writeCiphertext:async()=>{
      if(mode==='sink') throw new Error('private');
    }};
    if(mode==='chunk') options.chunkBytes=1;
    if(mode==='byte') options.maxBytes=1;
    const code={chunk:'CHUNK_LIMIT',byte:'BYTE_LIMIT',auth:'AUTHORIZATION_DENIED',sink:'SINK_FAILED'}[mode];
    await rejected(encryptStream(options),code);assert.ok(finalized,'source teardown occurred');
  }
});
test('30 throwing iterator return surfaces safe cleanup error',async()=>{
  let returned=false;
  const source={
    [Symbol.asyncIterator](){return this;},
    async next(){return {done:false,value:Buffer.alloc(2)};},
    async return(){returned=true;throw new Error('private source cleanup');}
  };
  await rejected(encryptStream({source,chunkBytes:1,authorize:allow,writeCiphertext:async()=>{}}),'SOURCE_CLEANUP_FAILED');
  assert.ok(returned,'return attempted');
});
test('31 reversed key operation set accepted and copied canonically',async()=>{
  const f=await encrypted(),d=clone(f.descriptor);d.key.key_ops.reverse();
  const accepted=validateDescriptor(d);
  assert.ok(accepted.key.key_ops[0]==='encrypt'&&accepted.key.key_ops[1]==='decrypt');
  assert.ok(accepted.key.k===f.descriptor.key.k&&accepted!==d,'fresh canonical copy');
});
test('32 special-bit temp root rejected',posix,async()=>rootFixture(async root=>{
  const f=await encrypted();
  await fs.chmod(root,0o1700);
  try {await rejected(dec(f,root),'INVALID_TEMP_ROOT');await emptyRoot(root);}
  finally {await fs.chmod(root,0o700);}
}));
