/**
 * Bounded synthetic Matrix attachment-v2 crypto subset. No upload/event API.
 * encryptStream({source,writeCiphertext,authorize,signal?,maxBytes?,chunkBytes?})
 * decryptVerifiedStream({source,descriptor,tempRoot,writePlaintext,authorize,
 *                        signal?,maxBytes?,chunkBytes?})
 * source: AsyncIterable<Uint8Array>; sinks: awaited serial callbacks.
 * authorize: mandatory async access gate resolving true; denial throws/returns
 * anything else. This boolean is NOT descriptor authentication. Caller MUST use
 * an independently verified encrypted-room descriptor. AES-CTR+SHA256 is NOT MAC.
 * Returns {bytes,descriptor,maxPayload}; maxPayload is largest sink payload.
 * Defaults/caps: 64MiB, 256KiB segments, 4096 segments including empty segments.
 * Oversized segments rejected, not split. No deterministic key/IV API.
 * Byte bounds are NOT cancellation/deadlines: trusted source/sink/authorizer or
 * source return() may never settle. Abort is checked after awaits, not a promise
 * of prompt cancellation. Early failure awaits source return() unconditionally.
 * Interruption does NOT preserve resumable secret state. Already emitted
 * ciphertext may use separately designed resumable transport. No sink rollback.
 * Decrypt spools ONLY ciphertext; verifies complete on-disk hash then checks
 * private immutable RAM hashes for each read BEFORE releasing that chunk.
 * This prevents release of a changed chunk, not rollback of prior good chunks.
 * Same fd retained. No plaintext or keys written to disk.
 * tempRoot: existing trusted POSIX directory, owner uid, mode exactly0700,
 * no symlink. Ancestors/filesystem trusted. Namespace0700/file0600. Windows
 * fails closed: Node mode bits cannot enforce owner-only Windows ACLs.
 * Privileged/owner physical attacks, root substitution, malicious filesystem,
 * memory compromise excluded. Cleanup despite denial/abort verifies namespace
 * absence and fails on errors. Unlink/absence is NOT physical secure erasure.
 */
import {createCipheriv,createDecipheriv,createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import {types} from 'node:util';
const BYTE_CAP=64*1024*1024, CHUNK_CAP=256*1024, SEGMENT_CAP=4096;
const abortedGetter=Object.getOwnPropertyDescriptor(AbortSignal.prototype,'aborted').get;
export class AttachmentStreamError extends Error {
  constructor(code) { super(code); this.name='AttachmentStreamError'; this.code=code; }
}
const fail=code=>{throw new AttachmentStreamError(code);};
function plain(value,fields) {
  if(!value||typeof value!=='object'||types.isProxy(value)) fail('INVALID_DESCRIPTOR');
  const proto=Object.getPrototypeOf(value);
  if(proto!==Object.prototype&&proto!==null) fail('INVALID_DESCRIPTOR');
  const names=Reflect.ownKeys(value);
  if(names.length!==fields.length||fields.some(k=>!names.includes(k))) fail('INVALID_DESCRIPTOR');
  const copy=Object.create(null);
  for(const k of fields) {
    const d=Object.getOwnPropertyDescriptor(value,k);
    if(!d||!Object.hasOwn(d,'value')) fail('INVALID_DESCRIPTOR');
    copy[k]=d.value;
  }
  return copy;
}
function decode(value,size,url) {
  const pattern=url?/^[A-Za-z0-9_-]+$/:/^[A-Za-z0-9+/]+$/;
  if(typeof value!=='string'||value.length!==Math.ceil(size*8/6)||!pattern.test(value)) fail('INVALID_DESCRIPTOR');
  const bytes=Buffer.from(value,url?'base64url':'base64');
  const encoded=url?bytes.toString('base64url'):bytes.toString('base64').replace(/=+$/,'');
  if(bytes.length!==size||encoded!==value) fail('INVALID_DESCRIPTOR');
  return bytes;
}
/** Exact crypto subset; deep copied and frozen. No proxies/accessors/extra fields. */
export function validateDescriptor(value) {
  try {
    const d=plain(value,['v','key','iv','hashes']);
    const k=plain(d.key,['kty','alg','ext','key_ops','k']);
    const h=plain(d.hashes,['sha256']);
    if(d.v!=='v2'||k.kty!=='oct'||k.alg!=='A256CTR'||k.ext!==true) fail('INVALID_DESCRIPTOR');
    const ops=k.key_ops;
    if(!Array.isArray(ops)||types.isProxy(ops)||Object.getPrototypeOf(ops)!==Array.prototype) fail('INVALID_DESCRIPTOR');
    if(Reflect.ownKeys(ops).length!==3) fail('INVALID_DESCRIPTOR');
    const a=Object.getOwnPropertyDescriptor(ops,'0'), b=Object.getOwnPropertyDescriptor(ops,'1'), l=Object.getOwnPropertyDescriptor(ops,'length');
    if(!a||!b||!l||!Object.hasOwn(a,'value')||!Object.hasOwn(b,'value')||l.value!==2||!((a.value==='encrypt'&&b.value==='decrypt')||(a.value==='decrypt'&&b.value==='encrypt'))) fail('INVALID_DESCRIPTOR');
    decode(k.k,32,true);
    const iv=decode(d.iv,16,false);
    if(iv.subarray(8).some(x=>x!==0)) fail('INVALID_DESCRIPTOR');
    decode(h.sha256,32,false);
    return Object.freeze({v:'v2',key:Object.freeze({kty:'oct',alg:'A256CTR',ext:true,key_ops:Object.freeze(['encrypt','decrypt']),k:k.k}),iv:d.iv,hashes:Object.freeze({sha256:h.sha256})});
  } catch { fail('INVALID_DESCRIPTOR'); }
}
function setup(options,sinkName) {
  if(!options||typeof options!=='object') fail('INVALID_OPTIONS');
  const {source,authorize,signal,maxBytes=BYTE_CAP,chunkBytes=CHUNK_CAP}=options;
  const sink=options[sinkName];
  if(!source||typeof source[Symbol.asyncIterator]!=='function'||typeof sink!=='function'||typeof authorize!=='function') fail('INVALID_OPTIONS');
  if(!Number.isSafeInteger(maxBytes)||maxBytes<0||maxBytes>BYTE_CAP||!Number.isSafeInteger(chunkBytes)||chunkBytes<1||chunkBytes>CHUNK_CAP) fail('INVALID_OPTIONS');
  if(signal!==undefined) {
    try {if(types.isProxy(signal)) fail('INVALID_OPTIONS'); abortedGetter.call(signal);}
    catch {fail('INVALID_OPTIONS');}
  }
  const checkAbort=()=>{if(signal&&abortedGetter.call(signal)) fail('ABORTED');};
  const gate=async()=>{
    checkAbort(); let permitted;
    try {permitted=await authorize();} catch {fail('AUTHORIZATION_DENIED');}
    checkAbort(); if(permitted!==true) fail('AUTHORIZATION_DENIED');
  };
  const io=async(fn,code)=>{
    await gate(); let result;
    try {result=await fn();} catch {fail(code);}
    await gate(); return result;
  };
  return {source,sink,maxBytes,chunkBytes,gate,io};
}
async function consume(ctx,onChunk) {
  let iterator;
  try {iterator=ctx.source[Symbol.asyncIterator]();} catch {fail('SOURCE_FAILED');}
  if(!iterator||typeof iterator.next!=='function') fail('SOURCE_FAILED');
  let bytes=0,segments=0,completed=false;
  try {
    for(;;) {
      const item=await ctx.io(()=>iterator.next(),'SOURCE_FAILED');
      if(!item||typeof item!=='object') fail('SOURCE_FAILED');
      if(item.done) {completed=true;return bytes;}
      if(++segments>SEGMENT_CAP) fail('SEGMENT_LIMIT');
      const input=item.value;
      if(!types.isUint8Array(input)||types.isProxy(input)) fail('INVALID_CHUNK');
      if(input.byteLength>ctx.chunkBytes) fail('CHUNK_LIMIT');
      if(input.byteLength>ctx.maxBytes-bytes) fail('BYTE_LIMIT');
      const chunk=Buffer.from(input); // copy before any subsequent await
      bytes+=chunk.length;
      if(chunk.length) await onChunk(chunk);
    }
  } finally {
    if(!completed) {
      // Resource teardown must run even after authorization/abort denial.
      try {if(typeof iterator.return==='function') await iterator.return();}
      catch {fail('SOURCE_CLEANUP_FAILED');}
    }
  }
}
const b64=b=>b.toString('base64').replace(/=+$/,'');
const digest=b=>createHash('sha256').update(b).digest();
export async function encryptStream(options) {
  let key;
  try {
    const ctx=setup(options,'writeCiphertext'); await ctx.gate();
    key=randomBytes(32);
    const iv=Buffer.concat([randomBytes(8),Buffer.alloc(8)]);
    const cipher=createCipheriv('aes-256-ctr',key,iv), hash=createHash('sha256');
    let maxPayload=0;
    const bytes=await consume(ctx,async chunk=>{
      const output=cipher.update(chunk); hash.update(output);
      maxPayload=Math.max(maxPayload,output.length);
      await ctx.io(()=>ctx.sink(new Uint8Array(output)),'SINK_FAILED');
    });
    if(cipher.final().length!==0) fail('CRYPTO_FAILED');
    const descriptor=validateDescriptor({v:'v2',key:{kty:'oct',alg:'A256CTR',ext:true,key_ops:['encrypt','decrypt'],k:key.toString('base64url')},iv:b64(iv),hashes:{sha256:b64(hash.digest())}});
    await ctx.gate();
    return {bytes,descriptor,maxPayload};
  } catch(e) {if(e instanceof AttachmentStreamError) throw e; fail('ENCRYPTION_FAILED');}
  finally {if(key) key.fill(0);}
}
async function cleanup(fd,directory) {
  let failed=false;
  if(fd) {try {await fd.close();} catch {failed=true;}}
  if(directory) {
    try {await fs.rm(directory,{recursive:true,force:false});} catch {failed=true;}
    try {await fs.lstat(directory); failed=true;}
    catch(e) {if(e?.code!=='ENOENT') failed=true;}
  }
  if(failed) fail('CLEANUP_FAILED');
}
export async function decryptVerifiedStream(options) {
  let fd,directory,key,result,error,ctx;
  try {
    ctx=setup(options,'writePlaintext');
    const descriptor=validateDescriptor(options.descriptor);
    if(process.platform==='win32') fail('UNSUPPORTED_FILESYSTEM');
    const root=options.tempRoot;
    if(typeof root!=='string'||!path.isAbsolute(root)) fail('INVALID_TEMP_ROOT');
    const stat=await ctx.io(()=>fs.lstat(root),'TEMP_IO_FAILED');
    if(!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o7777)!==0o700||stat.uid!==process.getuid()) fail('INVALID_TEMP_ROOT');
    // Assign within IO: post-IO denial must still close/remove created resources.
    await ctx.io(async()=>{directory=await fs.mkdtemp(path.join(root,'attachment-'));},'TEMP_IO_FAILED');
    await ctx.io(()=>fs.chmod(directory,0o700),'TEMP_IO_FAILED');
    await ctx.io(async()=>{fd=await fs.open(path.join(directory,'ciphertext'),'wx+',0o600);},'TEMP_IO_FAILED');
    const ns=await ctx.io(()=>fs.lstat(directory),'TEMP_IO_FAILED'), st=await ctx.io(()=>fd.stat(),'TEMP_IO_FAILED');
    if((ns.mode&0o7777)!==0o700||(st.mode&0o7777)!==0o600||ns.uid!==process.getuid()||st.uid!==process.getuid()) fail('INVALID_TEMP_ROOT');
    const spans=[]; let offset=0;
    const bytes=await consume(ctx,async chunk=>{
      const start=offset; let written=0;
      while(written<chunk.length) {
        const r=await ctx.io(()=>fd.write(chunk,written,chunk.length-written,start+written),'TEMP_IO_FAILED');
        if(r.bytesWritten<=0) fail('TEMP_IO_FAILED'); written+=r.bytesWritten;
      }
      spans.push(Object.freeze({offset:start,length:chunk.length})); offset+=chunk.length;
    });
    const read=async span=>{
      const buffer=Buffer.alloc(span.length); let n=0;
      while(n<buffer.length) {
        const r=await ctx.io(()=>fd.read(buffer,n,buffer.length-n,span.offset+n),'TEMP_IO_FAILED');
        if(r.bytesRead<=0) fail('CACHE_TAMPERED'); n+=r.bytesRead;
      }
      return buffer;
    };
    const size=await ctx.io(()=>fd.stat(),'TEMP_IO_FAILED');
    if(size.size!==bytes) fail('CACHE_TAMPERED');
    const full=createHash('sha256'),verified=[];
    for(const span of spans) {
      const buffer=await read(span); full.update(buffer);
      verified.push(Object.freeze({...span,hash:digest(buffer).toString('hex')}));
    }
    if(!timingSafeEqual(full.digest(),decode(descriptor.hashes.sha256,32,false))) fail('HASH_MISMATCH');
    await ctx.gate(); // verify/decrypt boundary; no production mutation hook
    key=decode(descriptor.key.k,32,true);
    const decipher=createDecipheriv('aes-256-ctr',key,decode(descriptor.iv,16,false));
    let maxPayload=0;
    for(const span of verified) {
      const buffer=await read(span);
      if(!timingSafeEqual(digest(buffer),Buffer.from(span.hash,'hex'))) fail('CACHE_TAMPERED');
      const output=decipher.update(buffer); maxPayload=Math.max(maxPayload,output.length);
      await ctx.io(()=>ctx.sink(new Uint8Array(output)),'SINK_FAILED');
    }
    if(decipher.final().length!==0) fail('CRYPTO_FAILED');
    const end=await ctx.io(()=>fd.stat(),'TEMP_IO_FAILED');
    if(end.size!==bytes) fail('CACHE_TAMPERED');
    await ctx.gate(); result={bytes,descriptor,maxPayload};
  } catch(e) {error=e instanceof AttachmentStreamError?e:new AttachmentStreamError('DECRYPTION_FAILED');}
  finally {
    if(key) key.fill(0);
    try {await cleanup(fd,directory);} catch(e) {error=e;}
  }
  if(error) throw error;
  await ctx.gate(); // cleanup awaited IO may have expired access
  return result;
}
