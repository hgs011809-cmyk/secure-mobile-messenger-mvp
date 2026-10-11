/** Node-only synthetic transport composed with independently obtained receipts.
 * prepareTransportFixture(tempRoot): trusted existing POSIX owner-0700 directory;
 * returns {descriptor, dispose}. Descriptor/key lives only in RAM, for SDK send.
 * attachTransportReceiver(fixture, receipt, authorize): receipt is exactly the
 * receiveDescriptor shape. Its provenance is the caller's responsibility. Every
 * access calls the injected authorize(originalReceipt), requiring strict true.
 * A SHA256 canonical-context bindingId is a LOCAL identifier, NOT an auth MAC.
 * Session: metrics(), completeResumedTransfer(), decrypt({corruptSource=false}),
 * denialProbe({expectedCode,corruptSource=false}), checkPreserved(), cleanup().
 * Metrics contain no descriptors, bytes, paths or per-file hashes. All failures
 * are static codes. One session per fixture, serial trusted owner operation;
 * trusted ancestors/filesystem assumed. No crash recovery or tamper repair claim.
 * Ciphertext retained through success/denial. Decrypt copies to quarantine and
 * verifies full SHA256 before plaintext, with guarded receiver reads per segment.
 * Generated plaintext and keys are never persisted or logged. 256KiB chunks;
 * 64MiB policy; live ciphertext payload <= 8+8+8=24MiB LOGICAL file bytes,
 * excluding small metadata, NOT physical allocation, secure erasure or RSS.
 * cleanup independently removes local namespaces; receiver.erase tombstone is
 * exercised before namespace removal. No remote deletion authority implied.
 */
import * as fs from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {types} from 'node:util';
import {encryptStream,decryptVerifiedStream,validateDescriptor,AttachmentStreamError} from '../media-transfer-lab/attachment-stream.mjs';
import {SyntheticReceiver,validateManifest} from '../media-transfer-lab/receiver.mjs';

const TOTAL=8*1024*1024, CHUNK=256*1024, COUNT=TOTAL/CHUNK, POLICY=64*1024*1024;
const fixtures=new WeakMap();
class PipelineError extends Error {constructor(code){super(code);this.code=code;this.name='TransportPipelineError';}}
const fail=code=>{throw new PipelineError(code);};
const sha=b=>createHash('sha256').update(b).digest('hex');
const requireTrue=(value,code='PIPELINE_FAILED')=>{if(value!==true)fail(code);};
async function safe(fn) {try{return await fn();}catch(e){if(e instanceof PipelineError)throw e;fail('PIPELINE_FAILED');}}
async function privateMode(p,mode,directory=false) {
  const s=await fs.lstat(p);
  requireTrue(!s.isSymbolicLink()&&(directory?s.isDirectory():s.isFile())&&
    (s.mode&0o7777)===mode&&s.uid===process.getuid(),'UNSAFE_FILESYSTEM');
}
async function absent(p) {try{await fs.lstat(p);return false;}catch(e){if(e?.code==='ENOENT')return true;throw e;}}
async function readBounded(p,size=CHUNK) {
  await privateMode(p,0o600);
  const fd=await fs.open(p,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const s=await fd.stat();requireTrue(s.isFile()&&s.size===size&&size<=CHUNK);
    const b=Buffer.alloc(size);let n=0;
    while(n<size){const r=await fd.read(b,n,size-n,n);requireTrue(r.bytesRead>0);n+=r.bytesRead;}
    return b;
  } finally {await fd.close();}
}
async function removeNamespaces(f) {
  let good=true;
  // Attempt each independent namespace even if an earlier removal fails.
  for(const p of [f.sourceRoot,f.receiverRoot,f.decryptRoot,f.root]) {
    try{await fs.rm(p,{recursive:true,force:true});requireTrue(await absent(p));}
    catch{good=false;}
  }
  requireTrue(good,'CLEANUP_FAILED');f.disposed=true;
  return Object.freeze({namespacesRemoved:true,physicalErasure:false});
}
export async function prepareTransportFixture(tempRoot) {
  let f;
  return safe(async()=>{
    try {
      if(process.platform==='win32')fail('UNSUPPORTED_FILESYSTEM');
      requireTrue(typeof tempRoot==='string'&&path.isAbsolute(tempRoot),'INVALID_TEMP_ROOT');
      await privateMode(tempRoot,0o700,true);
      const root=await fs.mkdtemp(path.join(tempRoot,'transport-'));
      f={root,sourceRoot:path.join(root,'source'),receiverRoot:path.join(root,'receiver'),
        decryptRoot:path.join(root,'quarantine'),disposed:false,attached:false};
      await fs.chmod(root,0o700);await privateMode(root,0o700,true);
      for(const p of [f.sourceRoot,f.receiverRoot,f.decryptRoot]) {
        await fs.mkdir(p,{mode:0o700});await fs.chmod(p,0o700);await privateMode(p,0o700,true);
      }
      const expected=createHash('sha256'),hashes=[];let index=0;
      async function* generate() {
        for(let i=0;i<COUNT;i++) {
          const b=Buffer.alloc(CHUNK);
          for(let j=0;j<b.length;j++)b[j]=(i*29+j*13+7)&255;
          expected.update(b);try{yield b;}finally{b.fill(0);}
        }
      }
      const enc=await encryptStream({source:generate(),authorize:async()=>!f.disposed,
        maxBytes:POLICY,chunkBytes:CHUNK,writeCiphertext:async b=>{
          requireTrue(b.length===CHUNK&&index<COUNT);
          const p=path.join(f.sourceRoot,'cipher-'+index++);
          const fd=await fs.open(p,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
          try{await fd.writeFile(b);await fd.sync();}finally{await fd.close();}
          await privateMode(p,0o600);hashes.push(sha(b));
        }});
      requireTrue(enc.bytes===TOTAL&&index===COUNT&&enc.maxPayload<=CHUNK);
      f.descriptor=validateDescriptor(enc.descriptor);f.expected=expected.digest();
      f.sourceHashes=Object.freeze(hashes); // private immutable RAM baseline
      const api=Object.freeze({descriptor:f.descriptor,dispose:()=>safe(()=>removeNamespaces(f))});
      fixtures.set(api,f);return api;
    }catch(e){if(f)await removeNamespaces(f);throw e;}
  });
}
function optionsCopy(options,fields) {
  requireTrue(!!options&&typeof options==='object'&&!types.isProxy(options),'INVALID_OPTIONS');
  const proto=Object.getPrototypeOf(options);
  requireTrue(proto===Object.prototype||proto===null,'INVALID_OPTIONS');
  const out={};
  for(const key of Reflect.ownKeys(options)) {
    requireTrue(fields.includes(key),'INVALID_OPTIONS');
    const d=Object.getOwnPropertyDescriptor(options,key);
    requireTrue(!!d&&Object.hasOwn(d,'value'),'INVALID_OPTIONS');out[key]=d.value;
  }
  return out;
}
function receiptCopy(receipt) {
  try {
    requireTrue(receipt!==null&&typeof receipt==='object'&&!types.isProxy(receipt),'INVALID_RECEIPT');
    const proto=Object.getPrototypeOf(receipt);
    requireTrue(proto===Object.prototype||proto===null,'INVALID_RECEIPT');
    const names=['eventId','roomId','senderUserId','senderDeviceId','descriptor'];
    const keys=Reflect.ownKeys(receipt);
    requireTrue(keys.length===names.length&&names.every(k=>keys.includes(k)),'INVALID_RECEIPT');
    const out={};
    for(const k of names){const d=Object.getOwnPropertyDescriptor(receipt,k);requireTrue(!!d&&Object.hasOwn(d,'value'),'INVALID_RECEIPT');out[k]=d.value;}
    for(const k of names.slice(0,4))requireTrue(typeof out[k]==='string'&&out[k].length>0&&out[k].length<=(k==='senderDeviceId'?255:1024)&&!/[\x00-\x1f\x7f]/.test(out[k]),'INVALID_RECEIPT');
    requireTrue(out.eventId.startsWith('$'),'INVALID_RECEIPT');
    out.descriptor=validateDescriptor(out.descriptor);return Object.freeze(out);
  }catch{fail('INVALID_RECEIPT');}
}
export function attachTransportReceiver(fixture,receipt,authorize) {
  try {
    const f=fixtures.get(fixture);
    requireTrue(!!f&&!f.disposed&&!f.attached&&typeof authorize==='function','INVALID_SESSION');
    const captured=receiptCopy(receipt);
    const descriptorMatches=JSON.stringify(captured.descriptor)===JSON.stringify(f.descriptor);
    requireTrue(descriptorMatches,'DESCRIPTOR_MISMATCH');
    const identity=JSON.stringify(captured);
    // Fixed ordered primitive tuple, domain separated. No secret/key in context.
    const bindingId=sha(JSON.stringify(['transport-local-context-v1',captured.eventId,captured.roomId,captured.senderUserId,captured.senderDeviceId]));
    const manifest=validateManifest({version:1,transferId:randomBytes(16).toString('hex'),bindingId,
      totalBytes:TOTAL,chunkBytes:CHUNK,sha256:Buffer.from(f.descriptor.hashes.sha256,'base64').toString('hex'),expiresAt:Date.now()+8*60*1000});
    let closed=false,complete=false,present=0,restarted=false,lostAckRepeated=false,manifestHash=null;
    const gate=async binding=>{
      if(closed||f.disposed||binding!==bindingId||Date.now()>=manifest.expiresAt)return false;
      try {
        if(JSON.stringify(receiptCopy(receipt))!==identity)return false;
        if(await authorize(receipt)!==true)return false;
        return !closed&&!f.disposed&&Date.now()<manifest.expiresAt&&JSON.stringify(receiptCopy(receipt))===identity;
      }catch{return false;}
    };
    const config={root:f.receiverRoot,manifest,authorize:gate};
    let receiver=new SyntheticReceiver(config);
    const open=()=>requireTrue(!closed&&!f.disposed,'SESSION_CLOSED');
    const metrics=()=>Object.freeze({descriptorMatches,bindingId,bindingKind:'LOCAL_CONTEXT_IDENTIFIER_NOT_AUTH_MAC',
      transferId:manifest.transferId,expiresAt:manifest.expiresAt,bytes:TOTAL,chunkBytes:CHUNK,
      policyBytes:POLICY,logicalPayloadCeiling:3*TOTAL,presentSegments:present,restarted,lostAckRepeated,complete,closed});
    const preserved=async()=>{
      open();
      for(let i=0;i<COUNT;i++)requireTrue(sha(await readBounded(path.join(f.sourceRoot,'cipher-'+i)))===f.sourceHashes[i],'PRESERVATION_FAILED');
      if(manifestHash!==null) {
        const p=path.join(receiver.dir,'manifest.json');const s=await fs.lstat(p);
        requireTrue(sha(await readBounded(p,s.size))===manifestHash,'PRESERVATION_FAILED');
      }
      for(let i=0;i<present;i++)requireTrue(sha(await readBounded(receiver.file(i)))===f.sourceHashes[i],'PRESERVATION_FAILED');
      requireTrue((await fs.readdir(f.decryptRoot)).length===0,'PRESERVATION_FAILED');
      return Object.freeze({sourcePreserved:true,receiverPreserved:true,quarantineEmpty:true});
    };
    const deliver=async i=>{
      const b=await readBounded(path.join(f.sourceRoot,'cipher-'+i));
      requireTrue(sha(b)===f.sourceHashes[i],'PRESERVATION_FAILED');
      return receiver.accept({index:i,offset:i*CHUNK,bytes:b,sha256:f.sourceHashes[i]});
    };
    const completeResumedTransfer=()=>safe(async()=>{
      open();requireTrue(!complete&&present===0,'INVALID_SESSION');
      try {
        await receiver.initialize();await privateMode(receiver.dir,0o700,true);
        const p=path.join(receiver.dir,'manifest.json'),s=await fs.lstat(p);
        manifestHash=sha(await readBounded(p,s.size));
        for(let i=0;i<COUNT/2;i++){const ack=await deliver(i);requireTrue(ack.accepted&&!ack.repeated);present++;}
        await preserved();
        receiver=new SyntheticReceiver(config);await receiver.initialize();await privateMode(receiver.dir,0o700,true);
        const state=await receiver.resume();
        requireTrue(state.totalBytes===TOTAL/2&&state.present.length===COUNT/2&&state.present.every((v,i)=>v===i));restarted=true;
        // Sender deliberately lost the last half-transfer ack; resend same bytes.
        const ack=await deliver(COUNT/2-1);requireTrue(ack.accepted&&ack.repeated);lostAckRepeated=true;
        await preserved();
        for(let i=COUNT/2;i<COUNT;i++){const accepted=await deliver(i);requireTrue(accepted.accepted&&!accepted.repeated);present++;}
        const out=await receiver.finalize();requireTrue(out.complete&&out.totalBytes===TOTAL);complete=true;
        await preserved();return metrics();
      }catch(e){if(e?.message==='not_authorized')fail('AUTHORIZATION_DENIED');throw e;}
    });
    async function runDecrypt(corruptSource,counters) {
      open();requireTrue(typeof corruptSource==='boolean','INVALID_OPTIONS');
      // Initial fresh gate also permits an authorization-denial probe before transfer.
      if(!await gate(bindingId))fail('AUTHORIZATION_DENIED');
      requireTrue(complete,'TRANSFER_INCOMPLETE');
      const digest=createHash('sha256');
      async function* persisted() {
        await receiver.resume();
        for(let i=0;i<COUNT;i++) {
          await receiver.guard();await privateMode(receiver.file(i),0o600);
          const b=await receiver.read(i);await receiver.guard();requireTrue(b.length===CHUNK);
          // Only a streamed COPY changes. Stored source and receiver remain intact.
          const copy=Buffer.from(b);if(corruptSource&&i===1)copy[0]^=1;
          yield copy;
        }
      }
      let result;
      try {
        result=await decryptVerifiedStream({source:persisted(),descriptor:captured.descriptor,
          tempRoot:f.decryptRoot,maxBytes:POLICY,chunkBytes:CHUNK,authorize:()=>gate(bindingId),
          writePlaintext:async b=>{
            requireTrue(b.length<=CHUNK);counters.plaintextCallbacks++;counters.bytes+=b.length;digest.update(b);
          }});
      }catch(e){
        // Only errors from the imported crypto API, not arbitrary injected errors.
        if(e instanceof AttachmentStreamError&&['AUTHORIZATION_DENIED','HASH_MISMATCH'].includes(e.code))fail(e.code);
        fail('DECRYPTION_FAILED');
      }
      requireTrue(result.bytes===TOTAL&&counters.bytes===TOTAL);
      const digestMatches=timingSafeEqual(digest.digest(),f.expected);
      requireTrue(digestMatches,'PLAINTEXT_DIGEST_MISMATCH');await preserved();
      return Object.freeze({bytes:counters.bytes,digestMatches,plaintextCallbacks:counters.plaintextCallbacks});
    }
    const decrypt=(options={})=>safe(()=>{
      const {corruptSource=false}=optionsCopy(options,['corruptSource']);
      return runDecrypt(corruptSource,{bytes:0,plaintextCallbacks:0});
    });
    const denialProbe=(options={})=>safe(async()=>{
      const {expectedCode,corruptSource=false}=optionsCopy(options,['expectedCode','corruptSource']);
      requireTrue(['AUTHORIZATION_DENIED','HASH_MISMATCH'].includes(expectedCode),'INVALID_PROBE');
      const counters={bytes:0,plaintextCallbacks:0};let exact=false;
      try{await runDecrypt(corruptSource,counters);}
      catch(e){exact=e instanceof PipelineError&&e.code===expectedCode;}
      requireTrue(exact&&counters.plaintextCallbacks===0&&counters.bytes===0,'DENIAL_PROBE_FAILED');
      await preserved();return Object.freeze({code:expectedCode,plaintextCallbacks:0,bytes:0});
    });
    const cleanup=()=>safe(async()=>{
      if(closed||f.disposed){closed=true;return removeNamespaces(f);}
      closed=true;let tombstoned=false,good=true;
      try {
        const deletion=await receiver.erase();requireTrue(deletion.deleted&&deletion.physicalErasure===false);
        await privateMode(receiver.tomb,0o600);requireTrue(await absent(receiver.dir));
        // Existing erase API creates the marker. Do not fabricate a grant to
        // probe restoration: a closed session's external gate denies first.
        tombstoned=true;
      }catch{good=false;}
      let removed;
      try{removed=await removeNamespaces(f);}catch{good=false;}
      requireTrue(good,'CLEANUP_FAILED');
      return Object.freeze({...removed,receiverTombstoned:tombstoned});
    });
    f.attached=true;
    return Object.freeze({metrics,completeResumedTransfer,decrypt,denialProbe,checkPreserved:()=>safe(preserved),cleanup});
  }catch(e){if(e instanceof PipelineError)throw e;fail('INVALID_SESSION');}
}
