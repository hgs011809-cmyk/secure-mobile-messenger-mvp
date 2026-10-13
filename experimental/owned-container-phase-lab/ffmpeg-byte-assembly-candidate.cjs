'use strict';
// PURE candidate: bounded assembly of caller-supplied bytes only. NO fetch,
// filesystem, process, extraction, ZIP parsing, transport cancellation or timer.
// Prior HEAD declaration is a CLAIM, not GET validation, authentication or
// acquisition authority. An independently reviewed acquisition wrapper and
// external temporal/resource admission remain required before real acquisition.
const crypto=require('node:crypto'),util=require('node:util');
const ERROR='INVALID_FFMPEG_BYTE_ASSEMBLY_CANDIDATE';
const LIMITS=Object.freeze({maxCaptureBytes:2302701,maxChunkBytes:262144,maxChunks:4096});
const PUBLIC_URL='https://playwright.download.prss.microsoft.com/dbazure/download/playwright/builds/ffmpeg/1013/ffmpeg-linux.zip';
// Deliberately canonical, exact primitive text, not a permissive JSON parser.
const PRIOR_HEAD_CLAIM=JSON.stringify({kind:'prior_head_claim',url:PUBLIC_URL,status:200,declaredRepresentationLength:2302701,identityRepresentation:true,redirect:null});
const typed=Object.getPrototypeOf(Uint8Array.prototype),lengthGet=Object.getOwnPropertyDescriptor(typed,'length').get,bufferGet=Object.getOwnPropertyDescriptor(typed,'buffer').get;
const setBytes=Uint8Array.prototype.set;
function bad(){throw Error(ERROR);}
function createFFmpegByteAssemblyCandidate(claimText){
 if(typeof claimText!=='string'||claimText!==PRIOR_HEAD_CLAIM)bad();
 let state='open',total=0,chunks=0,storage;
 try{storage=Buffer.alloc(LIMITS.maxCaptureBytes);}catch{bad();}
 function block(){state='blocked';storage=null;bad();}
 function push(chunk){
  if(state!=='open')block();
  try{
   if(util.types.isProxy(chunk)||!util.types.isUint8Array(chunk))block();
   const n=lengthGet.call(chunk),backing=bufferGet.call(chunk);
   if(util.types.isSharedArrayBuffer(backing)||n<1||n>LIMITS.maxChunkBytes||++chunks>LIMITS.maxChunks||n>LIMITS.maxCaptureBytes-total)block();
   // Native typed-array slots and copy, never caller length/valueOf/iterator.
   setBytes.call(storage,chunk,total);total+=n;
  }catch{block();}
 }
 function finish(){
  if(state!=='open'||total!==LIMITS.maxCaptureBytes)block();
  try{
   const snapshotSha256=crypto.createHash('sha256').update(storage).digest('hex'),bytes=Buffer.from(storage);
   state='finished';storage=null;
   // Buffer is explicitly a mutable COPY. Digest describes assembly snapshot,
   // not later caller mutations. Consumers must re-hash before subsequent use.
   return Object.freeze({candidateOnly:true,byteCount:total,chunkCount:chunks,snapshotSha256,bytes,mutableCopyReturned:true,metadataClaimOnly:true,wireResponseValidated:false,acquisitionAuthorityEstablished:false,archiveVerified:false,vendorAuthenticated:false,zipCompatibilityEstablished:false,temporalBoundEstablished:false,transportCancellationEstablished:false,physicalErasureEstablished:false});
  }catch{block();}
 }
 function abandon(){state='abandoned';storage=null;}
 return Object.freeze({push,finish,abandon});
}
module.exports=Object.freeze({createFFmpegByteAssemblyCandidate,PRIOR_HEAD_CLAIM,PUBLIC_URL,LIMITS,ERROR});
