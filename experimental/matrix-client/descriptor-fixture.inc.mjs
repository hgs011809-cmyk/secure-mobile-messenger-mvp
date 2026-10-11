import {encryptStream} from '../media-transfer-lab/attachment-stream.mjs';
import {createHash} from 'node:crypto';
// Small generated test bytes only. No key/plaintext/descriptor files or logs.
const fileFixture=await(async()=>{
 const plain=Uint8Array.from({length:4096},(_,i)=>(i*17+11)&255),chunks=[];
 const expectedDigest=createHash('sha256').update(plain).digest('base64').replace(/=+$/,'');
 async function* source(){yield plain;}
 try{
  const encrypted=await encryptStream({source:source(),authorize:async()=>true,maxBytes:4096,chunkBytes:4096,writeCiphertext:async b=>chunks.push(Buffer.from(b))});
  return {descriptor:encrypted.descriptor,ciphertext:Buffer.concat(chunks),expectedDigest};
 }finally{plain.fill(0);}
})();
const descriptorGates=[];
