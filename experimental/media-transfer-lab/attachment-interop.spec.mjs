// Eight flat cases, 3 Windows skips. Official1.0.3 unmodified Node source.
// Small fixtures only; this does not establish browser/SDK/room/Android integration.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {encryptStream,decryptVerifiedStream} from './attachment-stream.mjs';
import reference from './reference/matrix-encrypt-attachment-1.0.3/nodejs.js';
const allow=async()=>true;
const same=(a,b)=>assert.ok(Buffer.from(a).equals(Buffer.from(b)),'interop byte equality');
async function* segment(bytes){for(let p=0;p<bytes.length;p+=8192)yield bytes.subarray(p,p+8192);}
async function privateFixture(fn){const root=await fs.mkdtemp(path.join(os.tmpdir(),'attachment-interop-'));try{await fs.chmod(root,0o700);await fn(root);}finally{await fs.rm(root,{recursive:true,force:false});await assert.rejects(fs.lstat(root),e=>e.code==='ENOENT');}}
for(const size of [0,17,65537]){
  test('official reference decrypts streaming encryption size '+size,async()=>{
    const plain=Buffer.alloc(size,0x36),parts=[];
    const result=await encryptStream({source:segment(plain),authorize:allow,writeCiphertext:async b=>parts.push(Buffer.from(b))});
    let decrypted;
    try{decrypted=reference.decryptAttachment(Buffer.concat(parts),result.descriptor);}catch{assert.fail('reference decrypt rejected');}
    same(decrypted,plain);assert.ok(result.bytes===size&&result.maxPayload<=8192);
  });
  test('verified streaming decrypts official encryption size '+size,{skip:process.platform==='win32'},async()=>privateFixture(async root=>{
    const plain=Buffer.alloc(size,0x48);let encrypted;
    try{encrypted=await reference.encryptAttachment(plain);}catch{assert.fail('reference encrypt rejected');}
    const parts=[];
    const result=await decryptVerifiedStream({source:segment(encrypted.data),descriptor:encrypted.info,tempRoot:root,authorize:allow,writePlaintext:async b=>parts.push(Buffer.from(b))});
    same(Buffer.concat(parts),plain);assert.ok(result.bytes===size&&result.maxPayload<=8192);
    assert.ok((await fs.readdir(root)).length===0,'interop namespace removed');
  }));
}
test('official reference rejects corrupted streaming ciphertext before decrypt',async()=>{
  const parts=[];const result=await encryptStream({source:segment(Buffer.alloc(17,0x19)),authorize:allow,writeCiphertext:async b=>parts.push(Buffer.from(b))});
  const bad=Buffer.concat(parts);bad[0]^=1;let refused=false;
  try{reference.decryptAttachment(bad,result.descriptor);}catch{refused=true;}
  assert.ok(refused,'corrupt reference ciphertext refused');
});
test('platform filesystem gate rejects before plaintext release',async()=>{
  const encrypted=await reference.encryptAttachment(Buffer.alloc(1));let calls=0;
  await assert.rejects(decryptVerifiedStream({source:segment(encrypted.data),descriptor:encrypted.info,tempRoot:'relative-root-is-not-trusted',authorize:allow,writePlaintext:async()=>{calls++;}}),error=>error.code===(process.platform==='win32'?'UNSUPPORTED_FILESYSTEM':'INVALID_TEMP_ROOT'));
  assert.ok(calls===0,'filesystem gate released no plaintext');
});
