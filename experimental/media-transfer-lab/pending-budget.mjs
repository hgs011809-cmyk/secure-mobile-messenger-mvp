// Independent synthetic single-owner length accounting. Never wired to receiver.
import * as fs from 'node:fs/promises';import path from 'node:path';import {createHash} from 'node:crypto';
const T=8388608,C=262144;const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=b=>createHash('sha256').update(b).digest('hex');
export class PendingCiphertextBudget {
 constructor(root,limit){if(!path.isAbsolute(root)||!Number.isSafeInteger(limit)||limit<0)fail('INVALID_BUDGET');this.root=root;this.limit=limit;}
 async inventory(){
  const s=await fs.lstat(this.root);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&4095)!==448||s.uid!==process.getuid())fail('UNSAFE_FIXTURE');
  const rows=[];let bytes=0;
  for(const name of (await fs.readdir(this.root)).sort()){
   const m=/^chunk-(\d+)\.bin(\.pending)?$/.exec(name);if(name!=='source.bin'&&(!m||Number(m[1])>=32||String(Number(m[1]))!==m[1]))fail('UNEXPECTED_CIPHERTEXT_FILE');
   const v=await fs.lstat(path.join(this.root,name));if(!v.isFile()||v.isSymbolicLink()||(v.mode&4095)!==384||v.uid!==process.getuid())fail('UNSAFE_FIXTURE');
   const pending=!!m?.[2];if(name==='source.bin'?v.size!==T:pending?(v.size<1||v.size>C):v.size!==C)fail('INVALID_CIPHERTEXT_LENGTH');
   const b=await fs.readFile(path.join(this.root,name));bytes+=v.size;rows.push({name,bytes:v.size,sha256:hash(b)});
  }
  if(!rows.some(r=>r.name==='source.bin'))fail('SOURCE_MISSING');if(bytes>this.limit)fail('LOGICAL_BUDGET_EXCEEDED');return {bytes,rows};
 }
 // Read-only projection. No repair, append, unlink, rename or authorization claim.
 async candidate(index,chunk){
  if(!Number.isInteger(index)||index<0||index>=32||!Buffer.isBuffer(chunk)||chunk.length!==C)fail('INVALID_CHUNK');
  const inv=await this.inventory(),name='chunk-'+index+'.bin';let remaining=C,seen=false;
  for(const suffix of ['', '.pending']){const old=inv.rows.find(r=>r.name===name+suffix);if(!old)continue;seen=true;
   if(old.sha256!==hash(chunk.subarray(0,old.bytes)))fail('conflicting_retry');
   if(suffix==='.pending')remaining=C-old.bytes;else remaining=0;
  }
  if(inv.rows.some(r=>r.name===name))remaining=0;
  const projected=inv.bytes+remaining;if(projected>this.limit)fail('LOGICAL_BUDGET_EXCEEDED');return {bytes:inv.bytes,remaining,projected,repeated:seen&&remaining===0};
 }
}
