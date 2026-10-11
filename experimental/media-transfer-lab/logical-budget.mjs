// Synthetic single-owner logical lengths only. Not a quota or security boundary.
import * as fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
const TOTAL=8388608,CHUNK=262144;
const fail=code=>{throw Object.assign(new Error(code),{code});};
export class LogicalCiphertextBudget {
 constructor(root,limit){if(!path.isAbsolute(root)||!Number.isSafeInteger(limit)||limit<0)fail('INVALID_BUDGET');this.root=root;this.limit=limit;}
 async inventory(){
  const s=await fs.lstat(this.root);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&4095)!==448||s.uid!==process.getuid())fail('UNSAFE_FIXTURE');
  const rows=[];let bytes=0;
  for(const name of (await fs.readdir(this.root)).sort()){
   const match=/^chunk-(\d+)\.bin$/.exec(name);if(name!=='source.bin'&&(!match||Number(match[1])>=32||String(Number(match[1]))!==match[1]))fail('UNEXPECTED_CIPHERTEXT_FILE');
   const p=path.join(this.root,name),v=await fs.lstat(p),want=name==='source.bin'?TOTAL:CHUNK;
   if(!v.isFile()||v.isSymbolicLink()||(v.mode&4095)!==384||v.uid!==process.getuid())fail('UNSAFE_FIXTURE');
   if(v.size!==want)fail('INVALID_CIPHERTEXT_LENGTH');
   const h=createHash('sha256'),handle=await fs.open(p,'r'),buf=Buffer.alloc(CHUNK);try{for(;;){const r=await handle.read(buf,0,CHUNK,null);if(!r.bytesRead)break;h.update(buf.subarray(0,r.bytesRead));}}finally{await handle.close();}
   bytes+=v.size;rows.push({name,bytes:v.size,sha256:h.digest('hex')});
  }
  if(!rows.some(r=>r.name==='source.bin'))fail('SOURCE_MISSING');
  if(bytes>this.limit)fail('LOGICAL_BUDGET_EXCEEDED');return {bytes,rows};
 }
 async accept(index,bytes){
  if(!Number.isInteger(index)||index<0||index>=32||!Buffer.isBuffer(bytes)||bytes.length!==CHUNK)fail('INVALID_CHUNK');
  const inv=await this.inventory(),name='chunk-'+index+'.bin',old=inv.rows.find(r=>r.name===name),hash=createHash('sha256').update(bytes).digest('hex');
  if(old){if(old.sha256!==hash)fail('conflicting_retry');return {repeated:true,bytes:inv.bytes};}
  if(inv.bytes+bytes.length>this.limit)fail('LOGICAL_BUDGET_EXCEEDED');
  const handle=await fs.open(path.join(this.root,name),'wx',0o600);try{await handle.writeFile(bytes);}finally{await handle.close();}
  return {repeated:false,bytes:(await this.inventory()).bytes};
 }
}
