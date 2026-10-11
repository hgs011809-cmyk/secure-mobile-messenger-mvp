// Synthetic transport mechanics only. Not Matrix protocol, cryptographic admission or a production service.
import { promises as fs, constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
export const MAX_BYTES = 2 ** 31; // Lab parser cap, NOT a deployed product limit.
const hash = b => createHash('sha256').update(b).digest('hex');
const fail = c => { throw new Error(c); };
const exists = async p => { try { await fs.lstat(p); return true; } catch(e) { if(e.code === 'ENOENT')return false; throw e; } };
const shape = m => m && Object.getPrototypeOf(m) === Object.prototype && Object.keys(m).sort().join(',') === 'bindingId,chunkBytes,expiresAt,sha256,totalBytes,transferId,version';
export function validateManifest(m) {
  if(!shape(m) || m.version!==1 || !/^[a-f0-9]{32}$/.test(m.transferId) || !/^[a-f0-9]{64}$/.test(m.bindingId) || !/^[a-f0-9]{64}$/.test(m.sha256) || !Number.isSafeInteger(m.totalBytes) || m.totalBytes<1 || m.totalBytes>MAX_BYTES || !Number.isSafeInteger(m.chunkBytes) || m.chunkBytes<65536 || m.chunkBytes>1048576 || !Number.isSafeInteger(m.expiresAt) || m.expiresAt<1)fail('invalid_manifest');
  return Object.freeze({...m});
}
export class SyntheticReceiver {
  constructor({root,manifest,authorize,clock=Date.now}) {
    if(typeof root!=='string'||!path.isAbsolute(root)||typeof authorize!=='function'||typeof clock!=='function')fail('invalid_config');
    this.m=validateManifest(manifest);this.root=root;this.dir=path.join(root,this.m.transferId);this.tomb=path.join(root,this.m.transferId+'.deleted');this.authorize=authorize;this.clock=clock;this.tail=Promise.resolve();this.maxPayloadBytes=0;this.pending=0;
  }
  serial(fn){if(this.pending>=2)return Promise.reject(new Error('backpressure'));this.pending++;const p=this.tail.then(fn).finally(()=>{this.pending--;});this.tail=p.catch(()=>{});return p;}
  async guard(){
    if(this.clock()>=this.m.expiresAt)fail('expired');
    if(await this.authorize(this.m.bindingId)!==true)fail('not_authorized');
    const st=await fs.lstat(this.root);if(!st.isDirectory()||st.isSymbolicLink())fail('unsafe_root');
    if(await exists(this.tomb))fail('deleted');
    if(await this.authorize(this.m.bindingId)!==true||this.clock()>=this.m.expiresAt)fail('not_authorized');
  }
  size(i){if(!Number.isSafeInteger(i)||i<0||i>=Math.ceil(this.m.totalBytes/this.m.chunkBytes))fail('invalid_index');return Math.min(this.m.chunkBytes,this.m.totalBytes-i*this.m.chunkBytes);}
  file(i){this.size(i);return path.join(this.dir,'chunk-'+i+'.bin');}
  async safeDir(){const s=await fs.lstat(this.dir);if(!s.isDirectory()||s.isSymbolicLink())fail('unsafe_transfer_dir');}
  async read(i){await this.safeDir();const h=await fs.open(this.file(i),constants.O_RDONLY|constants.O_NOFOLLOW);try{const st=await h.stat();if(!st.isFile()||st.size!==this.size(i))fail('invalid_stored_chunk');return await h.readFile();}finally{await h.close();}}
  async atomic(file,data){const temp=file+'.pending';const h=await fs.open(temp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);try{await h.writeFile(data);await h.sync();}finally{await h.close();}await fs.rename(temp,file);}
  async setup(){
    await this.guard();await fs.mkdir(this.dir,{mode:0o700}).catch(e=>{if(e.code!=='EEXIST')throw e;});await this.safeDir();
    const p=path.join(this.dir,'manifest.json');
    if(await exists(p)){const h=await fs.open(p,constants.O_RDONLY|constants.O_NOFOLLOW);try{const st=await h.stat();if(st.size>2048)fail('manifest_changed');const old=JSON.parse(await h.readFile('utf8'));if(JSON.stringify(old)!==JSON.stringify(this.m))fail('manifest_changed');}finally{await h.close();}}
    else await this.atomic(p,JSON.stringify(this.m));
    // Partial writes never count as acknowledgements. Re-scan actual chunk files on resume.
    for(const e of await fs.readdir(this.dir))if(/^(chunk-\d+\.bin|checkpoint\.json|manifest\.json)\.pending$/.test(e))await fs.unlink(path.join(this.dir,e));
    await this.guard();
  }
  initialize(){return this.serial(()=>this.setup());}
  accept({index,offset,bytes,sha256}){
    // Copy immediately: caller mutation across awaits cannot change the accepted payload.
    if(!Buffer.isBuffer(bytes)||bytes.length>this.m.chunkBytes)return Promise.reject(new Error('invalid_chunk'));
    if(this.pending>=2)return Promise.reject(new Error('backpressure'));
    const owned=Buffer.from(bytes);
    return this.serial(async()=>{
      await this.guard();await this.safeDir();const size=this.size(index);
      if(offset!==index*this.m.chunkBytes||owned.length!==size||typeof sha256!=='string'||sha256!==hash(owned))fail('invalid_chunk');
      this.maxPayloadBytes=Math.max(this.maxPayloadBytes,owned.length);
      const file=this.file(index);let repeated=false;
      if(await exists(file)){const stored=await this.read(index);if(hash(stored)!==sha256)fail('conflicting_retry');repeated=true;}
      else{await this.guard();await this.atomic(file,owned);}
      await this.guard(); // No ack after revoked binding, expiry or deletion.
      return {accepted:true,repeated,index};
    });
  }
  resume(){return this.serial(async()=>{
    await this.guard();await this.safeDir();const present=[];
    for(let i=0;i<Math.ceil(this.m.totalBytes/this.m.chunkBytes);i++)if(await exists(this.file(i))){await this.read(i);present.push(i);}
    await this.guard();return {present,totalBytes:present.reduce((n,i)=>n+this.size(i),0)};
  });}
  finalize(){return this.serial(async()=>{
    await this.guard();const digest=createHash('sha256');let n=0;
    for(let i=0;i<Math.ceil(this.m.totalBytes/this.m.chunkBytes);i++){await this.guard();if(!await exists(this.file(i)))fail('incomplete');const b=await this.read(i);this.maxPayloadBytes=Math.max(this.maxPayloadBytes,b.length);digest.update(b);n+=b.length;}
    if(n!==this.m.totalBytes||digest.digest('hex')!==this.m.sha256)fail('integrity_failed');
    await this.guard();return {complete:true,totalBytes:n}; // No plaintext, key, rendering or public download.
  });}
  erase(){return this.serial(async()=>{
    // Local safety cancellation may tombstone a revoked lease; no remote deletion authority implied.
    const st=await fs.lstat(this.root);if(!st.isDirectory()||st.isSymbolicLink())fail('unsafe_root');
    if(!await exists(this.tomb)){const h=await fs.open(this.tomb,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);try{await h.writeFile('deleted');await h.sync();}finally{await h.close();}}
    if(await exists(this.dir)){await this.safeDir();await fs.rm(this.dir,{recursive:true});}
    return {deleted:true,physicalErasure:false};
  });}
}
