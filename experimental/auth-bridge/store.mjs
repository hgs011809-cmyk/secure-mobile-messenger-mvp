import {promises as fs} from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
// Single-process experimental store. Passwords are server-only secrets, never public output.
export class BridgeStore {
 constructor(file){this.file=file;this.queue=Promise.resolve();}
 transaction(fn){const run=this.queue.then(async()=>{
  let data;try{data=JSON.parse(await fs.readFile(this.file,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;data={version:1,mappings:{}};}
  if(data.version!==1||!data.mappings||typeof data.mappings!=='object'||Array.isArray(data.mappings))throw new Error('bridge_store_invalid');
  const result=await fn(data);await fs.mkdir(path.dirname(this.file),{recursive:true,mode:0o700});
  const tmp=this.file+'.'+randomUUID()+'.tmp';let handle;
  try{handle=await fs.open(tmp,'wx',0o600);await handle.writeFile(JSON.stringify(data));await handle.sync();await handle.close();handle=null;await fs.rename(tmp,this.file);await fs.chmod(this.file,0o600);}
  finally{await handle?.close();await fs.unlink(tmp).catch(()=>{});}
  return result;
 });this.queue=run.catch(()=>{});return run;}
}
