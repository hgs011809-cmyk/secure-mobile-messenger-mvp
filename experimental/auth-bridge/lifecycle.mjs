import {BridgeError} from './broker.mjs';
// Single-process lab coordinator. Must initialize BEFORE accepting grants/ingress.
export class RevocationCoordinator {
 constructor({intents,enrollment,allowedDeviceIds}){this.intents=intents;this.enrollment=enrollment;this.allowed=new Set(allowedDeviceIds);this.denied=new Set();this.ready=false;this.queue=Promise.resolve();}
 async initialize(){await this.intents.transaction(d=>{
  // This is a SEPARATE revocation-intent file, not the broker's active identity mapping file.
  for(const [id,x] of Object.entries(d.mappings)){if(typeof x.enrollmentDone!=='boolean'||typeof x.matrixDone!=='boolean'||typeof x.cleanupPending!=='boolean')throw new BridgeError('revocation_store_invalid');this.denied.add(id);}
 });this.ready=true;}
 async getDevice(id){if(!this.ready||this.denied.has(id)||!this.allowed.has(id))return null;const d=await this.enrollment.getDevice(id);return this.denied.has(id)?null:d;}
 revokeDevice(id,broker){
  if(!this.allowed.has(id))return Promise.reject(new BridgeError('device_not_allowed'));
  this.denied.add(id); // deny immediately, including while an older grant is awaiting network I/O
  const run=this.queue.then(async()=>{
   if(!this.ready)throw new BridgeError('lifecycle_not_ready');
   // Persist intent before either external mutation. Restart cannot reopen this device.
   await this.intents.transaction(d=>{d.mappings[id]??={enrollmentDone:false,matrixDone:false};d.mappings[id].cleanupPending=true;});
   let enrollmentDone=false,matrixDone=false;
   try{await this.enrollment.revokeDevice(id);enrollmentDone=(await this.enrollment.getDevice(id))===null;}catch{}
   try{matrixDone=(await broker.revoke(id)).revoked===true;}catch{}
   await this.intents.transaction(d=>{Object.assign(d.mappings[id],{enrollmentDone,matrixDone,cleanupPending:!(enrollmentDone&&matrixDone)});});
   return {revoked:enrollmentDone&&matrixDone,cleanupPending:!(enrollmentDone&&matrixDone)};
  });this.queue=run.catch(()=>{});return run;
 }
 async retryPending(broker){if(!this.ready)throw new BridgeError('lifecycle_not_ready');const ids=await this.intents.transaction(d=>Object.keys(d.mappings).filter(id=>d.mappings[id].cleanupPending));const results=[];for(const id of ids)results.push(await this.revokeDevice(id,broker));return results;}
}
