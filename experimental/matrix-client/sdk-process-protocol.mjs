// Synthetic IPC foundation only. NOT actual SDK/native authority proof.
export const OPS=new Set(['initialize','accept','resume','finalize']);
export const CODES=new Set(['not_authorized','manifest_changed','invalid_stored_chunk','integrity_failed','conflicting_retry','invalid_chunk','incomplete','expired','invalid_manifest','SESSION_DENIED','PROTOCOL_DENIED','AUTH_TIMEOUT','SESSION_CLOSED']);
export function exact(o,keys){return !!o&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).sort().join(',')===[...keys].sort().join(',');}
export function context(c){return exact(c,['generation','transferId','bindingId'])&&typeof c.generation==='string'&&typeof c.transferId==='string'&&typeof c.bindingId==='string'&&/^[a-f0-9]{64}$/.test(c.generation)&&/^[a-f0-9]{32}$/.test(c.transferId)&&/^[a-f0-9]{64}$/.test(c.bindingId);}
export const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export function authorityRequest(m,c,command,last){return exact(m,['type','context','command','request','checkpoint','deadline'])&&m.type==='authority'&&context(m.context)&&same(m.context,c)&&m.command===command&&Number.isSafeInteger(m.request)&&m.request===last+1&&Number.isSafeInteger(m.checkpoint)&&m.checkpoint>=1&&Number.isSafeInteger(m.deadline)&&m.deadline>Date.now()&&m.deadline<=Date.now()+5000;}

export function validResult(op,r,m,p){
 if(op==='initialize')return exact(r,['initialized'])&&r.initialized===true;
 if(op==='accept')return exact(r,['accepted','repeated','index'])&&r.accepted===true&&typeof r.repeated==='boolean'&&Number.isSafeInteger(r.index)&&r.index===p.index&&r.index>=0&&r.index<Math.ceil(m.totalBytes/m.chunkBytes);
 if(op==='finalize')return exact(r,['complete','totalBytes'])&&r.complete===true&&r.totalBytes===m.totalBytes;
 if(op==='resume'){if(!exact(r,['present','totalBytes'])||!Array.isArray(r.present)||r.present.length>Math.ceil(m.totalBytes/m.chunkBytes)||!Number.isSafeInteger(r.totalBytes))return false;let last=-1,bytes=0;for(const i of r.present){if(!Number.isSafeInteger(i)||i<=last||i<0||i>=Math.ceil(m.totalBytes/m.chunkBytes))return false;last=i;bytes+=Math.min(m.chunkBytes,m.totalBytes-i*m.chunkBytes);}return r.totalBytes===bytes;}
 return false;
}
