// Foundational private IPC bridge. Caller-supplied authority is NOT real SDK proof.
import {fork} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
import {OPS,CODES,exact,authorityRequest,same,validResult} from './sdk-process-protocol.mjs';
const worker=fileURLToPath(new URL('./sdk-process-worker.mjs',import.meta.url));
export async function openCiphertextSession({root,manifest,authorize,syntheticDecisionFault=null}){
 if(typeof authorize!=='function')throw Error('INVALID_AUTHORITY');
 const context={generation:randomBytes(32).toString('hex'),transferId:manifest.transferId,bindingId:manifest.bindingId};
 const child=fork(worker,['--sdk-process-root='+root],{stdio:['ignore','ignore','ignore','ipc'],execArgv:[],serialization:'json',env:{TZ:'UTC'}});
 const exited=once(child,'exit');let closed=false,seq=0,last=0,checkpoint=0,pending=null,authBusy=false;
 const controller=new AbortController();
 const close=async()=>{if(!closed){closed=true;authBusy=false;controller.abort();if(pending){clearTimeout(pending.timer);pending.reject(Error('SESSION_CLOSED'));pending=null;}if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');}}await exited;};
 const ready=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{close().finally(()=>reject(Error('SESSION_CLOSED')));},3000);child.once('error',()=>{clearTimeout(timer);close().finally(()=>reject(Error('SESSION_CLOSED')));});child.once('exit',()=>{clearTimeout(timer);reject(Error('SESSION_CLOSED'));});child.once('message',m=>{clearTimeout(timer);if(!exact(m,['type','pid','environmentIsolated'])||m.type!=='ready'||m.pid!==child.pid||m.environmentIsolated!==true){close().finally(()=>reject(Error('PROTOCOL_DENIED')));}else resolve(true);});});
 child.on('message',async m=>{
  if(closed)return;
  if(m?.type==='authority'){
   if(!pending||authBusy||!authorityRequest(m,context,seq,last)||m.checkpoint!==checkpoint+1){await close();return;}
   last=m.request;checkpoint=m.checkpoint;authBusy=true;
   let allowed=false;try{allowed=await authorize(Object.freeze({...m,context:Object.freeze({...context})}),controller.signal)===true;}catch{}finally{authBusy=false;}
   if(closed||!pending||Date.now()>=m.deadline){await close();return;}
   let reply={...m,type:'decision',allowed};if(syntheticDecisionFault)reply=syntheticDecisionFault(reply);
   if(reply)child.send(reply,()=>{});return;
  }
  if(!pending||!exact(m,m?.ok===true?['type','context','seq','ok','result']:['type','context','seq','ok','code'])||m.type!=='result'||!same(m.context,context)||m.seq!==seq||typeof m.ok!=='boolean'||(!m.ok&&!CODES.has(m.code))||(m.ok&&!validResult(pending.op,m.result,manifest,pending.payload))){await close();return;}
  const p=pending;pending=null;clearTimeout(p.timer);if(m.ok)p.resolve(m.result);else p.reject(Error(m.code));
 });
 child.on('exit',()=>{closed=true;authBusy=false;controller.abort();if(pending){clearTimeout(pending.timer);pending.reject(Error('SESSION_CLOSED'));pending=null;}});
 const command=(op,payload={})=>{
  if(closed)return Promise.reject(Error('SESSION_CLOSED'));if(pending||authBusy)return Promise.reject(Error('BACKPRESSURE'));if(!OPS.has(op))return Promise.reject(Error('INVALID_OPERATION'));
  seq++;checkpoint=0;return new Promise((resolve,reject)=>{pending={op,payload,resolve,reject,timer:setTimeout(()=>{close();},4000)};child.send({type:'command',context,seq,op,payload},err=>{if(err)close();});});
 };
 return Object.freeze({pid:child.pid,command,close,exited,initialized:ready});
}
