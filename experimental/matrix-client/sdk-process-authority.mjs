// NEW experimental parent-only candidate. No SDK/runtime provenance claim by itself.
// Secrets remain closure-local; only authorize's strict boolean may enter child IPC.
import {types} from 'node:util';
import {validateDescriptor} from '../media-transfer-lab/attachment-stream.mjs';
import {context as validContext} from './sdk-process-protocol.mjs';

export class SdkProcessAuthorityError extends Error {
 constructor(code){super(code);this.name='SdkProcessAuthorityError';this.code=code;}
}
const fail=()=>{throw new SdkProcessAuthorityError('AUTHORITY_DENIED');};
const requireTrue=v=>{if(v!==true)fail();};
function record(v,fields){
 requireTrue(!!v&&typeof v==='object'&&!types.isProxy(v));
 const p=Object.getPrototypeOf(v);requireTrue(p===Object.prototype||p===null);
 requireTrue(Reflect.ownKeys(v).length===fields.length);
 const out=Object.create(null);
 for(const k of fields){const d=Object.getOwnPropertyDescriptor(v,k);requireTrue(!!d&&Object.hasOwn(d,'value'));out[k]=d.value;}
 return out;
}
function text(v,max=1024){requireTrue(typeof v==='string'&&v.length>0&&v.length<=max&&!/[\x00-\x1f\x7f]/.test(v));return v;}
function receipt(v){
 const r=record(v,['eventId','roomId','senderUserId','senderDeviceId','descriptor']);
 for(const k of ['eventId','roomId','senderUserId','senderDeviceId'])text(r[k],k==='senderDeviceId'?255:1024);
 requireTrue(r.eventId.startsWith('$'));r.descriptor=validateDescriptor(r.descriptor);
 return Object.freeze(r);
}
function participant(v){
 const p=record(v,['userId','matrixDeviceId','deviceId','accessToken']);
 for(const k of Object.keys(p))text(p[k],k==='accessToken'?8192:1024);
 return Object.freeze(p);
}
function pin(v){
 const p=record(v,['deviceId','userId','matrixDeviceId','ed25519','curve25519']);
 for(const k of ['deviceId','userId','matrixDeviceId'])text(p[k]);
 for(const k of ['ed25519','curve25519'])requireTrue(typeof p[k]==='string'&&/^[A-Za-z0-9+/]{43}$/.test(p[k])&&Buffer.from(p[k],'base64').length===32);
 return Object.freeze(p);
}

/** Trusted owner driver inputs, NOT hostile/injected executable authority objects.
 * broker/issuer/registry/lifecycle must be the driver's existing real instances.
 * recipientPage is its live Playwright page with existing window.lab transport hooks.
 * terminateOwnedChannel: synchronous, non-throwing close/kill initiation by owner;
 * owner MUST await owned child exit separately before cleanup. No child is owned here.
 * signal/deadline apply to INITIAL capture; each authorize uses IPC deadline/signal.
 * No arbitrary authorization callback, cached grant or fixed mockAllowed input.
 */
export async function createSdkProcessAuthority({broker,issuer,registry,lifecycle,recipientPage,
 sender,recipient,originalReceipt,transferId,bindingId,signal,deadline,terminateOwnedChannel}){
 let denied=false,busy=false,generation=null,lastRequest=0,lastCommand=0,lastCheckpoint=0;
 const stop=()=>{denied=true;try{terminateOwnedChannel();}catch{}};
 try{
  requireTrue(typeof terminateOwnedChannel==='function');
  requireTrue(typeof broker?.resolveSession==='function'&&typeof issuer?.whoami==='function'&&typeof registry?.read==='function'&&typeof lifecycle?.getDevice==='function'&&typeof recipientPage?.evaluate==='function');
  requireTrue(typeof transferId==='string'&&/^[a-f0-9]{32}$/.test(transferId)&&typeof bindingId==='string'&&/^[a-f0-9]{64}$/.test(bindingId));
  const s=participant(sender),r=participant(recipient),captured=receipt(originalReceipt),identity=JSON.stringify(captured);
  requireTrue(s.deviceId!==r.deviceId&&s.userId!==r.userId&&s.matrixDeviceId!==r.matrixDeviceId);
  requireTrue(captured.senderUserId===s.userId&&captured.senderDeviceId===s.matrixDeviceId);
  const live=(sig,until)=>!denied&&sig?.aborted===false&&Number.isSafeInteger(until)&&Date.now()<until&&until<=Date.now()+5000;
  // Underlying SDK/native helpers have no AbortSignal API. Race only revokes grants;
  // read-only work can settle later, never grant. Owner closes IPC on cancellation.
  async function bounded(fn,sig,until){
   requireTrue(live(sig,until));
   let timer,abort;
   const cancelled=new Promise((_,reject)=>{
    abort=()=>{stop();reject(new SdkProcessAuthorityError('AUTHORITY_DENIED'));};
    sig.addEventListener('abort',abort,{once:true});timer=setTimeout(abort,Math.max(0,until-Date.now()));
   });
   try{const value=await Promise.race([Promise.resolve().then(()=>{requireTrue(live(sig,until));return fn();}),cancelled]);requireTrue(live(sig,until));return value;}
   finally{clearTimeout(timer);sig.removeEventListener('abort',abort);}
  }
  async function leases(sig,until){
   for(const p of [r,s]){
    const native=await bounded(()=>issuer.whoami(p.accessToken),sig,until);
    const current=await bounded(()=>broker.resolveSession(p.accessToken,native),sig,until);
    requireTrue(!!current&&current.userId===p.userId&&current.matrixDeviceId===p.matrixDeviceId&&current.deviceId===p.deviceId);
   }
  }
  async function bindings(sig,until){
   const current=await bounded(()=>registry.read(),sig,until);
   requireTrue(current?.shape==='direct-matrix-sdk-binding-v1'&&current.roomId===captured.roomId&&Array.isArray(current.devices)&&current.devices.length===2);
   const pins=current.devices.map(pin).sort((a,b)=>a.deviceId.localeCompare(b.deviceId));
   for(const p of [s,r]){
    requireTrue(pins.some(d=>d.deviceId===p.deviceId&&d.userId===p.userId&&d.matrixDeviceId===p.matrixDeviceId));
    const active=await bounded(()=>lifecycle.getDevice(p.deviceId),sig,until);
    requireTrue(!!active&&active.deviceId===p.deviceId);
   }
   return JSON.stringify({roomId:current.roomId,devices:pins});
  }
  async function crossBinding(sig,until){
   const value=await bounded(()=>recipientPage.evaluate(async event=>{
    if(typeof window.lab?.sdkProcessAuthorityCrossBinding!=='function')return null;
    return window.lab.sdkProcessAuthorityCrossBinding({event});
   },captured.eventId),sig,until);
   if(value===null)throw new SdkProcessAuthorityError('SDK_CROSS_BINDING_BLOCKED');
   const v=record(value,['recipientUserId','recipientDeviceId','roomId','peerUserId','peerDeviceId','eventId','eventSenderUserId','eventSenderCurve25519','eventSenderEd25519','devices']);
   requireTrue(v.recipientUserId===r.userId&&v.recipientDeviceId===r.matrixDeviceId&&v.roomId===captured.roomId&&v.peerUserId===s.userId&&v.peerDeviceId===s.matrixDeviceId&&v.eventId===captured.eventId&&v.eventSenderUserId===s.userId);
   requireTrue(Array.isArray(v.devices)&&!types.isProxy(v.devices)&&v.devices.length===2);
   const actual=v.devices.map(d=>record(d,['userId','matrixDeviceId','ed25519','curve25519']));
   const pins=JSON.parse(baseline).devices;
   for(const p of pins){const d=actual.filter(x=>x.userId===p.userId&&x.matrixDeviceId===p.matrixDeviceId);requireTrue(d.length===1&&d[0].ed25519===p.ed25519&&d[0].curve25519===p.curve25519);}
   const senderPin=pins.find(p=>p.deviceId===s.deviceId);
   requireTrue(v.eventSenderCurve25519===senderPin.curve25519&&v.eventSenderEd25519===senderPin.ed25519);
  }
  async function sdk(sig,until){
   await crossBinding(sig,until);
   const status=await bounded(()=>recipientPage.evaluate(async event=>window.lab.transportAuthorityStatus({event}),captured.eventId),sig,until);
   requireTrue(status?.allowed===true&&status.stage==='LIVE');
   // This invokes receiveDescriptor again, not a supplied boolean. Export follows
   // original-map status and is compared against the private INITIAL receipt.
   const fresh=await bounded(()=>recipientPage.evaluate(async event=>window.lab.transportExport({event}),captured.eventId),sig,until);
   requireTrue(JSON.stringify(receipt(fresh))===identity);
   const after=await bounded(()=>recipientPage.evaluate(async event=>window.lab.transportAuthorityStatus({event}),captured.eventId),sig,until);
   requireTrue(after?.allowed===true&&after.stage==='LIVE');
   await crossBinding(sig,until);
  }
  await leases(signal,deadline);
  const baseline=await bindings(signal,deadline);
  await sdk(signal,deadline);
  await leases(signal,deadline);requireTrue(await bindings(signal,deadline)===baseline);
  requireTrue(live(signal,deadline));
  const authorize=async(request,abortSignal)=>{
   if(denied||busy){stop();return false;}busy=true;
   try{
    const q=record(request,['type','context','command','request','checkpoint','deadline']);
    const c=record(q.context,['generation','transferId','bindingId']);
    requireTrue(q.type==='authority'&&validContext({...c})&&c.transferId===transferId&&c.bindingId===bindingId);
    requireTrue(generation===null||generation===c.generation);
    requireTrue(Number.isSafeInteger(q.request)&&q.request===lastRequest+1&&Number.isSafeInteger(q.command)&&q.command>=1&&Number.isSafeInteger(q.checkpoint)&&q.checkpoint>=1);
    requireTrue((q.command===lastCommand&&q.checkpoint===lastCheckpoint+1)||(q.command===lastCommand+1&&q.checkpoint===1));
    requireTrue(live(abortSignal,q.deadline));
    generation=c.generation;lastRequest=q.request;lastCommand=q.command;lastCheckpoint=q.checkpoint;
    await leases(abortSignal,q.deadline);
    requireTrue(await bindings(abortSignal,q.deadline)===baseline);
    await sdk(abortSignal,q.deadline);
    // Refresh both native sessions and exact pins after async SDK checks.
    await leases(abortSignal,q.deadline);
    requireTrue(await bindings(abortSignal,q.deadline)===baseline);
    requireTrue(live(abortSignal,q.deadline));return true;
   }catch{stop();return false;}finally{busy=false;}
  };
  return Object.freeze({authorize,close:stop});
 }catch(error){stop();throw new SdkProcessAuthorityError(error instanceof SdkProcessAuthorityError&&error.code==='SDK_CROSS_BINDING_BLOCKED'?'SDK_CROSS_BINDING_BLOCKED':'AUTHORITY_DENIED');}
}
