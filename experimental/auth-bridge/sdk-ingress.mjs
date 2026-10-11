import {createServer} from 'node:http';
import {authorizeSdkRequest} from './sdk-policy.mjs';
import {authorizePinnedSignatures} from './signature-policy.mjs';
// Separate default-disabled SDK staging surface. Never imported by operating auth/app.
export function createSdkIngress({enabled=false,upstreamBase,resolveSession,getBinding,fetchImpl=globalThis.fetch,maxPerMinute=600}={}){
 let upstream;try{upstream=new URL(upstreamBase);}catch{}
 const host=upstream?.hostname,octets=(host||'').split('.'),ipv4=octets.length===4&&octets.every(x=>/^\d{1,3}$/.test(x)&&Number(x)<=255),privateHost=host==='127.0.0.1'||host==='localhost'||ipv4&&(Number(octets[0])===10||Number(octets[0])===192&&Number(octets[1])===168||Number(octets[0])===172&&Number(octets[1])>=16&&Number(octets[1])<=31);
 if(enabled&&(!privateHost||upstream.protocol!=='http:'||!['8008','18008'].includes(upstream.port)||upstream.username||upstream.password||upstream.pathname!=='/'||upstream.search||upstream.hash||typeof resolveSession!=='function'||typeof getBinding!=='function'||!Number.isInteger(maxPerMinute)||maxPerMinute<1||maxPerMinute>1000))throw new Error('sdk_ingress_config_invalid');
 let active=0;const buckets=new Map();
 const reject=(res,status)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({errcode:status===401?'M_UNKNOWN_TOKEN':'M_FORBIDDEN',error:'Request unavailable'}));};
 return createServer(async(req,res)=>{
  const now=Date.now(),key=req.socket.remoteAddress;for(const [ip,b]of buckets)if(b.until<=now)buckets.delete(ip);
  if(!buckets.has(key)&&buckets.size>=1024){req.resume();reject(res,429);return;}
  const bucket=buckets.get(key)||{count:0,until:now+60000};bucket.count++;buckets.set(key,bucket);
  if(bucket.count>maxPerMinute||active>=16){req.resume();reject(res,429);return;}
  if(!enabled){req.resume();reject(res,503);return;}
  const auth=req.headers.authorization,token=typeof auth==='string'&&/^Bearer [A-Za-z0-9._~+\/-]{1,4096}={0,2}$/.test(auth)?auth.slice(7):null;
  active++;try{
   // Never decompress or accept unbounded/chunked request bodies.
   if(req.headers['content-encoding']||req.headers['transfer-encoding']){req.resume();reject(res,403);return;}
   const length=Number(req.headers['content-length']||0);if(!Number.isInteger(length)||length<0||length>524288){req.resume();reject(res,413);return;}
   let size=0;const chunks=[];for await(const chunk of req){size+=chunk.length;if(size>524288)throw new Error('oversized_body');chunks.push(chunk);}
   if(size!==length){reject(res,403);return;}
   let body;try{body=size?JSON.parse(Buffer.concat(chunks).toString('utf8')):undefined;}catch{reject(res,403);return;}
   const identity=token?await resolveSession(token):null;
   const binding=identity?await getBinding(identity):null;
   const input={method:req.method,target:req.url,body,identity,binding};
   const allowed=authorizeSdkRequest(input)||authorizePinnedSignatures(input);
   if(!allowed){reject(res,identity?403:401);return;}
   if(!allowed.public&&!identity){reject(res,401);return;}
   // Recheck before issuing writes. Already in-flight native writes cannot be atomically undone.
   if(!allowed.public){const again=await resolveSession(token);if(!again||again.deviceId!==identity.deviceId||again.userId!==identity.userId||again.matrixDeviceId!==identity.matrixDeviceId){reject(res,401);return;}}
   const r=await fetchImpl(upstream.origin+allowed.path,{method:allowed.method,redirect:'error',signal:AbortSignal.timeout(65000),headers:{'Content-Type':'application/json',...(allowed.public?{}:{Authorization:'Bearer '+token})},...(allowed.method==='GET'||allowed.body===undefined||allowed.body===null?{}:{body:JSON.stringify(allowed.body)})});
   if(!r.ok){await r.body?.cancel();reject(res,r.status===401?401:r.status===403?403:502);return;}
   const reader=r.body.getReader(),parts=[];let total=0;while(true){const item=await reader.read();if(item.done)break;total+=item.value.length;if(total>2097152){await reader.cancel();throw new Error('oversized_response');}parts.push(item.value);}
   if(!allowed.public){const after=await resolveSession(token);if(!after||after.deviceId!==identity.deviceId||after.userId!==identity.userId||after.matrixDeviceId!==identity.matrixDeviceId){reject(res,401);return;}}
   const raw=Buffer.concat(parts);let output=raw;
   if(!allowed.public){const currentBinding=await getBinding(identity),own=currentBinding?.devices?.find(d=>d.userId===identity.userId&&d.matrixDeviceId===identity.matrixDeviceId);if(!own||own.active===false||currentBinding.roomId!==binding.roomId){reject(res,403);return;}const data=JSON.parse(raw.toString('utf8'));
    const peers=binding.devices.map(d=>d.userId),ids=new Map(binding.devices.map(d=>[d.userId,d.matrixDeviceId]));
    if(/^\/_matrix\/client\/(v3|r0)\/sync(?:\?|$)/.test(allowed.path)){
     for(const kind of ['join','invite','leave'])if(data.rooms?.[kind])data.rooms[kind]=Object.fromEntries(Object.entries(data.rooms[kind]).filter(([id])=>id===binding.roomId));
     if(data.to_device?.events)data.to_device.events=data.to_device.events.filter(e=>peers.includes(e.sender)&&(/^m\.key\.verification\.(request|ready|start|accept|key|mac|done|cancel)$/.test(e.type)||e.type==='m.room.encrypted')&&(!e.content?.from_device||e.content.from_device===ids.get(e.sender)));
     for(const type of ['changed','left'])if(Array.isArray(data.device_lists?.[type]))data.device_lists[type]=data.device_lists[type].filter(uid=>peers.includes(uid));
    }
    for(const name of ['device_keys','one_time_keys'])if(data[name])data[name]=Object.fromEntries(Object.entries(data[name]).filter(([uid])=>peers.includes(uid)).map(([uid,values])=>[uid,Object.fromEntries(Object.entries(values).filter(([did])=>did===ids.get(uid)))]));
    for(const name of ['master_keys','self_signing_keys','user_signing_keys'])if(data[name])data[name]=Object.fromEntries(Object.entries(data[name]).filter(([uid])=>peers.includes(uid)));
    output=Buffer.from(JSON.stringify(data));
   }
   res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(output);
  }catch{if(!res.headersSent)reject(res,502);else res.destroy();}finally{active--;}
 });
}
