import {createServer} from 'node:http';
import {BridgeError} from './broker.mjs';
// Deliberately read-only staging surface. No claim of full SDK/message compatibility.
export function classifyClientRequest(method,target){
 if(typeof target!=='string'||!target.startsWith('/')||target.startsWith('//')||target.length>8192||/[\\\x00-\x20\x7f#]/.test(target))return null;
 const [raw,...rest]=target.split('?');if(rest.length>1)return null;
 let decoded;try{decoded=decodeURIComponent(raw);}catch{return null;}
 // No allowed staging route needs escaped characters. Reject canonicalization ambiguities.
 if(decoded!==raw||raw.includes('//')||raw.split('/').some(s=>s==='.'||s==='..'))return null;
 const query=new URLSearchParams(rest[0]||'');for(const key of query.keys())if(!['since','timeout','filter','full_state','set_presence','from','limit'].includes(key))return null;
 if(method!=='GET')return null;
 if(raw==='/_matrix/client/versions')return {public:true};
 return /^\/_matrix\/client\/(v3|r0)\/(account\/whoami|devices|sync)$/.test(raw)?{public:false}:null;
}
export function createLabClientIngress({enabled=false,upstreamBase,resolveSession,fetchImpl=globalThis.fetch,maxPerMinute=120}={}){
 let upstream;try{upstream=new URL(upstreamBase);}catch{if(enabled)throw new BridgeError('ingress_config_invalid');}
 const host=upstream?.hostname;const privateHost=host==='127.0.0.1'||host==='localhost'||/^10\./.test(host||'')||/^192\.168\./.test(host||'')||/^172\.(1[6-9]|2\d|3[01])\./.test(host||'');
 if(enabled&&(!privateHost||upstream.protocol!=='http:'||!['8008','18008'].includes(upstream.port)||upstream.username||upstream.password||upstream.pathname!=='/'||upstream.search||upstream.hash||typeof resolveSession!=='function'||!Number.isInteger(maxPerMinute)||maxPerMinute<1||maxPerMinute>1000))throw new BridgeError('ingress_config_invalid');
 const buckets=new Map();let active=0;
 const reply=(res,status)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({errcode:status===401?'M_UNKNOWN_TOKEN':'M_FORBIDDEN',error:'Request unavailable'}));};
 return createServer(async(req,res)=>{
  const bucketKey=req.socket.remoteAddress;const now=Date.now();for(const [key,b] of buckets)if(b.until<=now)buckets.delete(key);
  if(!buckets.has(bucketKey)&&buckets.size>=1024){req.resume();reply(res,429);return;}
  const b=buckets.get(bucketKey)||{count:0,until:now+60000};b.count++;buckets.set(bucketKey,b);
  if(b.count>maxPerMinute||active>=16){req.resume();reply(res,429);return;}
  if(!enabled){req.resume();reply(res,503);return;}
  const route=classifyClientRequest(req.method,req.url);
  if(!route||req.headers['transfer-encoding']||Number(req.headers['content-length']||0)!==0){req.resume();reply(res,403);return;}
  const auth=req.headers.authorization;const token=typeof auth==='string'&&/^Bearer [A-Za-z0-9._~+\/-]{1,4096}={0,2}$/.test(auth)?auth.slice(7):null;
  let identity;active++;
  try{
   if(!route.public){identity=token?await resolveSession(token):null;if(!identity){reply(res,401);return;}}
   const target=upstream.origin+req.url;
   const r=await fetchImpl(target,{method:'GET',redirect:'error',signal:AbortSignal.timeout(65000),headers:!route.public&&token?{Authorization:'Bearer '+token}:{} });
   if(!r.ok){await r.body?.cancel();reply(res,r.status===401?401:502);return;}
   // Fully buffer a bounded encrypted/metadata response, then recheck revocation before publishing.
   const reader=r.body.getReader(),parts=[];let size=0;
   while(true){const chunk=await reader.read();if(chunk.done)break;size+=chunk.value.length;if(size>2097152){await reader.cancel();throw new Error('oversize');}parts.push(chunk.value);}
   if(!route.public){const after=await resolveSession(token);if(!after||after.deviceId!==identity.deviceId||after.userId!==identity.userId){reply(res,401);return;}}
   res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(Buffer.concat(parts));
  }catch{if(!res.headersSent)reply(res,502);else res.destroy();}finally{active--;}
 });
}
