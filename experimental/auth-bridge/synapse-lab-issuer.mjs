import {BridgeError} from './broker.mjs';
// Only a trusted local/CI transport. Never accepted from browser request data.
const privateHost=h=>h==='localhost'||h==='127.0.0.1'||/^10\.(\d{1,3}\.){2}\d{1,3}$/.test(h)||/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)||/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(h);
export class SynapseLabIssuer {
 #base;#admin;#fetch;
 constructor({baseUrl,adminToken,fetchImpl=globalThis.fetch}){
  let u;try{u=new URL(baseUrl);}catch{throw new BridgeError('lab_transport_invalid');}
  if(u.protocol!=='http:'||!privateHost(u.hostname)||!['8008','18008'].includes(u.port)||u.username||u.password||u.pathname!=='/'||u.search||u.hash||typeof adminToken!=='string'||!adminToken||typeof fetchImpl!=='function')throw new BridgeError('lab_transport_invalid');
  this.#base=u.origin;this.#admin=adminToken;this.#fetch=fetchImpl;
 }
 async #request(path,method,body,token){
  try{
   const r=await this.#fetch(this.#base+path,{method,redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})});
   if(!r.ok)throw new Error('rejected');
   const text=await r.text();if(text.length>65536)throw new Error('oversized');
   return JSON.parse(text);
  }catch{throw new BridgeError('matrix_transport_failure');}
 }
 ensureAccount(m){return this.#request('/_synapse/admin/v2/users/'+encodeURIComponent(m.userId),'PUT',{password:m.password,logout_devices:false,admin:false,deactivated:false},this.#admin);}
 login(m){return this.#request('/_matrix/client/v3/login','POST',{type:'m.login.password',identifier:{type:'m.id.user',user:m.userId},password:m.password,device_id:m.matrixDeviceId,refresh_token:false},undefined);}
 whoami(token){return this.#request('/_matrix/client/v3/account/whoami','GET',undefined,token);}
 async listDevices(token){const r=await this.#request('/_matrix/client/v3/devices','GET',undefined,token);return r.devices;}
 revoke(m){return this.#request('/_synapse/admin/v1/deactivate/'+encodeURIComponent(m.userId),'POST',{erase:false},this.#admin);}
}
