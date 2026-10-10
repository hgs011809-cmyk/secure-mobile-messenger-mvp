import {randomBytes} from 'node:crypto';
import {importP256PublicKey,verifyEcdsaSignature,fingerprintSpki} from '../../infra/ncp/auth/src/crypto.js';
const ID=/^[A-Za-z0-9_-]{16,128}$/;
const PEER=/^[A-Za-z0-9._-]{3,80}$/;
const token=()=>randomBytes(24).toString('base64url');
export class BridgeError extends Error {constructor(code){super(code);this.name='BridgeError';this.code=code;}}
const fail=code=>{throw new BridgeError(code);};
// DEVELOPMENT ONLY. No HTTP route or production import. Enrollment != E2EE verification.
export class MatrixAdmissionBroker {
 constructor({enabled=false,store,getDevice,issuer,allowedDeviceIds=[],serverName='matrix.lab',now=Date.now,challengeMs=30000,maxSessionMs=600000,maxChallenges=64}={}){
  this.enabled=enabled;this.store=store;this.getDevice=getDevice;this.issuer=issuer;this.now=now;this.queue=Promise.resolve();this.challenges=new Map();
  this.allowed=new Set(allowedDeviceIds);this.serverName=serverName;this.challengeMs=challengeMs;this.maxSessionMs=maxSessionMs;this.maxChallenges=maxChallenges;
  if(enabled&&(this.allowed.size!==2||allowedDeviceIds.length!==2||!allowedDeviceIds.every(id=>ID.test(id))||!['matrix.lab','matrix.ci'].includes(serverName)||!Number.isInteger(challengeMs)||challengeMs<1000||challengeMs>60000||!Number.isInteger(maxSessionMs)||maxSessionMs<30000||maxSessionMs>3600000||!Number.isInteger(maxChallenges)||maxChallenges<1||maxChallenges>1024||!store||typeof getDevice!=='function'||!['ensureAccount','login','whoami','listDevices','revoke'].every(m=>typeof issuer?.[m]==='function')))fail('bridge_config_invalid');
 }
 _serial(fn){const run=this.queue.then(fn);this.queue=run.catch(()=>{});return run;}
 async _device(deviceId,peerId){
  if(!this.enabled)fail('matrix_disabled');
  if(!ID.test(deviceId||'')||!PEER.test(peerId||'')||!this.allowed.has(deviceId))fail('device_not_allowed');
  const d=await this.getDevice(deviceId);
  if(!d||d.deviceId!==deviceId||d.peerId!==peerId)fail('device_not_enrolled');
  let fingerprint;try{fingerprint=fingerprintSpki(d.publicKeySpkiB64);await importP256PublicKey(d.publicKeySpkiB64);}catch{fail('device_key_invalid');}
  if(d.fingerprint!==fingerprint)fail('device_key_invalid');
  return {deviceId,peerId,fingerprint,publicKeySpkiB64:d.publicKeySpkiB64};
 }
 async challenge({deviceId,peerId}={}){
  const d=await this._device(deviceId,peerId);
  const blocked=await this.store.transaction(data=>data.mappings[deviceId]?.status==='blocked'||data.mappings[deviceId]?.status==='revoked');
  if(blocked)fail('device_blocked');
  const now=this.now();for(const [id,c] of this.challenges)if(c.expiresAt<=now)this.challenges.delete(id);
  if(this.challenges.size>=this.maxChallenges)fail('challenge_capacity');
  const challengeId=token(),nonce=token(),expiresAt=now+this.challengeMs;
  const challengeText=['direct-matrix-auth-v1',challengeId,nonce,deviceId,peerId,d.fingerprint].join('\n');
  this.challenges.set(challengeId,{...d,challengeText,expiresAt});return {challengeId,challengeText,expiresAt};
 }
 async grant(request={}){
  if(!this.enabled)fail('matrix_disabled');
  const {deviceId,peerId,challengeId,signature}=request;
  const c=this.challenges.get(challengeId);this.challenges.delete(challengeId); // consume before any await
  if(!c||c.expiresAt<=this.now())fail('challenge_expired');
  if(c.deviceId!==deviceId||c.peerId!==peerId)fail('challenge_binding');
  const d=await this._device(deviceId,peerId);
  if(d.fingerprint!==c.fingerprint)fail('device_key_changed');
  let verified=false;try{verified=await verifyEcdsaSignature(await importP256PublicKey(d.publicKeySpkiB64),c.challengeText,signature);}catch{}
  if(!verified)fail('invalid_signature');
  return this._serial(async()=>{
   const current=await this._device(deviceId,peerId);if(current.fingerprint!==d.fingerprint)fail('device_key_changed');
   // Durable intent BEFORE provisioning/login. Crash retry reuses user/device/password.
   const selected=await this.store.transaction(data=>{
    let m=Object.hasOwn(data.mappings,deviceId)?data.mappings[deviceId]:null;
    if(m&&(m.status==='blocked'||m.status==='revoked'))return {error:'device_blocked'};
    if(m&&(m.peerId!==peerId||m.fingerprint!==d.fingerprint))return {error:'mapping_identity_changed'};
    if(m&&(m.deviceId!==deviceId||!['pending','active'].includes(m.status)||!new RegExp('^@pilot_[0-9a-f]{32}:'+this.serverName.replaceAll('.','\\.')+'$').test(m.userId)||!/^PILOT_[0-9a-f]{32}$/.test(m.matrixDeviceId)||!/^[-_A-Za-z0-9]{32}$/.test(m.password)))return {error:'mapping_corrupt'};
    if(!m){if(Object.values(data.mappings).filter(x=>x.status!=='revoked').length>=2)return {error:'device_capacity'};
     m={deviceId,peerId,fingerprint:d.fingerprint,userId:'@pilot_'+randomBytes(16).toString('hex')+':'+this.serverName,matrixDeviceId:'PILOT_'+randomBytes(16).toString('hex'),password:token(),status:'pending',cleanupPending:false};data.mappings[deviceId]=m;
    }return {mapping:structuredClone(m)};
   });if(selected.error)fail(selected.error);const m=selected.mapping;
   try{
    await this.issuer.ensureAccount(m);
    const loginStartedAt=this.now();
    const login=await this.issuer.login(m);
    if(typeof login?.access_token!=='string'||!login.access_token||login.user_id!==m.userId||login.device_id!==m.matrixDeviceId||!Number.isInteger(login.expires_in_ms)||login.expires_in_ms<=0||login.expires_in_ms>this.maxSessionMs)throw new BridgeError('matrix_session_binding');
    const who=await this.issuer.whoami(login.access_token);
    const devices=await this.issuer.listDevices(login.access_token);
    if(who?.user_id!==m.userId||who.device_id!==m.matrixDeviceId||!Array.isArray(devices)||devices.length!==1||devices[0].device_id!==m.matrixDeviceId)throw new BridgeError('matrix_device_binding');
    const after=await this._device(deviceId,peerId);if(after.fingerprint!==d.fingerprint)throw new BridgeError('device_key_changed');
    const expiresAt=loginStartedAt+login.expires_in_ms;if(expiresAt<=this.now())throw new BridgeError('matrix_session_expired');
    await this.store.transaction(data=>{data.mappings[deviceId].status='active';});
    if(expiresAt<=this.now())throw new BridgeError('matrix_session_expired');
    return {userId:m.userId,deviceId:m.matrixDeviceId,accessToken:login.access_token,expiresAt,keyVerified:false};
   }catch{
    // Quarantine before cleanup; failed cleanup stays durable and grants remain blocked.
    await this._quarantine(m);fail('matrix_session_rejected');
   }
  });
 }
 async _quarantine(m){
  await this.store.transaction(data=>{const x=data.mappings[m.deviceId];if(x){x.status='blocked';x.cleanupPending=true;}});
  try{await this.issuer.revoke(m);await this.store.transaction(data=>{const x=data.mappings[m.deviceId];x.status='revoked';x.cleanupPending=false;delete x.password;});}catch{}
 }
 // INTERNAL operator/revocation hook only. Never expose as unauthenticated client route.
 async revoke(deviceId){if(!this.enabled)fail('matrix_disabled');return this._serial(async()=>{
  if(!ID.test(deviceId||'')||!this.allowed.has(deviceId))fail('device_not_allowed');
  for(const [id,c] of this.challenges)if(c.deviceId===deviceId)this.challenges.delete(id);
  const m=await this.store.transaction(data=>{let x=data.mappings[deviceId];
   if(!x){data.mappings[deviceId]={deviceId,status:'revoked',cleanupPending:false};return null;}
   if(x.status==='revoked'&&!x.cleanupPending)return null;
   x.status='blocked';x.cleanupPending=true;return structuredClone(x);});
  if(!m)return {revoked:true,cleanupPending:false};
  try{await this.issuer.revoke(m);await this.store.transaction(data=>{const x=data.mappings[deviceId];x.status='revoked';x.cleanupPending=false;delete x.password;});return {revoked:true,cleanupPending:false};}
  catch{return {revoked:false,cleanupPending:true};}
 });}
}
