import {webcrypto,randomBytes,createHmac} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {waitForServer} from '../../infra/ncp/matrix-lab/ci/readiness.mjs';
import {Store} from '../../infra/ncp/auth/src/store.js';
import {fingerprintSpki} from '../../infra/ncp/auth/src/crypto.js';
import {BridgeStore} from './store.mjs';
import {MatrixAdmissionBroker} from './broker.mjs';
import {SynapseLabIssuer} from './synapse-lab-issuer.mjs';
if(process.env.GITHUB_ACTIONS!=='true')throw new Error('ci_only');
let stage='readiness';const gates=[];const assert=v=>{if(!v)throw new Error('gate_failed');};
try{
 const ci=new URL('../../infra/ncp/matrix-lab/ci/',import.meta.url),base=await waitForServer(fileURLToPath(ci));
 const api=async(p,method='GET',body,token)=>{const r=await fetch(base+p,{method,redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});if(!r.ok)throw new Error('http_gate');return r.json();};
 stage='synthetic operator';const secret=(await readFile(new URL('runtime/registration.secret',ci),'utf8')).trim();const {nonce}=await api('/_synapse/admin/v1/register');const username='ci_bridge_operator',password=randomBytes(32).toString('hex');const mac=createHmac('sha1',secret).update([nonce,username,password,'admin'].join('\0')).digest('hex');
 await api('/_synapse/admin/v1/register','POST',{nonce,username,password,admin:true,inhibit_login:true,mac});const operator=await api('/_matrix/client/v3/login','POST',{type:'m.login.password',identifier:{type:'m.id.user',user:username},password,device_id:'CI_OPERATOR'});
 const issuer=new SynapseLabIssuer({baseUrl:base,adminToken:operator.access_token});
 const enrolment=new Store(fileURLToPath(new URL('runtime/enrolment.json',ci)));const mappings=new BridgeStore(fileURLToPath(new URL('runtime/bridge-private.json',ci)));
 const ids=['DEVICE_CI_ALICE_000000000000','DEVICE_CI_BOB_00000000000000'],keys=new Map();
 stage='existing invitation enrollment';for(const [index,id] of ids.entries()){
  const key=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);keys.set(id,key.privateKey);
  const publicKeySpkiB64=Buffer.from(await webcrypto.subtle.exportKey('spki',key.publicKey)).toString('base64url');const peerId=index===0?'ci-peer-alice':'ci-peer-bob';
  const invitation=await enrolment.createInvite(1800000,{numeric:true});assert(/^\d{8}$/.test(invitation.inviteCode));assert((await enrolment.registerDevice(invitation.inviteCode,peerId,{deviceId:id,peerId,publicKeySpkiB64,fingerprint:fingerprintSpki(publicKeySpkiB64),createdAt:new Date().toISOString()})).ok);
  assert(!(await enrolment.registerDevice(invitation.inviteCode,peerId,{deviceId:id,peerId})).ok);
 }gates.push('original-store-numeric-single-use-enrollment');
 const options={enabled:true,store:mappings,getDevice:id=>enrolment.getDevice(id),issuer,allowedDeviceIds:ids,serverName:'matrix.ci',maxSessionMs:600000};
 let broker=new MatrixAdmissionBroker(options);
 const prove=async id=>{const d=await enrolment.getDevice(id);const c=await broker.challenge({deviceId:id,peerId:d.peerId});const signature=Buffer.from(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.get(id),Buffer.from(c.challengeText))).toString('base64url');return {deviceId:id,peerId:d.peerId,challengeId:c.challengeId,signature};};
 stage='signed fixed-device sessions';const proof=await prove(ids[0]);const first=await broker.grant(proof);assert(first.keyVerified===false&&first.expiresAt>Date.now());const secondUser=await broker.grant(await prove(ids[1]));assert(first.userId!==secondUser.userId&&first.deviceId!==secondUser.deviceId);gates.push('p256-signed-device-bound-expiring-sessions');
 stage='replay rejection';let rejected=false;try{await broker.grant(proof);}catch(e){rejected=e.code==='challenge_expired';}assert(rejected);gates.push('challenge-replay-rejected');
 stage='restart same device';broker=new MatrixAdmissionBroker({...options,store:new BridgeStore(mappings.file)});const repeated=await broker.grant(await prove(ids[0]));assert(first.userId===repeated.userId&&first.deviceId===repeated.deviceId);assert((await issuer.listDevices(repeated.accessToken)).length===1);gates.push('broker-restart-fixed-user-and-one-device');
 stage='ordinary account and response secrecy';for(const r of [repeated,secondUser]){assert((await api('/_synapse/admin/v2/users/'+encodeURIComponent(r.userId),'GET',undefined,operator.access_token)).admin===false);assert(!('password' in r)&&!('refreshToken' in r));}gates.push('ordinary-accounts-no-provisioning-password-response');
 stage='extra device reactive quarantine';const stored=await mappings.transaction(d=>structuredClone(d.mappings[ids[0]]));const extra=await api('/_matrix/client/v3/login','POST',{type:'m.login.password',identifier:{type:'m.id.user',user:stored.userId},password:stored.password,device_id:'CI_UNEXPECTED_DEVICE'});assert((await issuer.listDevices(repeated.accessToken)).length===2);
 rejected=false;try{await broker.grant(await prove(ids[0]));}catch(e){rejected=e.code==='matrix_session_rejected';}assert(rejected);
 for(const token of [first.accessToken,repeated.accessToken,extra.access_token]){const r=await fetch(base+'/_matrix/client/v3/account/whoami',{headers:{Authorization:'Bearer '+token}});assert(r.status===401);}gates.push('unexpected-device-detected-and-all-account-tokens-invalidated');
 stage='enrollment and Matrix revocation';await enrolment.revokeDevice(ids[1]);assert((await broker.revoke(ids[1])).revoked);const revoked=await fetch(base+'/_matrix/client/v3/account/whoami',{headers:{Authorization:'Bearer '+secondUser.accessToken}});assert(revoked.status===401);gates.push('enrollment-revoke-matrix-session-invalidated');
 console.log(JSON.stringify({status:'passed',gates,productionIntegration:false,devicePrevention:'reactive detection only; direct Matrix extra-session prevention NOT implemented',cryptoVerification:'NOT automatic; SAS and message cold reopen remain separate gates'}));
}catch{console.error('FAIL: '+stage+'. Sensitive details suppressed.');process.exitCode=1;}
