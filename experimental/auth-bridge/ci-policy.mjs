import {webcrypto,randomBytes,createHmac} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
import {execFileSync} from 'node:child_process';
import {waitForServer} from '../../infra/ncp/matrix-lab/ci/readiness.mjs';
import {Store} from '../../infra/ncp/auth/src/store.js';
import {fingerprintSpki} from '../../infra/ncp/auth/src/crypto.js';
import {BridgeStore} from './store.mjs';
import {MatrixAdmissionBroker} from './broker.mjs';
import {SynapseLabIssuer} from './synapse-lab-issuer.mjs';
import {RevocationCoordinator} from './lifecycle.mjs';
import {createLabClientIngress} from './client-ingress.mjs';
if(process.env.GITHUB_ACTIONS!=='true')throw new Error('ci_only');
let stage='readiness',ingress;const gates=[];const assert=v=>{if(!v)throw new Error('gate_failed');};
try{
 const ci=new URL('../../infra/ncp/matrix-lab/ci/',import.meta.url),base=await waitForServer(fileURLToPath(ci));
 const api=async(p,method='GET',body,token)=>{const r=await fetch(base+p,{method,redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});if(!r.ok)throw new Error('http_gate');return r.json();};
 const countRows=userId=>JSON.parse(execFileSync('docker',['compose','-f',fileURLToPath(new URL('compose.yaml',ci)),'exec','-T','synapse','python','/gate/count_auth_rows.py'],{input:JSON.stringify({user_id:userId}),encoding:'utf8',timeout:10000,stdio:['pipe','pipe','ignore']}));
 stage='synthetic operator';const secret=(await readFile(new URL('runtime/registration.secret',ci),'utf8')).trim();const {nonce}=await api('/_synapse/admin/v1/register');const username='ci_bridge_operator',password=randomBytes(32).toString('hex');const mac=createHmac('sha1',secret).update([nonce,username,password,'admin'].join('\0')).digest('hex');
 await api('/_synapse/admin/v1/register','POST',{nonce,username,password,admin:true,inhibit_login:true,mac});const operator=await api('/_matrix/client/v3/login','POST',{type:'m.login.password',identifier:{type:'m.id.user',user:username},password,device_id:'CI_OPERATOR'});
 const issuer=new SynapseLabIssuer({baseUrl:base,adminToken:operator.access_token});
 const enrolment=new Store(fileURLToPath(new URL('runtime/enrolment.json',ci))),mappings=new BridgeStore(fileURLToPath(new URL('runtime/bridge-private.json',ci))),intents=new BridgeStore(fileURLToPath(new URL('runtime/revocation-intents.json',ci)));
 const ids=['DEVICE_CI_ALICE_000000000000','DEVICE_CI_BOB_00000000000000'],keys=new Map();
 let lifecycle=new RevocationCoordinator({intents,enrollment:enrolment,allowedDeviceIds:ids});await lifecycle.initialize();
 stage='existing invitation enrollment';for(const [index,id] of ids.entries()){
  const key=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);keys.set(id,key.privateKey);
  const publicKeySpkiB64=Buffer.from(await webcrypto.subtle.exportKey('spki',key.publicKey)).toString('base64url');const peerId=index===0?'ci-peer-alice':'ci-peer-bob';
  const invitation=await enrolment.createInvite(1800000,{numeric:true});assert(/^\d{8}$/.test(invitation.inviteCode));assert((await enrolment.registerDevice(invitation.inviteCode,peerId,{deviceId:id,peerId,publicKeySpkiB64,fingerprint:fingerprintSpki(publicKeySpkiB64),createdAt:new Date().toISOString()})).ok);
  assert(!(await enrolment.registerDevice(invitation.inviteCode,peerId,{deviceId:id,peerId})).ok);
 }gates.push('original-store-numeric-single-use-enrollment');
 const options={enabled:true,store:mappings,getDevice:id=>lifecycle.getDevice(id),issuer,allowedDeviceIds:ids,serverName:'matrix.ci',maxSessionMs:600000};
 let broker=new MatrixAdmissionBroker(options);
 const prove=async id=>{const d=await enrolment.getDevice(id);const c=await broker.challenge({deviceId:id,peerId:d.peerId});const signature=Buffer.from(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.get(id),Buffer.from(c.challengeText))).toString('base64url');return {deviceId:id,peerId:d.peerId,challengeId:c.challengeId,signature};};
 stage='signed fixed-device sessions';const proof=await prove(ids[0]),first=await broker.grant(proof),secondUser=await broker.grant(await prove(ids[1]));assert(first.keyVerified===false&&first.expiresAt>Date.now());assert(first.userId!==secondUser.userId&&first.deviceId!==secondUser.deviceId);gates.push('p256-signed-fixed-device-expiring-sessions');
 stage='replay rejection';let rejected=false;try{await broker.grant(proof);}catch(e){rejected=e.code==='challenge_expired';}assert(rejected);gates.push('challenge-replay-rejected');
 stage='restart same device';lifecycle=new RevocationCoordinator({intents:new BridgeStore(intents.file),enrollment:enrolment,allowedDeviceIds:ids});await lifecycle.initialize();broker=new MatrixAdmissionBroker({...options,store:new BridgeStore(mappings.file)});const repeated=await broker.grant(await prove(ids[0]));assert(first.userId===repeated.userId&&first.deviceId===repeated.deviceId);assert((await issuer.listDevices(repeated.accessToken)).length===1);gates.push('broker-and-coordinator-restart-fixed-device');
 stage='ordinary account response';assert((await api('/_synapse/admin/v2/users/'+encodeURIComponent(repeated.userId),'GET',undefined,operator.access_token)).admin===false);assert(!('password' in repeated));gates.push('ordinary-account-no-password-response');
 stage='native pre-persistence login rejection';const stored=await mappings.transaction(d=>structuredClone(d.mappings[ids[0]]));const before=countRows(stored.userId);
 for(const device of ['CI_UNEXPECTED_DEVICE',null]){const body={type:'m.login.password',identifier:{type:'m.id.user',user:stored.userId},password:stored.password,...(device?{device_id:device}:{})};const r=await fetch(base+'/_matrix/client/v3/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});assert(r.status===403);await r.body?.cancel();}
 assert(JSON.stringify(before)===JSON.stringify(countRows(stored.userId)));gates.push('native-new-or-missing-device-login-denied-before-device-token-rows');
 stage='client ingress current lease';ingress=createLabClientIngress({enabled:true,upstreamBase:base,resolveSession:async token=>{try{return await broker.resolveSession(token,await issuer.whoami(token));}catch{return null;}}});ingress.listen(0,'127.0.0.1');await once(ingress,'listening');const front='http://127.0.0.1:'+ingress.address().port;
 const check=async(token,status)=>{const r=await fetch(front+'/_matrix/client/v3/account/whoami',{headers:{Authorization:'Bearer '+token}});assert(r.status===status);await r.body?.cancel();};
 await check(repeated.accessToken,200);await check(first.accessToken,401);assert((await issuer.whoami(first.accessToken)).device_id===first.deviceId);gates.push('latest-lease-only-old-private-native-token-not-publicly-usable');
 stage='public creation path rejection';const deniedPaths=[['POST','/_matrix/client/v3/login'],['POST','/_matrix/client/r0/login'],['POST','/_matrix/client/v3/register'],['POST','/_matrix/client/v3/refresh'],['POST','/_matrix/client/v1/login/get_token'],['PUT','/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device'],['PUT','/_matrix/client/unstable/org.matrix.msc2697.v2/dehydrated_device'],['POST','/_synapse/admin/v1/users/'+encodeURIComponent(stored.userId)+'/login'],['PUT','/_matrix/client/v3/devices/CI_EXTRA']];
 const countsBefore=countRows(stored.userId);for(const [method,p] of deniedPaths){const r=await fetch(front+p,{method,headers:{Authorization:'Bearer '+repeated.accessToken,'Content-Type':'application/json'},body:'{}'});assert(r.status===403);await r.body?.cancel();}assert(JSON.stringify(countsBefore)===JSON.stringify(countRows(stored.userId)));gates.push('all-tested-public-session-device-mutation-paths-denied-with-no-new-auth-rows');
 stage='coordinated enrollment and Matrix revoke';assert((await lifecycle.revokeDevice(ids[0],broker)).revoked);await check(repeated.accessToken,401);const revoked=await fetch(base+'/_matrix/client/v3/account/whoami',{headers:{Authorization:'Bearer '+repeated.accessToken}});assert(revoked.status===401);gates.push('coordinated-revoke-public-and-native-access-denied');
 stage='remote cleanup failure durable denial';const nativeRevoke=issuer.revoke.bind(issuer);issuer.revoke=async()=>{throw new Error('synthetic-failure');};const result=await lifecycle.revokeDevice(ids[1],broker);assert(result.cleanupPending&&!result.revoked);await check(secondUser.accessToken,401);assert((await issuer.whoami(secondUser.accessToken)).device_id===secondUser.deviceId);
 lifecycle=new RevocationCoordinator({intents:new BridgeStore(intents.file),enrollment:enrolment,allowedDeviceIds:ids});await lifecycle.initialize();broker=new MatrixAdmissionBroker({...options,store:new BridgeStore(mappings.file)});await check(secondUser.accessToken,401);issuer.revoke=nativeRevoke;assert((await lifecycle.retryPending(broker))[0].revoked);const final=await fetch(base+'/_matrix/client/v3/account/whoami',{headers:{Authorization:'Bearer '+secondUser.accessToken}});assert(final.status===401);gates.push('failed-cleanup-denied-after-restart-and-private-retry-invalidates-native-token');
 console.log(JSON.stringify({status:'passed',gates,productionIntegration:false,scope:'private backend + supported pre-login gate + read-only staging ingress; NOT full SDK/message integration',nativeOldTokens:'may stay privately valid until expiry; latest lease required at ingress',cryptoVerification:'SAS, actual message cold reopen and Android remain separate gates'}));
}catch{console.error('FAIL: '+stage+'. Sensitive details suppressed.');process.exitCode=1;}
finally{if(ingress){ingress.closeAllConnections();await new Promise(resolve=>ingress.close(resolve));}}
