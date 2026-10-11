// CI-only composition. No credential/SDK error logs, screenshots or browser traces.
import {chromium} from '@playwright/test';
import {webcrypto,randomBytes,createHmac} from 'node:crypto';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';import {once} from 'node:events';
import {waitForServer} from '../../infra/ncp/matrix-lab/ci/readiness.mjs';
import {Store} from '../../infra/ncp/auth/src/store.js';import {fingerprintSpki} from '../../infra/ncp/auth/src/crypto.js';
import {BridgeStore} from '../auth-bridge/store.mjs';import {MatrixAdmissionBroker} from '../auth-bridge/broker.mjs';import {RevocationCoordinator} from '../auth-bridge/lifecycle.mjs';
import {SynapseLabIssuer} from '../auth-bridge/synapse-lab-issuer.mjs';import {SdkBindingRegistry} from '../auth-bridge/sdk-binding.mjs';import {createSdkIngress} from '../auth-bridge/sdk-ingress.mjs';
if(process.env.GITHUB_ACTIONS!=='true')throw new Error('ci_only');
import {encryptStream} from '../media-transfer-lab/attachment-stream.mjs';
import {createHash} from 'node:crypto';
// Small generated test bytes only. No key/plaintext/descriptor files or logs.
const fileFixture=await(async()=>{
 const plain=Uint8Array.from({length:4096},(_,i)=>(i*17+11)&255),chunks=[];
 const expectedDigest=createHash('sha256').update(plain).digest('base64').replace(/=+$/,'');
 async function* source(){yield plain;}
 try{
  const encrypted=await encryptStream({source:source(),authorize:async()=>true,maxBytes:4096,chunkBytes:4096,writeCiphertext:async b=>chunks.push(Buffer.from(b))});
  return {descriptor:encrypted.descriptor,ciphertext:Buffer.concat(chunks),expectedDigest};
 }finally{plain.fill(0);}
})();
const descriptorGates=[];

import {prepareTransportFixture,attachTransportReceiver} from './transport-pipeline.mjs';
import {validateDescriptor} from '../media-transfer-lab/attachment-stream.mjs';
const transportFixtures=new Set(),transportGates=[];
// CDP structured clones lose freezing; detach/canonicalize/freeze the SDK reply.
const sealTransportReceipt=r=>Object.freeze({...r,descriptor:validateDescriptor(r.descriptor)});
async function assertTransportPreserved(session){const p=await session.checkPreserved();assert(p.sourcePreserved===true&&p.receiverPreserved===true&&p.quarantineEmpty===true);return true;}

const ci=fileURLToPath(new URL('../../infra/ncp/matrix-lab/ci/',import.meta.url)),gates=[],contexts=new Set(),profiles=[];let stage='readiness',base,front,ingress;
const assert=v=>{if(!v)throw new Error('gate_failed');};
async function api(route,method='GET',body,token){const r=await fetch(base+route,{method,redirect:'error',signal:AbortSignal.timeout(30000),headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});if(!r.ok)throw new Error('private_api_failed');return r.json();}
const call=(actor,op,args)=>actor.page.evaluate(({op,args})=>window.lab[op](args),{op,args});
const close=async actor=>{const browser=actor.context.browser();await actor.context.close();assert(browser&&!browser.isConnected());contexts.delete(actor.context);};
let mappings,enrollment,lifecycle,broker,issuer,registry,ids,keys;
const prove=async id=>{const d=await enrollment.getDevice(id),c=await broker.challenge({deviceId:id,peerId:d.peerId});return {deviceId:id,peerId:d.peerId,challengeId:c.challengeId,signature:Buffer.from(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.get(id),Buffer.from(c.challengeText))).toString('base64url')};};
const renew=async id=>broker.grant(await prove(id));
const resolve=async token=>{try{return await broker.resolveSession(token,await issuer.whoami(token));}catch{return null;}};
async function binding(){const b=await registry.read();for(const d of b.devices)d.active=Boolean(await lifecycle.getDevice(d.deviceId));return b;}
async function launch(profile,session,{defer=false}={}){const context=await chromium.launchPersistentContext(profile,{headless:true,serviceWorkers:'block'});contexts.add(context);const actor={context,page:await context.newPage(),setup:false,session};
 await context.route('http://127.0.0.1:18008/**',async route=>{try{const req=route.request(),url=new URL(req.url());assert(url.origin==='http://127.0.0.1:18008');const cors={'access-control-allow-origin':'http://127.0.0.1:19461','access-control-allow-methods':'GET,POST,PUT,OPTIONS','access-control-allow-headers':'authorization,content-type'};if(req.method()==='OPTIONS'){await route.fulfill({status:204,headers:cors});return;}
 // Temporary private setup capability is enabled ONLY by this trusted driver for
 // first-profile owner signing, never reauthentication/reopen or arbitrary callers.
 const privateSetup=actor.setup&&req.method()==='POST'&&['/_matrix/client/v3/keys/device_signing/upload','/_matrix/client/unstable/keys/device_signing/upload','/_matrix/client/v3/keys/signatures/upload'].includes(url.pathname)&&!url.search;
 const target=(privateSetup?base:front)+url.pathname+url.search;let body=req.postData();
 // SDK43 emits the device upload BEFORE publishing its new owner signing keys.
 // During private first-owner setup only, drop unpinned additional signatures.
 // The normal ingress still verifies the mandatory approved device Ed25519 signature.
 if(actor.setup&&req.method()==='POST'&&url.pathname==='/_matrix/client/v3/keys/upload'&&body){const p=JSON.parse(body),d=p.device_keys;if(d){const sig=d.signatures?.[session.userId]?.['ed25519:'+session.deviceId];assert(typeof sig==='string');d.signatures={[session.userId]:{['ed25519:'+session.deviceId]:sig}};body=JSON.stringify(p);}}
 if(privateSetup){assert(req.headers().authorization==='Bearer '+session.accessToken);const parsed=JSON.parse(body);if(parsed.master_key||parsed.self_signing_key||parsed.user_signing_key){for(const name of ['master_key','self_signing_key','user_signing_key'])if(parsed[name])assert(parsed[name].user_id===session.userId);}}
 let r=await fetch(target,{method:req.method(),redirect:'error',headers:{'Content-Type':'application/json',...(req.headers().authorization?{Authorization:req.headers().authorization}:{})},...(body?{body}:{}),signal:AbortSignal.timeout(65000)});
 if(privateSetup&&r.status===401&&url.pathname.endsWith('device_signing/upload')){const challenge=await r.json(),stored=await mappings.transaction(d=>structuredClone(d.mappings[session.legacyId]));assert(typeof challenge.session==='string');body=JSON.stringify({...JSON.parse(body),auth:{type:'m.login.password',session:challenge.session,identifier:{type:'m.id.user',user:session.userId},password:stored.password}});r=await fetch(target,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+session.accessToken},body,signal:AbortSignal.timeout(30000)});}
 if(privateSetup)console.log(JSON.stringify({ownerSetup:{kind:url.pathname.includes('device_signing')?'signing':'signature',status:r.status}}));
 if(privateSetup&&r.ok&&url.pathname.endsWith('device_signing/upload')){const uid=session.userId,q=JSON.parse(req.postData());assert(q.master_key&&q.self_signing_key&&q.user_signing_key);await registry.change(d=>{d.ownerSigning??={};d.ownerSigning[uid]={master:q.master_key,selfSigning:q.self_signing_key,userSigning:q.user_signing_key};});}
 if(!r.ok&&url.pathname.includes('/sendToDevice/')){const m=JSON.parse(req.postData()||'{}').messages,cs=m?Object.values(m).flatMap(v=>Object.values(v)):[];for(const c of cs){const known=['from_device','methods','timestamp','transaction_id','org.matrix.msgid','method','key_agreement_protocols','hashes','message_authentication_codes','short_authentication_string','key_agreement_protocol','hash','message_authentication_code','commitment','key','mac','keys','code','reason','algorithm','sender_key','ciphertext'];console.log(JSON.stringify({toDeviceSchema:{fields:Object.keys(c).filter(k=>known.includes(k)),unknownFields:Object.keys(c).some(k=>!known.includes(k)),ownDeviceMatches:c.from_device===session.deviceId,sasOnly:Array.isArray(c.methods)&&c.methods.every(x=>x==='m.sas.v1'),transactionSafe:typeof c.transaction_id==='string'&&c.transaction_id.length<=128&&!/[\x00-\x1f\x7f]/.test(c.transaction_id),macNames:Array.isArray(c.message_authentication_codes)?c.message_authentication_codes.filter(x=>['hkdf-hmac-sha256.v2','org.matrix.msc3783.hkdf-hmac-sha256','hkdf-hmac-sha256'].includes(x)):[],unknownMacs:Array.isArray(c.message_authentication_codes)&&c.message_authentication_codes.some(x=>!['hkdf-hmac-sha256.v2','org.matrix.msc3783.hkdf-hmac-sha256','hkdf-hmac-sha256'].includes(x)),timestampSafe:Number.isSafeInteger(c.timestamp)}}));}}
 if(!r.ok&&!privateSetup)console.log(JSON.stringify({ingressDiagnostic:{status:r.status,route:url.pathname.split('/').map(x=>['','_matrix','client','v3','r0','unstable','versions','keys','upload','signatures','device_signing','room_keys','version','user','account_data','capabilities','pushrules','filter','devices','profile','rooms','state'].includes(x)?x:'<redacted>').join('/'),kind:url.pathname.includes('device_signing')?'owner-key-upload':url.pathname.includes('/signatures/upload')?'signature-upload':url.pathname.endsWith('/keys/upload')?'device-key-upload':url.pathname.includes('sendToDevice')?'to-device':url.pathname.includes('/keys/')?'other-keys':url.pathname.endsWith('/sync')?'sync':url.pathname.includes('/filter')?'filter':url.pathname.includes('/account_data/')?'account-data':url.pathname.includes('/devices/')?'device-info':url.pathname.includes('/state/')?'keyed-state':'other',version:url.pathname.includes('/unstable/')?'unstable':url.pathname.includes('/r0/')?'r0':'v3'}}));
 await route.fulfill({status:r.status,body:Buffer.from(await r.arrayBuffer()),headers:{...cors,'content-type':'application/json'}});
 }catch{if(actor.setup)console.log('FIXTURE: private owner setup transport failed; details suppressed.');await route.abort().catch(()=>{});}});
 await actor.page.goto('http://127.0.0.1:19461/transport.html');await actor.page.waitForFunction(()=>Boolean(window.lab));await call(actor,'start',{user_id:session.userId,device_id:session.deviceId,access_token:session.accessToken,deferSync:defer});return actor;}
async function check(token,method,route,body,status){const r=await fetch(front+route,{method,headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},...(body?{body:JSON.stringify(body)}:{})});assert(r.status===status);await r.body?.cancel();}
const deadline=setTimeout(()=>{console.error('FAIL: bounded composed deadline. Sensitive details suppressed.');process.exit(1);},600000);
try{
 base=await waitForServer(ci);stage='private operator';const secret=(await readFile(path.join(ci,'runtime/registration.secret'),'utf8')).trim(),{nonce}=await api('/_synapse/admin/v1/register'),password=randomBytes(32).toString('hex'),name='ci_bridge_operator',mac=createHmac('sha1',secret).update([nonce,name,password,'admin'].join('\0')).digest('hex');await api('/_synapse/admin/v1/register','POST',{nonce,username:name,password,admin:true,inhibit_login:true,mac});const operator=await api('/_matrix/client/v3/login','POST',{type:'m.login.password',identifier:{type:'m.id.user',user:name},password,device_id:'CI_OPERATOR'});
 issuer=new SynapseLabIssuer({baseUrl:base,adminToken:operator.access_token});enrollment=new Store(path.join(ci,'runtime/enrolment.json'));mappings=new BridgeStore(path.join(ci,'runtime/bridge-private.json'));ids=['DEVICE_CI_ALICE_000000000000','DEVICE_CI_BOB_00000000000000'];keys=new Map();const intents=new BridgeStore(path.join(ci,'runtime/revocation-intents.json'));lifecycle=new RevocationCoordinator({intents,enrollment,allowedDeviceIds:ids});await lifecycle.initialize();
 stage='signed enrolled device admission';for(const [i,id]of ids.entries()){const k=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);keys.set(id,k.privateKey);const pub=Buffer.from(await webcrypto.subtle.exportKey('spki',k.publicKey)).toString('base64url'),peerId='composed-peer-'+i,invite=await enrollment.createInvite(1800000,{numeric:true});assert((await enrollment.registerDevice(invite.inviteCode,peerId,{deviceId:id,peerId,publicKeySpkiB64:pub,fingerprint:fingerprintSpki(pub)})).ok);}
 const opts={enabled:true,store:mappings,getDevice:id=>lifecycle.getDevice(id),issuer,allowedDeviceIds:ids,serverName:'matrix.ci',maxSessionMs:600000};broker=new MatrixAdmissionBroker(opts);let a={...await renew(ids[0]),legacyId:ids[0]},b={...await renew(ids[1]),legacyId:ids[1]};assert(!a.keyVerified&&!b.keyVerified);gates.push('registered-P256-admission-latest-fixed-device-sessions');
 stage='private immutable two-user room';const created=await api('/_matrix/client/v3/createRoom','POST',{visibility:'private',preset:'private_chat',room_version:'12',invite:[b.userId],creation_content:{'m.federate':false},initial_state:[{type:'m.room.encryption',state_key:'',content:{algorithm:'m.megolm.v1.aes-sha2'}},{type:'m.room.history_visibility',state_key:'',content:{history_visibility:'joined'}},{type:'m.room.join_rules',state_key:'',content:{join_rule:'invite'}}],power_level_content_override:{users:{[b.userId]:0},users_default:0,redact:0,state_default:100,invite:100,kick:100,ban:100}},a.accessToken),room=created.room_id;await api('/_matrix/client/v3/join/'+encodeURIComponent(room),'POST',{},b.accessToken);
 stage='native non-federated room policy';const initialState=await api('/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/state','GET',undefined,a.accessToken);assert(initialState.find(e=>e.type==='m.room.create'&&e.state_key==='')?.content?.['m.federate']===false);
 registry=new SdkBindingRegistry({file:path.join(ci,'runtime/sdk-binding.json'),getDevice:id=>lifecycle.getDevice(id)});ingress=createSdkIngress({enabled:true,upstreamBase:base,resolveSession:resolve,getBinding:async()=>binding()});ingress.listen(0,'127.0.0.1');await once(ingress,'listening');front='http://127.0.0.1:'+ingress.address().port;
 const pa=await mkdtemp(path.join(tmpdir(),'composed-a-')),pb=await mkdtemp(path.join(tmpdir(),'composed-b-'));profiles.push(pa,pb);let alice=await launch(pa,a,{defer:true}),bob=await launch(pb,b,{defer:true});stage='P256 authorization of exact browser Matrix key pairs';const ak=await call(alice,'keys'),bk=await call(bob,'keys');for(const [session,pub]of [[a,ak],[b,bk]]){const challenge=await registry.challenge({deviceId:session.legacyId,userId:session.userId,matrixDeviceId:session.deviceId},pub),signature=Buffer.from(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.get(session.legacyId),Buffer.from(challenge.text))).toString('base64url');await registry.approve(challenge.id,signature);}await registry.bindRoom(room);gates.push('P256-approved-immutable-Matrix-Ed25519-and-Curve25519-pins');
 stage='all runtime SDK requests through bounded ingress';await Promise.all([call(alice,'resume'),call(bob,'resume')]);stage='controlled private owner bootstrap';for(const actor of [alice,bob]){actor.setup=true;try{await call(actor,'bootstrap',{});}finally{actor.setup=false;}const uid=actor.session.userId,r=await api('/_matrix/client/v3/keys/query','POST',{device_keys:{[uid]:[actor.session.deviceId]}},actor.session.accessToken);await registry.change(d=>{d.ownerSigning??={};const known=d.ownerSigning[uid];assert(known?.userSigning);d.ownerSigning[uid]={master:r.master_keys?.[uid]||known.master,selfSigning:r.self_signing_keys?.[uid]||known.selfSigning,userSigning:r.user_signing_keys?.[uid]||known.userSigning};});}
 stage='preprovisioned room binding';await Promise.all([call(alice,'bind',{room,peer:b.userId,device:b.deviceId}),call(bob,'bind',{room,peer:a.userId,device:a.deviceId})]);stage='explicit unverified peer trust gates';assert(await call(alice,'blocked'));assert(await call(bob,'blocked'));gates.push('preprovisioned-room-and-no-implicit-peer-trust');
 stage='descriptor pre-verification denied';assert(await call(alice,'descriptorPretrustDenied',{descriptor:fileFixture.descriptor}));descriptorGates.push('actual-unverified-peer-send-gate-denied');
 stage='real SAS over constrained ingress';await call(alice,'request',{peer:b.userId,device:b.deviceId});await call(bob,'requestReady');await call(bob,'accept');await call(alice,'ready');await call(alice,'beginSas');await call(bob,'verifierReady');await call(bob,'beginSas');assert(JSON.stringify(await call(alice,'sas'))===JSON.stringify(await call(bob,'sas')));await Promise.all([call(alice,'confirm'),call(bob,'confirm')]);await Promise.all([call(alice,'verified'),call(bob,'verified')]);gates.push('actual-SAS-and-signed-key-exchange-through-ingress');
 stage='public unauthorized mutation denial';for(const [method,p,body]of [['POST','/_matrix/client/v3/login',{}],['POST','/_matrix/client/v3/refresh',{}],['POST','/_matrix/client/v3/createRoom',{}],['POST','/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/invite',{user_id:'@unbound:matrix.ci'}],['PUT','/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/state/m.room.encryption',{}],['POST','/_matrix/client/v3/keys/query',{device_keys:{'@unbound:matrix.ci':[]}}],['PUT','/_matrix/client/v3/sendToDevice/m.key.verification.done/forbidden',{messages:{[b.userId]:{'*':{transaction_id:'forbidden'}}}}],['PUT','/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/send/m.room.message/plain',{msgtype:'m.text',body:'synthetic-forbidden'}]])await check(a.accessToken,method,p,body,403);gates.push('creation-invite-state-third-device-and-plaintext-paths-denied');
 stage='full recipient close encrypted offline delivery';await close(bob);const body='composed-offline-'+randomBytes(12).toString('hex'),event=await call(alice,'send',{body});const raw=await api('/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/event/'+encodeURIComponent(event),'GET',undefined,a.accessToken);assert(raw.type==='m.room.encrypted'&&!raw.content.body);stage='registered-device reauthentication then cold restore';const oldBob=b.accessToken;b={...await renew(ids[1]),legacyId:ids[1]};assert((await issuer.whoami(oldBob)).device_id===b.deviceId);await check(oldBob,'GET','/_matrix/client/v3/account/whoami',null,401);bob=await launch(pb,b);assert(JSON.stringify(await call(bob,'keys'))===JSON.stringify(bk));await call(bob,'bind',{room,peer:a.userId,device:a.deviceId});await call(bob,'verified');await call(bob,'receive',{event,body});gates.push('cold-browser-P256-reauth-current-lease-only-offline-decryption');
 // Inserted after actual cold-restore text proof, before original destructive tests.
stage='descriptor verified peer cold delivery';
await close(bob);
const fileEvent=await call(alice,'descriptorSend',{descriptor:fileFixture.descriptor});
const fileRaw=await api('/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/event/'+encodeURIComponent(fileEvent),'GET',undefined,a.accessToken);
assert(fileRaw.type==='m.room.encrypted'&&!fileRaw.content.file&&!fileRaw.content.body&&!JSON.stringify(fileRaw).includes(fileFixture.descriptor.key.k));
b={...await renew(ids[1]),legacyId:ids[1]};bob=await launch(pb,b);
assert(JSON.stringify(await call(bob,'keys'))===JSON.stringify(bk));
await call(bob,'bind',{room,peer:a.userId,device:a.deviceId});await call(bob,'verified');
const receivedFile=await call(bob,'descriptorReceive',{event:fileEvent,ciphertext:Array.from(fileFixture.ciphertext),expectedDigest:fileFixture.expectedDigest});
assert(receivedFile.sdkDerivedDescriptor&&receivedFile.wholeHashBeforeDecrypt&&receivedFile.plaintextDigestMatches&&receivedFile.textRendererExcluded&&receivedFile.fixtureBytes===4096);
descriptorGates.push('actual-SDK-Rust-decrypted-peer-descriptor-after-cold-reauth');
descriptorGates.push('SDK-derived-file-key-WebCrypto-plaintext-digest-and-hash-before-decrypt');
stage='descriptor corrupted ciphertext rejects before decrypt';
const corrupt=Array.from(fileFixture.ciphertext);corrupt[0]^=1;
const corruptedFile=await call(bob,'descriptorDenied',{event:fileEvent,ciphertext:corrupt,expectedDigest:fileFixture.expectedDigest,expectedError:'descriptor_ciphertext_hash_mismatch'});
assert(corruptedFile.rejected&&corruptedFile.noDecrypt&&corruptedFile.intendedEventState);descriptorGates.push('corrupted-ciphertext-no-decrypt');
stage='descriptor malformed actual encrypted event rejected';
const malformedEvent=await call(alice,'descriptorSend',{descriptor:fileFixture.descriptor,invalid:true});
const malformedRaw=await api('/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/event/'+encodeURIComponent(malformedEvent),'GET',undefined,a.accessToken);
assert(malformedRaw.type==='m.room.encrypted'&&!malformedRaw.content.file&&!malformedRaw.content.body);
const malformedFile=await call(bob,'descriptorDenied',{event:malformedEvent,ciphertext:Array.from(fileFixture.ciphertext),expectedDigest:fileFixture.expectedDigest,expectedError:'INVALID_DESCRIPTOR'});
assert(malformedFile.rejected&&malformedFile.noDecrypt&&malformedFile.intendedEventState);descriptorGates.push('malformed-actual-encrypted-descriptor-no-decrypt');
stage='descriptor actual redaction blocks subsequent use';
await call(bob,'remove',{event:fileEvent});await call(bob,'deleted',{event:fileEvent});
const redactedFile=await call(bob,'descriptorDenied',{event:fileEvent,ciphertext:Array.from(fileFixture.ciphertext),expectedDigest:fileFixture.expectedDigest,expectedError:'REDACTED'});
assert(redactedFile.rejected&&redactedFile.noDecrypt&&redactedFile.intendedEventState);descriptorGates.push('actual-target-redaction-no-decrypt');

 // Actual SDK control plane, private in-process ciphertext data plane; not MXC transport.
const transportAuthority=event=>async receipt=>{
 try{
  if(receipt.eventId!==event||receipt.roomId!==room||receipt.senderUserId!==a.userId||receipt.senderDeviceId!==a.deviceId)return false;
  const receiverSession=await resolve(b.accessToken),senderSession=await resolve(a.accessToken);
  if(!receiverSession||!senderSession||receiverSession.userId!==b.userId||receiverSession.matrixDeviceId!==b.deviceId||receiverSession.deviceId!==ids[1]||senderSession.userId!==a.userId||senderSession.matrixDeviceId!==a.deviceId||senderSession.deviceId!==ids[0])return false;
  const current=await binding();
  if(current.roomId!==room||current.devices.length!==2||current.devices.some(d=>!d.active)||!current.devices.some(d=>d.userId===b.userId&&d.matrixDeviceId===b.deviceId&&d.deviceId===ids[1])||!current.devices.some(d=>d.userId===a.userId&&d.matrixDeviceId===a.deviceId&&d.deviceId===ids[0]))return false;
  const sdk=await call(bob,'transportAuthorityStatus',{event});
  return sdk.allowed===true&&sdk.stage==='LIVE';
 }catch{return false;}
};
stage='authenticated transport resumed stream';
let activeFixture=await prepareTransportFixture(tmpdir());transportFixtures.add(activeFixture);
let transportEvent=await call(alice,'descriptorSend',{descriptor:activeFixture.descriptor});
let transportReceipt=sealTransportReceipt(await call(bob,'transportExport',{event:transportEvent}));
let transportSession=await attachTransportReceiver(activeFixture,transportReceipt,transportAuthority(transportEvent));
const resumedMetrics=await transportSession.completeResumedTransfer();
assert(resumedMetrics.restarted&&resumedMetrics.lostAckRepeated&&resumedMetrics.complete&&resumedMetrics.bytes===8388608&&resumedMetrics.chunkBytes===262144&&resumedMetrics.logicalPayloadCeiling===25165824);
const streamed=await transportSession.decrypt();
assert(streamed.bytes===8388608&&streamed.digestMatches&&streamed.plaintextCallbacks>0);
assert(await assertTransportPreserved(transportSession));
transportGates.push('actual-SDK-receipt-to-preserving-receiver-restart-retry-stream-decrypt');
transportGates.push('native-latest-two-session-and-active-registry-plus-SDK-rechecks');
stage='authenticated transport tampered source';
const tampered=await transportSession.denialProbe({expectedCode:'HASH_MISMATCH',corruptSource:true});
assert(tampered.code==='HASH_MISMATCH'&&tampered.plaintextCallbacks===0&&tampered.bytes===0&&await assertTransportPreserved(transportSession));
transportGates.push('tampered-stream-full-hash-denial-zero-plaintext-cache-preserved');
stage='authenticated transport actual descriptor redaction';
await call(bob,'remove',{event:transportEvent});await call(bob,'deleted',{event:transportEvent});
const beforeDeleteNative=await resolve(b.accessToken);assert(beforeDeleteNative&&await resolve(a.accessToken));
const deletedSdk=await call(bob,'transportAuthorityStatus',{event:transportEvent});assert(!deletedSdk.allowed&&deletedSdk.stage==='REDACTED');
const deletedTransport=await transportSession.denialProbe({expectedCode:'AUTHORIZATION_DENIED'});
assert(deletedTransport.code==='AUTHORIZATION_DENIED'&&deletedTransport.plaintextCallbacks===0&&deletedTransport.bytes===0&&await assertTransportPreserved(transportSession));
transportGates.push('actual-SDK-redaction-denies-node-stream-while-native-leases-active');
const firstTransportCleanup=await transportSession.cleanup();assert(firstTransportCleanup.namespacesRemoved&&firstTransportCleanup.receiverTombstoned&&firstTransportCleanup.physicalErasure===false);transportFixtures.delete(activeFixture);
stage='authenticated transport native revocation preparation';
activeFixture=await prepareTransportFixture(tmpdir());transportFixtures.add(activeFixture);
transportEvent=await call(alice,'descriptorSend',{descriptor:activeFixture.descriptor});
transportReceipt=sealTransportReceipt(await call(bob,'transportExport',{event:transportEvent}));
transportSession=await attachTransportReceiver(activeFixture,transportReceipt,transportAuthority(transportEvent));
await transportSession.completeResumedTransfer();
const preRevoke=await transportSession.decrypt();assert(preRevoke.bytes===8388608&&preRevoke.digestMatches);
assert(await assertTransportPreserved(transportSession));
// Kept until original coordinated-revocation stage; then exact cached-decrypt denial.

 stage='sender closed peer redaction through ingress';await close(alice);await call(bob,'remove',{event});a={...await renew(ids[0]),legacyId:ids[0]};alice=await launch(pa,a);assert(JSON.stringify(await call(alice,'keys'))===JSON.stringify(ak));await call(alice,'bind',{room,peer:b.userId,device:b.deviceId});await call(alice,'deleted',{event});gates.push('ordinary-peer-delete-and-cold-reopen-no-resurrection');
 stage='crypto-loss profile cannot replace approved keys';const pl=await mkdtemp(path.join(tmpdir(),'composed-lost-'));profiles.push(pl);const lost=await launch(pl,a,{defer:true});assert(JSON.stringify(await call(lost,'keys'))!==JSON.stringify(ak));await call(lost,'resume');await call(lost,'bind',{room,peer:b.userId,device:b.deviceId});assert(await call(lost,'blocked'));const preserved=await api('/_matrix/client/v3/keys/query','POST',{device_keys:{[a.userId]:[a.deviceId]}},a.accessToken);assert(preserved.device_keys[a.userId][a.deviceId].keys['ed25519:'+a.deviceId]===ak.ed25519&&preserved.device_keys[a.userId][a.deviceId].keys['curve25519:'+a.deviceId]===ak.curve25519);await close(lost);gates.push('lost-crypto-profile-untrusted-and-cannot-replace-native-device-pins');
 stage='coordinated revocation denies SDK access';assert((await lifecycle.revokeDevice(ids[1],broker)).revoked);await check(b.accessToken,'GET','/_matrix/client/v3/account/whoami',null,401);await check(a.accessToken,'PUT','/_matrix/client/v3/sendToDevice/m.key.verification.done/revoked',{messages:{[b.userId]:{[b.deviceId]:{transaction_id:'revoked'}}}},403);gates.push('coordinated-revoke-and-no-new-peer-key-delivery');
stage='authenticated transport actual native revoked lease';
assert(await resolve(b.accessToken)===null);
const revokedStream=await transportSession.denialProbe({expectedCode:'AUTHORIZATION_DENIED'});
assert(revokedStream.code==='AUTHORIZATION_DENIED'&&revokedStream.plaintextCallbacks===0&&revokedStream.bytes===0&&await assertTransportPreserved(transportSession));
transportGates.push('actual-native-revoked-current-lease-denies-cached-node-decryption');
const finalTransportCleanup=await transportSession.cleanup();
assert(finalTransportCleanup.namespacesRemoved&&finalTransportCleanup.receiverTombstoned&&finalTransportCleanup.physicalErasure===false);
transportFixtures.delete(activeFixture);

 console.log(JSON.stringify({status:'passed',gates,descriptorGates,transportGates,transportFixtureBytes:8388608,transportLogicalCeiling:25165824,transportChunkBytes:262144,actualSdkToNodeTransport:true,inProcessCiphertextDataPlane:true,descriptorFixtureBytes:4096,actualSdkDescriptor:true,mediaUpload:false,streamingBrowserFileTransfer:false,productionIntegration:false,Android:false,SAS:'synthetic automatic comparison, not human OOB',setup:'private room and initial-owner-bootstrap capability only; runtime uses constrained ingress',coldReopen:'whole Chromium process + same profile + new P256-authorized Matrix lease',atomicRevocation:'already-in-flight native writes not atomically undoable',physicalErasure:false}));
}catch{console.log(JSON.stringify({completedGates:gates,completedDescriptorGates:descriptorGates,completedTransportGates:transportGates}));for(const c of contexts){const p=c.pages().find(p=>p.url().endsWith('/transport.html'));if(p)try{console.log(JSON.stringify({ownerStatus:await p.evaluate(()=>window.lab.ownerStatus()),boundState:await p.evaluate(()=>window.lab.gateStatus())}));}catch{}}console.error('FAIL: '+stage+'. Sensitive exception details suppressed.');process.exitCode=1;}finally{let fixtureCleanupFailed=false;for(const f of transportFixtures)try{await f.dispose();}catch{fixtureCleanupFailed=true;}if(fixtureCleanupFailed){console.log('transport_fixture_cleanup_failed=true');process.exitCode=1;}clearTimeout(deadline);for(const c of contexts)await c.close().catch(()=>{});if(ingress){ingress.closeAllConnections();await new Promise(r=>ingress.close(r));}for(const p of profiles)await rm(p,{recursive:true,force:true});}
