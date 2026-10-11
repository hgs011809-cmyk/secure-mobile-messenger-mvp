// GitHub Actions only. Synthetic native Synapse retention observation, not production wiring.
import {fork,execFileSync} from 'node:child_process';
import {randomBytes,createHmac} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {waitForServer} from '../../infra/ncp/matrix-lab/ci/readiness.mjs';
import {ScrubMeasurements} from './measurement.mjs';
if(process.env.GITHUB_ACTIONS!=='true')throw new Error('ci_only');
const trial=Number(process.env.RETENTION_TRIAL);
if(![1,2].includes(trial))throw new Error('invalid_trial');
const ci=fileURLToPath(new URL('../../infra/ncp/matrix-lab/ci/',import.meta.url));
const source=await readFile(new URL('probe_rows.py',import.meta.url),'utf8');
const children=[],samples=[],gates=[];const measured=new ScrubMeasurements();
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const assert=v=>{if(!v)throw new Error('gate_failed');};
let base,stage='readiness',restartDowntimeMs=null,restartPendingSamples=0;
function docker(args,options={}){return execFileSync('docker',['compose','-f',ci+'compose.yaml',...args],{encoding:'utf8',timeout:20000,stdio:['ignore','pipe','ignore'],...options});}
async function api(route,method='GET',body,token){
 const r=await fetch(base+route,{method,redirect:'error',signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});
 if(!r.ok){await r.body?.cancel();throw new Error('http_gate_failed');}return r.json();
}
async function provision(username){
 const secret=(await readFile(ci+'runtime/registration.secret','utf8')).trim(),{nonce}=await api('/_synapse/admin/v1/register'),password=randomBytes(32).toString('hex');
 const mac=createHmac('sha1',secret).update([nonce,username,password,'notadmin'].join('\0')).digest('hex');
 await api('/_synapse/admin/v1/register','POST',{nonce,username,password,admin:false,inhibit_login:true,mac});
 const login=await api('/_matrix/client/v3/login','POST',{type:'m.login.password',identifier:{type:'m.id.user',user:username},password,device_id:'CI_RETENTION_'+username.toUpperCase()});
 const who=await api('/_matrix/client/v3/account/whoami','GET',undefined,login.access_token);assert(who.user_id===login.user_id);
 const admin=docker(['exec','-T','synapse','python','-c','import sqlite3,sys;d=sqlite3.connect("file:/data/homeserver.db?mode=ro",uri=True);print(int(d.execute("SELECT admin FROM users WHERE name=?",(sys.stdin.read(),)).fetchone()[0]));d.close()'],{input:login.user_id,stdio:['pipe','pipe','ignore']}).trim();assert(admin==='0');
 assert((await api('/_matrix/client/v3/devices','GET',undefined,login.access_token)).devices.length===1);return login;
}
function worker(){
 const child=fork(ci+'client-worker.mjs',[],{stdio:['ignore','ignore','ignore','ipc']});children.push(child);const pending=new Map();let sequence=0;
 child.on('message',m=>{const p=pending.get(m.id);if(!p)return;clearTimeout(p.timer);pending.delete(m.id);m.ok?p.resolve(m.value):p.reject(new Error('worker_gate_failed'));});
 child.on('exit',()=>{for(const p of pending.values()){clearTimeout(p.timer);p.reject(new Error('worker_exit'));}pending.clear();});
 return {child,call(op,args={}){return new Promise((resolve,reject)=>{const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(new Error('worker_timeout'));},100000);pending.set(id,{resolve,reject,timer});child.send({id,op,args});});}};
}
function rawProbe(eventIds){
 const started=performance.now();const result=JSON.parse(docker(['exec','-T','synapse','python','-c',source],{input:JSON.stringify({event_ids:eventIds}),stdio:['pipe','pipe','ignore'],timeout:5000}));const finished=performance.now();
 assert(result&&Object.keys(result).length===1&&Array.isArray(result.states)&&result.states.length===eventIds.length&&result.states.every(s=>['encrypted','scrubbed'].includes(s)));
 return {eventIds,states:result.states,probeStartedAtMs:started,probeFinishedAtMs:finished};
}
function observeAll(){const observed=rawProbe(samples.map(s=>s.eventId));measured.observe(observed);return observed;}
async function limited(items,fn,limit=4){let index=0;await Promise.all(Array.from({length:Math.min(limit,items.length)},async()=>{while(index<items.length){const i=index++;await fn(items[i],i);}}));}
const route=(room,id)=>'/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/event/'+encodeURIComponent(id);
async function hidden(room,sample,token){const event=await api(route(room,sample.eventId),'GET',undefined,token);assert(event.type==='m.room.encrypted'&&event.content&&Object.keys(event.content).length===0&&event.unsigned?.redacted_because);}
async function cohort({name,count,sender,recipient,room,senderToken,redactorToken}){
 const entries=Array.from({length:count},()=>({body:'synthetic-retention-'+randomBytes(16).toString('hex')}));
 await limited(entries,async entry=>{entry.eventId=await sender.call('send',{roomId:room,body:entry.body});});
 await limited(entries,async entry=>{const e=await api(route(room,entry.eventId),'GET',undefined,senderToken);assert(e.type==='m.room.encrypted'&&typeof e.content?.ciphertext==='string'&&e.content.ciphertext&&!Object.hasOwn(e.content,'body'));await recipient.call('decrypt',{roomId:room,eventId:entry.eventId,body:entry.body});});
 assert(rawProbe(entries.map(e=>e.eventId)).states.every(s=>s==='encrypted'));
 // Each window includes HTTP/IPC acknowledgement latency: conservative upper bound,
 // never a later clock reset that would hide already elapsed time.
 for(const entry of entries){
  const requestedAtMs=performance.now();await recipient.call('redact',{roomId:room,eventId:entry.eventId});const acknowledgedAtMs=performance.now();
  const sample={eventId:entry.eventId,cohort:name,requestedAtMs,acknowledgedAtMs};measured.register(sample);samples.push(sample);
  await hidden(room,sample,redactorToken);await Promise.all([sender.call('deleted',{roomId:room,eventId:entry.eventId}),recipient.call('deleted',{roomId:room,eventId:entry.eventId})]);
  delete entry.body;
 }
}
const deadline=setTimeout(()=>{console.error('{"status":"failed","stage":"bounded-deadline"}');for(const c of children)c.kill('SIGKILL');process.exit(1);},850000);
try{
 base=await waitForServer(ci);gates.push('private-synthetic-server-ready');stage='ordinary accounts and exact worker keys';
 const a=await provision('ci_retention_a'),b=await provision('ci_retention_b'),alice=worker(),bob=worker();
 const ak=await alice.call('start',{...a,baseUrl:base}),bk=await bob.call('start',{...b,baseUrl:base});
 const room=await alice.call('create',{otherUser:b.user_id});await bob.call('join',{roomId:room});await Promise.all([alice.call('ready',{roomId:room}),bob.call('ready',{roomId:room})]);
 await alice.call('verify',bk);await bob.call('verify',ak);gates.push('ordinary-two-user-encrypted-room-exact-synthetic-key-verification');
 const state=await api('/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/state','GET',undefined,a.access_token),content=type=>state.find(e=>e.type===type&&e.state_key==='')?.content;
 assert(content('m.room.create')?.['m.federate']===false&&content('m.room.encryption')?.algorithm==='m.megolm.v1.aes-sha2'&&content('m.room.power_levels')?.redact===0);
 stage='three reciprocal baseline repetitions';
 for(let i=0;i<3;i++){const reverse=i===1;await cohort({name:'baseline-repeated',count:1,sender:reverse?bob:alice,recipient:reverse?alice:bob,room,senderToken:reverse?b.access_token:a.access_token,redactorToken:reverse?a.access_token:b.access_token});await sleep(500);}
 stage='bounded encrypted burst';await cohort({name:'bounded-burst',count:24,sender:alice,recipient:bob,room,senderToken:a.access_token,redactorToken:b.access_token});
 stage='predefined final cohort';await cohort({name:trial===2?'restart-pending':'phase-control',count:9,sender:alice,recipient:bob,room,senderToken:a.access_token,redactorToken:b.access_token});
 gates.push('all-36-real-ciphertexts-prechecked-and-peer-redacted-api-hidden');
 observeAll();
 if(trial===2){
  await sleep(35000);const before=observeAll();
  restartPendingSamples=samples.filter((s,i)=>s.cohort==='restart-pending'&&before.states[i]==='encrypted').length;assert(restartPendingSamples===9);
  stage='clean server restart with pending ciphertext';const restartAt=performance.now();docker(['restart','--timeout','5','synapse'],{timeout:45000});const restored=await waitForServer(ci);assert(restored===base);restartDowntimeMs=Math.ceil(performance.now()-restartAt);
  gates.push('clean-synapse-restart-same-volume-with-9-pending-rows-no-clock-reset');
  stage='redaction remains hidden after server restart';await limited(samples,s=>hidden(room,s,a.access_token));gates.push('all-redactions-remain-api-hidden-after-restart');
 }
 stage='bounded active row observations';const observationEnd=Math.max(...samples.map(s=>s.acknowledgedAtMs))+390000;
 while(!measured.completed&&performance.now()<observationEnd){observeAll();if(!measured.completed)await sleep(1000);}
 const aggregate=measured.report();const report={status:aggregate.passed?'passed':'failed',trial,plannedSamples:36,gates,measurement:aggregate,restartDowntimeMs,restartPendingSamples,burst:{messages:24,sendConcurrency:4},targetWindow:'conservative request-to-first-observed-scrub upper bound; confirmed misses use ack-to-encrypted-probe lower bound',serverRestart:trial===2?'clean service restart, same SQLite volume; not SIGKILL/power loss':'not scheduled: separate no-restart control',verification:'synthetic exact worker public keys; not human OOB or production admission',physicalErasure:false,Android:false,productionIntegration:false,transport:base==='http://127.0.0.1:18008'?'host-loopback':'private-internal-bridge'};
 await writeFile(ci+'runtime/retention-result.json',JSON.stringify(report,null,2),{mode:0o600});console.log(JSON.stringify(report));if(!aggregate.passed)process.exitCode=1;
}catch{console.error(JSON.stringify({status:'failed',trial,plannedSamples:36,stage,measurement:measured.report(),details:'suppressed'}));process.exitCode=1;}
finally{clearTimeout(deadline);for(const c of children)c.kill('SIGTERM');await sleep(250);for(const c of children)if(c.exitCode===null)c.kill('SIGKILL');}
