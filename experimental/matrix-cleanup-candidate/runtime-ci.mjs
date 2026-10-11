// GitHub Actions only. Synthetic native Synapse retention observation, not production wiring.
import {fork,execFileSync} from 'node:child_process';
import {randomBytes,createHmac,createHash} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {waitForServer} from '../../infra/ncp/matrix-lab/ci/readiness.mjs';
import {ScrubMeasurements} from '../matrix-retention-lab/measurement.mjs';
if(process.env.GITHUB_ACTIONS!=='true')throw new Error('ci_only');
const mode=process.env.CANDIDATE_MODE;
if(!['control','restart'].includes(mode))throw new Error('invalid_mode');
const ci=fileURLToPath(new URL('../../infra/ncp/matrix-lab/ci/',import.meta.url));
const source=await readFile(new URL('../matrix-retention-lab/probe_rows.py',import.meta.url),'utf8');
const children=[],samples=[],gates=[];const measured=new ScrubMeasurements();
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const assert=v=>{if(!v)throw new Error('gate_failed');};
let base,stage='readiness';const restartDowntimeMs=[],negativeStatuses={};
function docker(args,options={}){return execFileSync('docker',['compose','-f',ci+'compose.yaml','-f',ci+'runtime/candidate-compose.yaml',...args],{encoding:'utf8',timeout:20000,stdio:['ignore','pipe','ignore'],...options});}
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

const deadline=setTimeout(()=>{console.error('{"status":"failed","stage":"bounded-runtime-deadline"}');for(const c of children)c.kill('SIGKILL');process.exit(1);},450000);
async function requestStatus(route,body,token){const r=await fetch(base+route,{method:'PUT',redirect:'error',signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify(body)});await r.body?.cancel();return r.status;}
async function indexReady(){const out=docker(['exec','-T','synapse','python','-c','import sqlite3;d=sqlite3.connect("file:/data/homeserver.db?mode=ro",uri=True);print(d.execute("SELECT COUNT(*) FROM background_updates WHERE update_name=?",("redactions_have_censored_ts_idx",)).fetchone()[0]);d.close()']).trim();return out==='0';}
try{
 base=await waitForServer(ci);gates.push('candidate-started-private-fixture');
 stage='installed-source-identity';const expected=createHash('sha256').update(await readFile(process.env.CANDIDATE_SOURCE)).digest('hex');
 const actual=docker(['exec','-T','synapse','python','-c','import hashlib,pathlib,synapse;print(hashlib.sha256((pathlib.Path(synapse.__file__).parent/"storage/databases/main/censor_events.py").read_bytes()).hexdigest())']).trim();assert(actual===expected);gates.push('installed-candidate-source-hash-matches');
 stage='index-ready';const indexDeadline=performance.now()+60000;while(!await indexReady()){assert(performance.now()<indexDeadline);await sleep(500);}gates.push('fresh-database-index-update-complete');
 stage='ordinary accounts and exact worker keys';const a=await provision('candidate_a'),b=await provision('candidate_b'),outsider=await provision('candidate_outsider'),alice=worker(),bob=worker();
 const ak=await alice.call('start',{...a,baseUrl:base}),bk=await bob.call('start',{...b,baseUrl:base});
 const room=await alice.call('create',{otherUser:b.user_id});await bob.call('join',{roomId:room});await Promise.all([alice.call('ready',{roomId:room}),bob.call('ready',{roomId:room})]);await alice.call('verify',bk);await bob.call('verify',ak);
 const state=await api('/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/state','GET',undefined,a.access_token),content=t=>state.find(e=>e.type===t&&e.state_key==='')?.content;
 assert(content('m.room.create')?.['m.federate']===false&&content('m.room.encryption')?.algorithm==='m.megolm.v1.aes-sha2'&&content('m.room.power_levels')?.redact===0);gates.push('ordinary-two-device-encrypted-private-room');
 stage='negative-controls';const sentinelBody='synthetic-sentinel-'+randomBytes(16).toString('hex'),sentinel=await alice.call('send',{roomId:room,body:sentinelBody});await bob.call('decrypt',{roomId:room,eventId:sentinel,body:sentinelBody});
 const initialSentinel=await api(route(room,sentinel),'GET',undefined,a.access_token);assert(initialSentinel.type==='m.room.encrypted'&&initialSentinel.content?.ciphertext&&!Object.hasOwn(initialSentinel.content,'body'));const sentinelContent=JSON.stringify(initialSentinel.content);
 const denied=await requestStatus('/_matrix/client/v3/rooms/'+encodeURIComponent(room)+'/redact/'+encodeURIComponent(sentinel)+'/outsider-negative',{reason:'synthetic-negative'},outsider.access_token);negativeStatuses.nonmember=denied;assert([403,404].includes(denied));
 const otherRoom=await alice.call('create',{otherUser:b.user_id});const cross=await requestStatus('/_matrix/client/v3/rooms/'+encodeURIComponent(otherRoom)+'/redact/'+encodeURIComponent(sentinel)+'/cross-room-negative',{reason:'synthetic-negative'},a.access_token);negativeStatuses.crossRoom=cross;assert([200,403,404].includes(cross));
 gates.push('non-member-redaction-rejected');
 for(let i=0;i<3;i++){
  stage='real-ciphertext-precheck';const reverse=i===1,sender=reverse?bob:alice,recipient=reverse?alice:bob,senderToken=reverse?b.access_token:a.access_token,recipientToken=reverse?a.access_token:b.access_token;
  const body='synthetic-candidate-'+randomBytes(16).toString('hex'),eventId=await sender.call('send',{roomId:room,body});const raw=await api(route(room,eventId),'GET',undefined,senderToken);assert(raw.type==='m.room.encrypted'&&raw.content?.ciphertext&&!Object.hasOwn(raw.content,'body'));await recipient.call('decrypt',{roomId:room,eventId,body});assert(rawProbe([eventId]).states[0]==='encrypted');
  stage='ordinary-peer-redaction';const requestedAtMs=performance.now();await recipient.call('redact',{roomId:room,eventId});const acknowledgedAtMs=performance.now();const sample={eventId,cohort:mode==='restart'?'candidate-restart':'candidate-control',requestedAtMs,acknowledgedAtMs};samples.push(sample);measured.register(sample);await hidden(room,sample,recipientToken);
  if(mode==='restart'){
   stage='predefined-pending-row-restart';assert(observeAll().states.at(-1)==='encrypted');const start=performance.now();docker(['restart','--timeout','5','synapse'],{timeout:45000});const restored=await waitForServer(ci);assert(restored===base);restartDowntimeMs.push(Math.ceil(performance.now()-start));
   stage='post-restart-api-hidden';for(const s of samples)await hidden(room,s,a.access_token);assert(await indexReady());
  }
  stage='active-row-observation';const observationDeadline=acknowledgedAtMs+90000;while(!measured.completed&&performance.now()<observationDeadline){observeAll();if(!measured.completed)await sleep(500);}assert(measured.completed);assert(measured.report().passed);
  stage='sdk-redaction-hidden';await Promise.all([sender.call('deleted',{roomId:room,eventId}),recipient.call('deleted',{roomId:room,eventId})]);
 }
 gates.push('three-reciprocal-redactions-scrubbed-with-original-clocks');if(mode==='restart')gates.push('three-clean-restart-cycles-pending-before-each-and-api-hidden-after');
 stage='negative-controls-after-native-ticks';await sleep(35000);assert(rawProbe([sentinel]).states[0]==='encrypted');const finalSentinel=await api(route(room,sentinel),'GET',undefined,a.access_token);assert(JSON.stringify(finalSentinel.content)===sentinelContent);await bob.call('decrypt',{roomId:room,eventId:sentinel,body:sentinelBody});gates.push('unredacted-and-cross-room-target-unchanged-after-native-ticks');
 const report={status:'passed',mode,plannedSamples:3,gates,negativeStatuses,measurement:measured.report(),restartDowntimeMs,observationBudgetMs:90000,observationBudgetMeaning:'early functional gate; not a changed 300000ms acceptance target; pending is not a confirmed miss',physicalErasure:false,Android:false,humanOOB:false,productionIntegration:false,batchBoundary101:false,transport:base==='http://127.0.0.1:18008'?'host-loopback':'private-internal-bridge'};console.log(JSON.stringify(report));
}catch{console.error(JSON.stringify({status:'failed',mode,plannedSamples:3,stage,gates,negativeStatuses,measurement:measured.report(),details:'suppressed'}));process.exitCode=1;}
finally{clearTimeout(deadline);for(const c of children)c.kill('SIGTERM');await sleep(250);for(const c of children)if(c.exitCode===null)c.kill('SIGKILL');}
