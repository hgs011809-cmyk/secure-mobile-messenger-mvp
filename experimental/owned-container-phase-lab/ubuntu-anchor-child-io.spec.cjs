'use strict';
// MOCK child streams/timers and in-memory writes ONLY. No real child/procfs,
// filesystem sink, gpgv, network, cryptographic result or runtime/cleanup proof.
// Test-only VM exposes private child() and bypasses filesystem recheck().
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto'),{EventEmitter}=require('node:events');
const source=fs.readFileSync(path.join(__dirname,'ubuntu-anchor-preflight.cjs'),'utf8');
if(crypto.createHash('sha256').update(source).digest('hex')!=='53613a5b07d813969438f9f5beb57863642c30f7c103142a9060f3ae270c08cb')throw Error('REVIEWED_ANCHOR_SOURCE_CHANGED');
let passed=0,failed=0;
const safety=setTimeout(()=>{console.log('{"kind":"ubuntu_anchor_child_io_mock_spec","status":"deadline","realChildren":0,"networkRequests":0}');process.exit(1);},55000);
function harness(plan,{writeMode='full',partial=2}={}){
 const writes=[],signals=[],timers=[],spawns=[];let calls=0,rechecks=0;
 class Stream extends EventEmitter{destroy(){this.destroyed=true;}}
 class Child extends EventEmitter{constructor(){super();this.stdout=new Stream();this.stderr=new Stream();this.stdio=[null,this.stdout,this.stderr,new Stream()];}kill(signal){signals.push(signal);return true;}unref(){this.unreferenced=true;}}
 const child=new Child(),fakeFs={writeSync(fd,b,offset,length,position){calls++;if(writeMode==='zero')return 0;if(writeMode==='throw'||(writeMode==='partial_then_throw'&&calls>1))throw Error('MOCK_WRITE');const n=writeMode.startsWith('partial')?Math.min(partial,length):length;writes.push({fd,position,n,data:Buffer.from(b.subarray(offset,offset+n))});return n;}};
 function fakeSpawn(p,args,options){spawns.push({p,args,options});queueMicrotask(()=>plan(child,timers));return child;}
 const mod={exports:{}},req=Object.assign(name=>{if(name==='node:fs')return fakeFs;if(name==='node:path')return path;if(name==='node:crypto')return crypto;if(name==='node:child_process')return {spawn:fakeSpawn};throw Error('UNEXPECTED_IMPORT');},{main:null});
 vm.runInNewContext(source+'\nrecheck=()=>{__recheck();}; module.exports=Object.freeze({child});',{module:mod,require:req,Buffer,TextDecoder,URL,process:{env:{}},console:{log(){throw Error('UNEXPECTED_LOG');}},fetch(){throw Error('FORBIDDEN_NETWORK');},setTimeout(fn,ms){const t={fn,ms,cancelled:false};timers.push(t);return t;},clearTimeout(t){if(t)t.cancelled=true;},__recheck(){rechecks++;}},{timeout:1000});
 return {run(cap=10,sink=true,input=true){return mod.exports.child({fd:66},['--MOCK-ONLY'],{fd:55},'/MOCK-HOME',cap,input?{fd:67}:null,sink?{fd:77}:null);},writes,signals,timers,spawns,child,get rechecks(){return rechecks;}};
}
function normal(events=[],exitCode=0,signal=null,closeCode=exitCode,closeSignal=signal){return c=>{c.emit('spawn');for(const [stream,data] of events)(stream==='status'?c.stdio[3]:c[stream]).emit('data',Buffer.from(data));c.emit('exit',exitCode,signal);c.emit('close',closeCode,closeSignal);};}
function maxEnd(h){return h.writes.reduce((m,w)=>Math.max(m,w.position+w.n),0);}
function written(h){const b=Buffer.alloc(maxEnd(h));for(const w of h.writes)w.data.copy(b,w.position);return b.toString();}
async function reject(h,code,cap=10,sink=true,input=true){await assert.rejects(h.run(cap,sink,input),e=>e.message==='PREFLIGHT_BLOCKED'&&e.fixed===code);}
async function test(name,fn){try{await fn();passed++;console.log('ok '+name);}catch{failed++;console.log('FAIL '+name);}}
(async()=>{
 await test('mapped_descriptors_no_parent_sink_inheritance',async()=>{const h=harness(normal([['stdout','abc']]));const r=await h.run();const s=h.spawns[0];assert.equal(s.p,'/proc/self/fd/5');assert.equal(s.options.shell,false);assert.equal(s.options.detached,false);assert.deepEqual(Array.from(s.options.stdio),['ignore','pipe','pipe','pipe',55,66,67]);assert.equal(s.options.stdio.includes(77),false);assert.equal(h.rechecks,3);assert.equal(r.spawned,true);assert.equal(r.exitObserved,true);assert.equal(r.closed,true);assert.equal(r.exitCode,0);});
 await test('full_write_parent_only',async()=>{const h=harness(normal([['stdout','abcdef']]));const r=await h.run();assert.equal(maxEnd(h),6);assert.equal(r.stdoutBytes,6);assert.equal(r.stdout.length,0);assert.equal(h.writes[0].fd,77);assert.equal(written(h),'abcdef');});
 await test('partial_writes_positions',async()=>{const h=harness(normal([['stdout','abcdef']]),{writeMode:'partial'});const r=await h.run();assert.deepEqual(h.writes.map(x=>x.position),[0,2,4]);assert.equal(maxEnd(h),6);assert.equal(r.stdoutBytes,6);assert.equal(written(h),'abcdef');});
 await test('successive_chunks_positions',async()=>{const h=harness(normal([['stdout','abc'],['stdout','de']]));const r=await h.run();assert.deepEqual(h.writes.map(x=>x.position),[0,3]);assert.equal(r.stdoutBytes,5);assert.equal(written(h),'abcde');});
 await test('exact_cap_accepted',async()=>{const h=harness(normal([['stdout','1234567890']]));const r=await h.run();assert.equal(maxEnd(h),10);assert.equal(r.stdoutBytes,10);});
 await test('first_over_cap_not_written',async()=>{const h=harness(normal([['stdout','12345678901']]));await reject(h,'child_cap');assert.equal(h.writes.length,0);});
 await test('overflow_then_later_chunk_discarded',async()=>{const h=harness(normal([['stdout','123456'],['stdout','78901'],['stdout','x']]));await reject(h,'child_cap');assert.equal(maxEnd(h),6);assert.equal(h.writes.length,1);assert.equal(written(h),'123456');});
 await test('zero_write_blocks',async()=>{const h=harness(normal([['stdout','abc']]),{writeMode:'zero'});await reject(h,'filesystem');assert.equal(h.writes.length,0);});
 await test('write_exception_blocks_later_chunks',async()=>{const h=harness(normal([['stdout','abc'],['stdout','de']]),{writeMode:'throw'});await reject(h,'filesystem');assert.equal(h.writes.length,0);});
 await test('partial_then_throw_preserves_bounded_prefix',async()=>{const h=harness(normal([['stdout','abcdef'],['stdout','xyz']]),{writeMode:'partial_then_throw'});await reject(h,'filesystem');assert.equal(maxEnd(h),2);assert.equal(h.writes.length,1);assert.equal(written(h),'ab');});
 await test('buffered_stdout_no_sink',async()=>{const h=harness(normal([['stdout','abc'],['stdout','de']]));const r=await h.run(10,false,false);assert.equal(r.stdout.toString(),'abcde');assert.equal(h.writes.length,0);assert.equal(h.rechecks,2);assert.equal(h.spawns[0].options.stdio.length,6);});
 await test('buffered_stdout_overflow',async()=>{const h=harness(normal([['stdout','12345678901']]));await reject(h,'child_cap',10,false);assert.equal(h.writes.length,0);});
 await test('stderr_exact32768',async()=>{const h=harness(normal([['stderr',Buffer.alloc(32768)]]));const r=await h.run();assert.equal(r.stderrBytes,32768);assert.equal(r.stderrSha256.length,64);});
 await test('stderr_over32768',async()=>{await reject(harness(normal([['stderr',Buffer.alloc(32769)]])),'child_cap');});
 await test('status_exact65536',async()=>{const h=harness(normal([['status',Buffer.alloc(65536)]]));const r=await h.run();assert.equal(r.status.length,65536);});
 await test('status_over65536',async()=>{await reject(harness(normal([['status',Buffer.alloc(65537)]])),'child_cap');});
 await test('spawn_error_is_failure',async()=>{const h=harness(c=>{c.emit('error',Error('MOCK'));c.emit('close',null,null);});await reject(h,'child_spawn');});
 await test('nonzero_exit_observed_not_signature_success',async()=>{const h=harness(normal([],5));const r=await h.run();assert.equal(r.exitCode,5);assert.equal(r.closed,true);assert.equal(Object.hasOwn(r,'cryptographicVerification'),false);});
 await test('exit_close_code_mismatch',async()=>{await reject(harness(normal([],0,null,1,null)),'child_exit');});
 await test('close_without_exit_is_unknown_failure',async()=>{const h=harness(c=>{c.emit('spawn');c.emit('close',0,null);});await reject(h,'child_exit');});
 await test('stream_error_blocks',async()=>{const h=harness(c=>{c.emit('spawn');c.stdout.emit('error',Error('MOCK'));c.emit('exit',0,null);c.emit('close',0,null);});await reject(h,'child_spawn');});
 await test('signal_observed_not_crypto_success',async()=>{const h=harness(normal([],null,'SIGKILL'));const r=await h.run();assert.equal(r.signalPresent,true);assert.equal(r.exitCode,null);assert.equal(Object.hasOwn(r,'cryptographicVerification'),false);});
 await test('timer_callback_owned_handle_only_not_elapsed_proof',async()=>{const h=harness((c,t)=>{c.emit('spawn');const deadline=t.find(x=>x.ms===20000);assert.ok(deadline);deadline.fn();c.emit('exit',null,'SIGKILL');c.emit('close',null,'SIGKILL');});await reject(h,'child_deadline');assert.deepEqual(h.signals,['SIGKILL']);assert.equal(h.child.unreferenced,undefined);});
 await test('missing_close_is_unknown_not_termination_cleanup',async()=>{const h=harness((c,t)=>{c.emit('spawn');t.find(x=>x.ms===20000).fn();t.find(x=>x.ms===2000).fn();});await assert.rejects(h.run(),e=>e.fixed==='child_unclosed'&&e.observed.closed===false&&e.observed.exitObserved===false);assert.equal(h.child.unreferenced,true);assert.equal(h.child.stdout.destroyed,true);assert.deepEqual(h.signals,['SIGKILL']);});
 await test('data_after_settled_close_not_written',async()=>{const h=harness(c=>{c.emit('spawn');c.stdout.emit('data',Buffer.from('abc'));c.emit('exit',0,null);c.emit('close',0,null);c.stdout.emit('data',Buffer.from('unsafe'));});const r=await h.run();assert.equal(maxEnd(h),3);assert.equal(r.stdoutBytes,3);});
 await test('stderr_cumulative_over_cap',async()=>{await reject(harness(normal([['stderr',Buffer.alloc(32768)],['stderr','x']])),'child_cap');});
 await test('status_cumulative_over_cap',async()=>{await reject(harness(normal([['status',Buffer.alloc(65536)],['status','x']])),'child_cap');});
 for(const stream of ['stderr','status'])await test(stream+'_stream_error_blocks',async()=>{const h=harness(c=>{c.emit('spawn');(stream==='status'?c.stdio[3]:c[stream]).emit('error',Error('MOCK'));c.emit('exit',0,null);c.emit('close',0,null);});await reject(h,'child_spawn');});
 await test('exit_close_signal_mismatch',async()=>{await reject(harness(normal([],null,'SIGKILL',null,'SIGTERM')),'child_exit');});
 await test('normal_close_cancels_mock_deadline',async()=>{const h=harness(normal());await h.run();assert.equal(h.timers.length,1);assert.equal(h.timers[0].cancelled,true);assert.equal(h.signals.length,0);});
 await test('closed_deadline_cancels_mock_grace',async()=>{const h=harness((c,t)=>{c.emit('spawn');t.find(x=>x.ms===20000).fn();c.emit('exit',null,'SIGKILL');c.emit('close',null,'SIGKILL');});await reject(h,'child_deadline');assert.equal(h.timers.length,2);assert.equal(h.timers.every(x=>x.cancelled),true);assert.equal(h.child.unreferenced,undefined);});
 await test('late_close_after_unclosed_does_not_reclassify',async()=>{const h=harness((c,t)=>{c.emit('spawn');t.find(x=>x.ms===20000).fn();t.find(x=>x.ms===2000).fn();c.emit('exit',null,'SIGKILL');c.emit('close',null,'SIGKILL');c.stdout.emit('data',Buffer.from('late'));});await assert.rejects(h.run(),e=>e.fixed==='child_unclosed'&&e.observed.closed===false&&e.observed.exitObserved===false);assert.equal(h.writes.length,0);});
 clearTimeout(safety);console.log(JSON.stringify({kind:'ubuntu_anchor_child_io_mock_spec',passed,failed,total:passed+failed,realChildren:0,realFilesystemSinkWrites:0,procfsReads:0,networkRequests:0,cryptographicEvidence:false,realTimerDeadlineEvidence:false,realDescriptorInheritanceEvidence:false,terminationOrCleanupEvidence:false}));if(failed)process.exitCode=1;
})().catch(()=>{clearTimeout(safety);console.log('{"kind":"ubuntu_anchor_child_io_mock_spec","status":"failed","realChildren":0,"networkRequests":0,"cryptographicEvidence":false}');process.exitCode=1;});
