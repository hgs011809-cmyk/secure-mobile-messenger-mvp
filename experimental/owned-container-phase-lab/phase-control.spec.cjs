'use strict';
// Pure synthetic metadata tests ONLY. Importing controller does not invoke CLI.
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('./phase-control.cjs');
const copy = v => JSON.parse(JSON.stringify(v));
const hex = n => n.repeat(64);
function fixture(mode='graceful') {
  // Synthetic pins, not an approved actual engine profile and never written as one.
  const profile={exactServerVersion:'28.5.1',exactServerGitCommit:'synthetic-engine',apiVersion:'1.51',cgroupVersion:'2',cgroupDriver:'systemd',defaultRuntime:'runc',runcVersion:'1.3.0',runcGitCommit:'v1.3.0-0-gsynthetic',containerdVersion:'1.7.28',containerdGitCommit:'synthetic-containerd',hostCgroupPathTemplate:'/system.slice/docker-{id}.scope',hostCgroupMountRoot:'/',hostCgroupMountPoint:'/sys/fs/cgroup',expectedCpuQuota:'100000',expectedCpuPeriod:'100000',expectedCpuBurst:'0',oomDisableCapability:false};
  const identity={exactId:hex('a'),exactImageId:'sha256:'+hex('b'),run:hex('c'),nonce:hex('d'),mode};
  const ns={pid:'pid:[11]',cgroup:'cgroup:[12]',mount:'mnt:[13]',time:'time:[14]'};
  const config={User:'10001:10001',Labels:{'owned-containment.run':identity.run,'owned-containment.nonce':identity.nonce,'owned-containment.mode':mode},Entrypoint:['node','/opt/fixture/phase-worker.mjs'],Cmd:[mode],WorkingDir:'/opt/fixture',Tty:false,OpenStdin:false,Volumes:null,Env:['NODE_VERSION=22.20.0','PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','PLAYWRIGHT_BROWSERS_PATH=/opt/playwright','YARN_VERSION=1.22.22',...Object.entries(ns).map(([k,v])=>'HOST_'+k.toUpperCase()+'_NAMESPACE='+v)],StopSignal:'SIGTERM'};
  const h={Privileged:false,ReadonlyRootfs:true,NetworkMode:'none',PidMode:'',IpcMode:'private',UsernsMode:'',UTSMode:'',CgroupnsMode:'private',AutoRemove:false,Init:false,PublishAllPorts:false,CapDrop:['ALL'],SecurityOpt:['no-new-privileges'],Memory:1073741824,MemorySwap:1073741824,NanoCpus:1000000000,PidsLimit:128,ShmSize:134217728,OomKillDisable:false,OomScoreAdj:0,Tmpfs:{'/tmp':'rw,noexec,nosuid,nodev,size=256m,mode=1777'},Binds:null,Devices:[],DeviceRequests:null,VolumesFrom:null,Links:null,ExtraHosts:null,CapAdd:null,Mounts:[],PortBindings:{},CgroupParent:'',ContainerIDFile:'',GroupAdd:null,Runtime:'runc',RestartPolicy:{Name:'no',MaximumRetryCount:0}};
  // Synthetic explicit defaults, not a rebaseline of any observed engine.
  Object.assign(h,{DeviceCgroupRules:null,Ulimits:null,BlkioWeightDevice:[],BlkioDeviceReadBps:[],BlkioDeviceWriteBps:[],BlkioDeviceReadIOps:[],BlkioDeviceWriteIOps:[],Dns:[],DnsOptions:[],DnsSearch:[],Sysctls:null,StorageOpt:null,Annotations:null,CpuShares:0,CpuPeriod:0,CpuQuota:0,CpuRealtimePeriod:0,CpuRealtimeRuntime:0,MemoryReservation:0,BlkioWeight:0,CpuCount:0,CpuPercent:0,IOMaximumIOps:0,IOMaximumBandwidth:0,Cgroup:'',CpusetCpus:'',CpusetMems:'',Isolation:'',MemorySwappiness:null});
  const created={Id:identity.exactId,Image:identity.exactImageId,Config:config,HostConfig:h,Mounts:[],NetworkSettings:{Networks:{none:{}}},State:{Running:false,Pid:0,ExitCode:0,Paused:false,Restarting:false,OOMKilled:false,Dead:false,Error:'',Status:'created'}};
  const plan=C.buildPlan(identity,profile,created,ns);
  const started=copy(created); started.HostConfig=copy(plan.hostConfigPoststart); Object.assign(started.State,{Running:true,Pid:1234,Status:'running'});
  const terminal=copy(started); Object.assign(terminal.State,{Running:false,Pid:0,Status:'exited',ExitCode:mode==='graceful'?0:137});
  const rec=op=>({version:1,op,exactId:identity.exactId});
  const journal={startIntent:rec('start-intent'),started:rec('started'),terminal:rec('terminal')};
  const proofs=['ready','result_ready'].map((milestone,i)=>({version:1,op:'accepted',exactId:identity.exactId,nonce:hex(i?'f':'e'),milestone}));
  const info={ServerVersion:profile.exactServerVersion,CgroupVersion:'2',CgroupDriver:'systemd',DefaultRuntime:'runc',OomKillDisable:false,Runtimes:{runc:{}}};
  const version={Server:{Version:profile.exactServerVersion,GitCommit:profile.exactServerGitCommit,ApiVersion:profile.apiVersion,Os:'linux',Components:[{Name:'Engine',Version:profile.exactServerVersion,Details:{GitCommit:profile.exactServerGitCommit}},{Name:'runc',Version:profile.runcVersion,Details:{GitCommit:profile.runcGitCommit}},{Name:'containerd',Version:profile.containerdVersion,Details:{GitCommit:profile.containerdGitCommit}}]}};
  return {profile,identity,ns,created,plan,started,terminal,journal,proofs,info,version};
}
function denied(fn) { assert.throws(fn,e=>e instanceof Error && e.message===C.ERROR); }
function freeze(v) { if (v && typeof v==='object') { for (const x of Object.values(v)) freeze(x); Object.freeze(v); } return v; }
test('valid predefined creation/start/terminal shapes and both required case exits',()=> {
  for (const mode of ['graceful','linger']) {
    const f=fixture(mode);
    assert.equal(C.validatePlan(f.plan),true);
    assert.equal(C.validatePhase(f.plan,f.created,'created'),true);
    assert.equal(C.validatePhase(f.plan,f.started,'started'),true);
    assert.equal(C.validateCase(f.plan,f.journal,f.proofs,f.terminal),true);
    assert.equal(C.validateEngineObservation(f.profile,f.info,f.version),true);
  }
});
test('poststart is deep clone with only own false-to-null difference',()=> {
  const f=fixture(); const post=copy(f.plan.hostConfigCreated); post.OomKillDisable=null;
  assert.deepEqual(f.plan.hostConfigPoststart,post);
  assert.notEqual(f.plan.config,f.created.Config); assert.notEqual(f.plan.hostConfigCreated,f.created.HostConfig);
  f.created.HostConfig.Tmpfs['/tmp']='changed'; assert.notEqual(f.plan.hostConfigCreated.Tmpfs['/tmp'],'changed');
});
for (const [field,bad] of Object.entries({Privileged:true,ReadonlyRootfs:false,NetworkMode:'host',PidMode:'host',IpcMode:'host',UsernsMode:'host',UTSMode:'host',CgroupnsMode:'host',AutoRemove:true,Init:true,PublishAllPorts:true,CapDrop:[],CapAdd:['SYS_ADMIN'],SecurityOpt:[],Memory:0,MemorySwap:-1,NanoCpus:0,PidsLimit:0,ShmSize:0,OomKillDisable:true,OomScoreAdj:-1000,Tmpfs:{'/tmp':'rw,size=1g'},Binds:['/var/run/docker.sock:/socket'],Devices:[{}],DeviceRequests:[{}],VolumesFrom:['foreign'],Links:['foreign'],ExtraHosts:['host:1.1.1.1'],Mounts:[{}],PortBindings:{'80/tcp':[{}]},CgroupParent:'/foreign',GroupAdd:['0']})) {
  test('reject observed security '+field,()=> { const f=fixture(); f.started.HostConfig[field]=bad; denied(()=>C.validatePhase(f.plan,f.started,'started')); });
  test('reject BOTH expected and observed bad security '+field,()=> {
    const f=fixture(); f.plan.hostConfigCreated[field]=copy(bad); f.plan.hostConfigPoststart[field]=copy(bad); f.started.HostConfig[field]=copy(bad);
    denied(()=>C.validatePhase(f.plan,f.started,'started'));
  });
}
for (const [field,bad] of Object.entries({User:'0',Entrypoint:['sh'],Cmd:['unknown'],WorkingDir:'/',Tty:true,OpenStdin:true,Volumes:{'/socket':{}},Labels:{},Env:['PATH=/bin']})) {
  test('reject both bad Config '+field,()=> { const f=fixture(); f.plan.config[field]=bad; f.started.Config[field]=copy(bad); denied(()=>C.validatePhase(f.plan,f.started,'started')); });
}
for (const value of [null,true,undefined,0,'false']) test('created own OOM false mandatory '+String(value),()=> {
  const f=fixture(); if (value===undefined) delete f.created.HostConfig.OomKillDisable; else f.created.HostConfig.OomKillDisable=value;
  denied(()=>C.buildPlan(f.identity,f.profile,f.created,f.ns));
});
test('null is not unconditional admission',()=> {
  const f=fixture(); f.created.HostConfig.OomKillDisable=null; denied(()=>C.validatePhase(f.plan,f.created,'created'));
  f.started.HostConfig.OomKillDisable=false; denied(()=>C.validatePhase(f.plan,f.started,'started'));
  f.plan.hostConfigCreated.OomKillDisable=null; f.plan.hostConfigPoststart.OomKillDisable=null; denied(()=>C.validatePlan(f.plan));
});
test('poststart unrelated field drift rejects even when observed matches malicious plan',()=> {
  const f=fixture(); f.plan.hostConfigPoststart.Runtime='foreign'; f.started.HostConfig.Runtime='foreign'; denied(()=>C.validatePhase(f.plan,f.started,'started'));
});
for (const target of ['Config','HostConfig']) test('full '+target+' equality includes unknown fields',()=> {
  const f=fixture(); f.started[target].UnknownFutureField='drift'; denied(()=>C.validatePhase(f.plan,f.started,'started'));
});
test('full Config drift rejects all phases',()=> {
  const f=fixture(); for (const [o,p] of [[f.created,'created'],[f.started,'started'],[f.terminal,'terminal']]) { o.Config.StopSignal='SIGKILL'; denied(()=>C.validatePhase(f.plan,o,p)); }
});
for (const name of ['version','identity','engineProfile','config','hostConfigCreated','hostConfigPoststart','observerNamespaces']) test('missing plan '+name,()=> { const f=fixture(); delete f.plan[name]; denied(()=>C.validatePlan(f.plan)); });
test('unknown plan/profile/identity/namespace keys reject',()=> {
  for (const target of ['plan','profile','identity','ns']) { const f=fixture(); const v=target==='plan'?f.plan:target==='profile'?f.plan.engineProfile:target==='identity'?f.plan.identity:f.plan.observerNamespaces; v.unknown=true; denied(()=>C.validatePlan(f.plan)); }
});
for (const k of ['exactServerVersion','exactServerGitCommit','apiVersion','runcVersion','runcGitCommit','containerdVersion','containerdGitCommit']) test('unknown source pin '+k+' rejects',()=> { const f=fixture(); f.profile[k]='unknown'; denied(()=>C.validateEngineProfile(f.profile)); });
test('missing profile has no fallback',()=> { for (const v of [null,{},undefined]) denied(()=>C.validateEngineProfile(v)); });
test('unsupported/nonexact engine capability and layout reject',()=> {
  for (const [k,v] of Object.entries({cgroupVersion:'1',cgroupDriver:'unknown',defaultRuntime:'unknown',oomDisableCapability:true,hostCgroupMountRoot:'/nested',hostCgroupMountPoint:'/other',hostCgroupPathTemplate:'/docker/{shortid}',expectedCpuQuota:'200000',expectedCpuBurst:'1'})) { const f=fixture(); f.profile[k]=v; denied(()=>C.validateEngineProfile(f.profile)); }
});
test('Docker info/version/runtime identity and duplicate components reject',()=> {
  for (const mutate of [f=>{f.info.ServerVersion='29.0.0';},f=>{delete f.info.OomKillDisable;},f=>{f.version.Server.GitCommit='other';},f=>{f.version.Server.ApiVersion='1.50';},f=>{delete f.version.Server.Components[1].Details.GitCommit;},f=>{f.version.Server.Components.push(copy(f.version.Server.Components[1]));},f=>{f.version.Server.Components[2].Version='other';},f=>{f.info.Runtimes={};}]) { const f=fixture(); mutate(f); denied(()=>C.validateEngineObservation(f.profile,f.info,f.version)); }
});
test('unresolved start admits only two exact full shapes for CLEANUP not case',()=> {
  const f=fixture(); for (const o of [f.created,f.started]) { assert.equal(C.validatePhase(f.plan,o,'start-intent','cleanup'),true); denied(()=>C.validatePhase(f.plan,o,'start-intent','case')); }
  f.started.HostConfig.Runtime='unknown'; denied(()=>C.validatePhase(f.plan,f.started,'start-intent','cleanup'));
});
test('created/start/terminal state mismatch and unknown phases reject',()=> {
  const f=fixture(); denied(()=>C.validatePhase(f.plan,f.started,'created')); denied(()=>C.validatePhase(f.plan,f.terminal,'started')); denied(()=>C.validatePhase(f.plan,f.started,'terminal')); denied(()=>C.validatePhase(f.plan,f.started,'unknown'));
});
for (const [k,v] of Object.entries({Paused:true,Restarting:true,OOMKilled:true,Dead:true,Error:'failure',Pid:0,Running:false,ExitCode:137,Status:'restarting'})) test('running state bad '+k,()=> { const f=fixture(); f.started.State[k]=v; denied(()=>C.validatePhase(f.plan,f.started,'started')); });
test('start ambiguous journal cannot pass case',()=> {
  const f=fixture(); f.journal.started=null; f.journal.terminal=null; denied(()=>C.validateCase(f.plan,f.journal,f.proofs,f.terminal));
});
test('case requires ordered distinct two proofs plus terminal exit',()=> {
  for (const mutate of [f=>{f.proofs.pop();},f=>{f.proofs.reverse();},f=>{f.proofs[1].nonce=f.proofs[0].nonce;},f=>{f.proofs[0].extra=true;},f=>{f.journal.terminal=null;},f=>{f.terminal.State.ExitCode=137;},f=>{f.proofs[0].exactId=hex('0');}]) { const f=fixture(); mutate(f); denied(()=>C.validateCase(f.plan,f.journal,f.proofs,f.terminal)); }
});
test('journal cannot invent started or terminal without predecessors',()=> {
  const f=fixture(); f.journal.startIntent=null; denied(()=>C.validateJournal(f.plan,f.journal));
  f.journal.startIntent={version:1,op:'start-intent',exactId:hex('0')}; denied(()=>C.validateJournal(f.plan,f.journal));
});
test('release fixed schema exact nonce and milestone',()=> {
  const v={version:1,op:'released',nonce:hex('e'),milestone:'ready'}; assert.equal(C.validateRelease(v,hex('e'),'ready'),true);
  for (const mutate of [x=>{x.extra=1;},x=>{x.nonce=hex('f');},x=>{x.op='ok';},x=>{x.milestone='result_ready';}]) { const x=copy(v); mutate(x); denied(()=>C.validateRelease(x,hex('e'),'ready')); }
});
test('nonmutation of frozen expected and observed metadata, success and rejection',()=> {
  const f=freeze(fixture()); const before=JSON.stringify(f);
  C.validatePlan(f.plan); C.validatePhase(f.plan,f.started,'started'); C.validateCase(f.plan,f.journal,f.proofs,f.terminal); C.validateEngineObservation(f.profile,f.info,f.version);
  denied(()=>C.validatePhase(f.plan,f.started,'created'));
  assert.equal(JSON.stringify(f),before);
});
test('accessor and symbol schema pollution rejected without accessor evaluation',()=> {
  const f=fixture(); Object.defineProperty(f.plan,'intruder',{enumerable:true,get(){throw new Error('RAW');}}); denied(()=>C.validatePlan(f.plan));
  const g=fixture(); g.plan[Symbol('unknown')]=true; denied(()=>C.validatePlan(g.plan));
});

// Regression: expected-and-observed equality NEVER substitutes security admission.
for (const [field,bad] of Object.entries({CapAdd:['SYS_ADMIN'],DeviceCgroupRules:['c *:* rwm'],CpuShares:1024,CpuPeriod:100000,CpuQuota:-1,CpuRealtimePeriod:1000000,CpuRealtimeRuntime:950000,MemoryReservation:1073741824,MemorySwappiness:100,Dns:['8.8.8.8'],DnsOptions:['use-vc'],DnsSearch:['example.invalid'],Sysctls:{'net.ipv4.ip_forward':'1'},StorageOpt:{size:'100G'},Annotations:{'runtime.unreviewed':'true'},Ulimits:[{Name:'memlock',Soft:-1,Hard:-1}],BlkioWeight:1000,BlkioWeightDevice:[{}],BlkioDeviceReadBps:[{}],BlkioDeviceWriteBps:[{}],BlkioDeviceReadIOps:[{}],BlkioDeviceWriteIOps:[{}],Cgroup:'/host',CpusetCpus:'0',CpusetMems:'0',Isolation:'hyperv',Runtime:'unreviewed',RestartPolicy:{Name:'always',MaximumRetryCount:0},ContainerIDFile:'/host/file',CpuCount:1,CpuPercent:100,IOMaximumIOps:1000,IOMaximumBandwidth:1000})) {
  test('ancillary security rejects BOTH matching bad '+field,()=> {
    const f=fixture(); f.plan.hostConfigCreated[field]=copy(bad); f.plan.hostConfigPoststart[field]=copy(bad); f.started.HostConfig[field]=copy(bad);
    denied(()=>C.validatePhase(f.plan,f.started,'started'));
  });
}
test('CapAdd strictly owned null only, including matching expected+observed',()=> {
  for (const v of [undefined,[],['SYS_ADMIN'],['NET_ADMIN'],false,{}]) {
    const f=fixture(); for (const h of [f.plan.hostConfigCreated,f.plan.hostConfigPoststart,f.started.HostConfig]) { if (v===undefined) delete h.CapAdd; else h.CapAdd=copy(v); }
    denied(()=>C.validatePhase(f.plan,f.started,'started'));
  }
});
test('missing ancillary own controls cannot be hidden in BOTH snapshots',()=> {
  for (const field of ['GroupAdd','CgroupParent','Devices','DeviceRequests','DeviceCgroupRules','CpuRealtimePeriod','CpuRealtimeRuntime','MemoryReservation','PortBindings','Dns','DnsOptions','DnsSearch','ExtraHosts','MemorySwappiness']) {
    const f=fixture(); for (const h of [f.plan.hostConfigCreated,f.plan.hostConfigPoststart,f.started.HostConfig]) delete h[field];
    denied(()=>C.validatePhase(f.plan,f.started,'started'));
  }
});
test('explicit reviewed-source/trusted-build hashes require exact matching four values',()=> {
  assert.equal(C.validateBuildProvenance(hex('1'),hex('2'),hex('1'),hex('2')),true);
  const invalid=[undefined,null,'', 'unknown','a'.repeat(63),'a'.repeat(65),'A'.repeat(64),' '+hex('a'),hex('a')+'\n',{},0];
  for (let index=0;index<4;index++) for (const value of invalid) { const args=[hex('1'),hex('2'),hex('1'),hex('2')]; args[index]=value; denied(()=>C.validateBuildProvenance(...args)); }
  denied(()=>C.validateBuildProvenance(hex('1'),hex('2'),hex('3'),hex('2')));
  denied(()=>C.validateBuildProvenance(hex('1'),hex('2'),hex('1'),hex('3')));
});
test('self-recorded binary hash is consistency only and cannot supply missing expectations',()=> {
  const h={version:1,sourceSha256:hex('1'),binarySha256:hex('2')};
  assert.equal(C.validateHelperRecord(h,hex('1'),hex('2')),true);
  denied(()=>C.validateHelperRecord(h,undefined,undefined));
  denied(()=>C.validateHelperRecord(h,hex('3'),hex('2')));
  denied(()=>C.validateHelperRecord(h,hex('1'),hex('3')));
  denied(()=>C.validateHelperRecord({version:1,sha256:hex('2')},hex('1'),hex('2')));
  denied(()=>C.validateHelperRecord({...h,extra:true},hex('1'),hex('2')));
});
test('compiled helper regular owned0700/nlink1, no symlink/suid/sgid',()=> {
  const good={regular:true,symlink:false,uid:1001,mode:0o700,nlink:1,size:4096};
  assert.equal(C.validateBuildFileFacts(good,1001,'binary'),true);
  for (const [key,value] of Object.entries({regular:false,symlink:true,uid:0,mode:0o4700,nlink:2,size:16777217})) denied(()=>C.validateBuildFileFacts({...good,[key]:value},1001,'binary'));
  for (const mode of [0o2700,0o1700,0o600,0o755,0o777]) denied(()=>C.validateBuildFileFacts({...good,mode},1001,'binary'));
  for (const size of [0,-1,NaN,Infinity]) denied(()=>C.validateBuildFileFacts({...good,size},1001,'binary'));
  denied(()=>C.validateBuildFileFacts({...good,unknown:true},1001,'binary'));
});
test('controlled C source owned nonsymlink single link read-only-to-others',()=> {
  const good={regular:true,symlink:false,uid:1001,mode:0o644,nlink:1,size:10000};
  assert.equal(C.validateBuildFileFacts(good,1001,'source'),true);
  assert.equal(C.validateBuildFileFacts({...good,mode:0o600},1001,'source'),true);
  for (const [key,value] of Object.entries({regular:false,symlink:true,uid:0,nlink:2,size:1048577})) denied(()=>C.validateBuildFileFacts({...good,[key]:value},1001,'source'));
  for (const mode of [0o666,0o664,0o755,0o4644,0o2644]) denied(()=>C.validateBuildFileFacts({...good,mode},1001,'source'));
});
test('build guard validations are nonmutating on frozen inputs',()=> {
  const facts=freeze({regular:true,symlink:false,uid:1001,mode:0o700,nlink:1,size:4096});
  const h=freeze({version:1,sourceSha256:hex('1'),binarySha256:hex('2')});
  const before=JSON.stringify([facts,h]); C.validateBuildFileFacts(facts,1001,'binary'); C.validateHelperRecord(h,hex('1'),hex('2'));
  denied(()=>C.validateHelperRecord(h,hex('3'),hex('2'))); assert.equal(JSON.stringify([facts,h]),before);
});
