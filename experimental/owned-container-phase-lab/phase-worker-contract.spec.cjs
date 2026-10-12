'use strict';
// Pure tests only: never imports the worker, launches processes or reads /proc.
const test=require('node:test');
const assert=require('node:assert/strict');
const modulePromise=import('./phase-worker-contract.mjs');
const nonce='a'.repeat(64), nextNonce='b'.repeat(64);
const namespaces={pid:'pid:[11]',cgroup:'cgroup:[12]',mount:'mnt:[13]',time:'time:[14]'};
const fact=pid=>({pid,startTicks:'100',state:'S',membership:'0::/',oomScoreAdj:0,namespaces:{...namespaces}});
const challenge=(milestone='ready',n=nonce)=>({version:1,op:'challenge',nonce:n,milestone,pid:9});
const release=n=>({version:1,op:'release',nonce:n,pid:9});
const initial=mode=>({mode,milestone:'ready',pending:null,used:[]});
function fixture(mode='graceful',milestone='ready'){
 const closed=mode==='graceful'&&milestone==='result_ready';
 return {version:1,nonce,milestone,init:fact(1),client:fact(9),cgroupRoot:{device:'29',inode:'1',fsType:'63677270'},containerMount:{root:'/',mountPoint:'/sys/fs/cgroup',mountDevice:'0:29',filesystem:'cgroup2',readOnly:true,unexpectedOvermounts:false},bounds:{memoryMax:'1073741824',memorySwapMax:'0',cpuQuota:'100000',cpuPeriod:'100000',cpuBurst:'0',pidsMax:'128',cgroupType:'domain'},children:closed?[]:[{...fact(2),role:'node_child',executableClass:'node',ancestorToInit:true},{...fact(3),role:'chromium_main',executableClass:'chromium_main',ancestorToInit:true}],caseResult:{mode,childObserved:true,browserObserved:true,childrenAlive:!closed,childClosed:closed,browserClosed:closed,profileRemoved:closed,childCount:1}};
}
function frozen(v){if(v&&typeof v==='object'){Object.values(v).forEach(frozen);Object.freeze(v);}return v;}
test('all four exact milestone witnesses are accepted without input mutation',async()=>{
 const {witness}=await modulePromise;
 for(const mode of ['graceful','linger'])for(const milestone of ['ready','result_ready']){const w=frozen(fixture(mode,milestone));const before=JSON.stringify(w);assert.equal(witness(w),w);assert.equal(JSON.stringify(w),before);}
});
test('exact challenge and release protocol; extra fields and invalid identity reject',async()=>{
 const {request}=await modulePromise;
 assert.deepEqual(request(challenge()),challenge());assert.deepEqual(request(release(nonce)),release(nonce));
 for(const value of [{...challenge(),extra:true},{...release(nonce),milestone:'ready'},{...challenge(),pid:1},{...challenge(),pid:'9'},{...challenge(),milestone:'unknown'},{...challenge(),nonce:'A'.repeat(64)},{...challenge(),nonce:1},null])assert.throws(()=>request(value));
});
test('graceful two releases gate completion and reject nonce replay; pure immutable transitions',async()=>{
 const {transition}=await modulePromise;
 const s=frozen(initial('graceful'));const a=transition(s,challenge());assert.equal(s.pending,null);assert.deepEqual(s.used,[]);assert.equal(a.pending,nonce);
 assert.throws(()=>transition(a,challenge()));assert.throws(()=>transition(a,release(nextNonce)));
 const b=transition(frozen(a),release(nonce));assert.equal(b.milestone,'result_ready');assert.throws(()=>transition(b,challenge('result_ready',nonce)));assert.throws(()=>transition(b,challenge('ready',nextNonce)));
 const c=transition(frozen(b),challenge('result_ready',nextNonce));const d=transition(frozen(c),release(nextNonce));assert.equal(d.milestone,'done');assert.throws(()=>transition(d,challenge('result_ready','c'.repeat(64))));assert.throws(()=>transition(d,release(nextNonce)));
});
test('linger second milestone cannot authorize self-exit',async()=>{
 const {transition}=await modulePromise;
 const a=transition(initial('linger'),challenge());const b=transition(a,release(nonce));const c=transition(b,challenge('result_ready',nextNonce));assert.throws(()=>transition(c,release(nextNonce)));
});
test('malformed immutable gate state fails closed',async()=>{
 const {transition}=await modulePromise;
 for(const s of [{...initial('graceful'),extra:1},{...initial('graceful'),used:[nonce,nonce]},{...initial('graceful'),used:[1]},{...initial('graceful'),pending:nonce},{...initial('graceful'),mode:'other'}])assert.throws(()=>transition(s,challenge()));
});
test('unknown and mismatched witness evidence rejects',async()=>{
 const {witness}=await modulePromise;
 const mutations=[w=>w.extra=true,w=>w.init.extra=true,w=>w.init.pid=2,w=>w.client.pid=1,w=>w.client.namespaces.pid='pid:[99]',w=>w.init.state='Z',w=>w.init.startTicks='001',w=>w.init.membership='0::/escape',w=>w.init.oomScoreAdj=1,w=>w.cgroupRoot.fsType='unknown',w=>w.cgroupRoot.inode='-1',w=>w.containerMount.readOnly=false,w=>w.containerMount.unexpectedOvermounts=true,w=>w.containerMount.root='/escape',w=>w.bounds.cpuQuota='max',w=>w.bounds.cpuPeriod='99999',w=>w.bounds.cpuBurst='1',w=>w.bounds.memorySwapMax='max',w=>w.bounds.extra=true,w=>w.children.reverse(),w=>w.children[0].ancestorToInit=false,w=>w.children[1].oomScoreAdj=300,w=>w.children[1].pid=2,w=>w.children[1].executableClass='chrome',w=>w.children.push({...w.children[0]}),w=>w.caseResult.childCount=2,w=>w.caseResult.profileRemoved=true];
 for(const mutate of mutations){const w=fixture();mutate(w);const before=JSON.stringify(w);assert.throws(()=>witness(frozen(w)));assert.equal(JSON.stringify(w),before);}
 const result=fixture('graceful','result_ready');result.children=[{...fact(2),role:'node_child',executableClass:'node',ancestorToInit:true}];assert.throws(()=>witness(result));
});

test('fresh same-stage challenge supersedes exactly one pending nonce without mutation',async()=>{
 const {transition}=await modulePromise;
 for(const mode of ['graceful','linger']){
 const a=frozen(transition(initial(mode),challenge()));const snapshot=JSON.stringify(a);
 const b=transition(a,challenge('ready',nextNonce));assert.equal(JSON.stringify(a),snapshot);
 assert.equal(b.milestone,'ready');assert.equal(b.pending,nextNonce);assert.deepEqual(b.used,[nonce,nextNonce]);
 assert.throws(()=>transition(b,release(nonce)));assert.throws(()=>transition(b,challenge('ready',nonce)));assert.throws(()=>transition(b,challenge('ready',nextNonce)));
 assert.throws(()=>transition(b,challenge('result_ready','c'.repeat(64))));
 const result=transition(frozen(b),release(nextNonce));assert.equal(result.milestone,'result_ready');assert.equal(result.pending,null);
 const c=transition(result,challenge('result_ready','c'.repeat(64)));const d=transition(frozen(c),challenge('result_ready','d'.repeat(64)));
 assert.equal(c.pending,'c'.repeat(64));assert.equal(d.pending,'d'.repeat(64));assert.equal(d.milestone,'result_ready');assert.equal(d.used.length,4);
 for(const stale of [nonce,nextNonce,'c'.repeat(64)]){assert.throws(()=>transition(d,release(stale)));assert.throws(()=>transition(d,challenge('result_ready',stale)));}
 assert.throws(()=>transition(d,challenge('ready','e'.repeat(64))));assert.throws(()=>transition(d,challenge('result_ready','d'.repeat(64))));
 if(mode==='graceful')assert.equal(transition(d,release('d'.repeat(64))).milestone,'done');else assert.throws(()=>transition(d,release('d'.repeat(64))));
 }
});
test('seen-nonce history is capped at sixteen, never evicted, and fails closed',async()=>{
 const {transition,MAX_SEEN_NONCES}=await modulePromise;assert.equal(MAX_SEEN_NONCES,16);
 const numbered=i=>i.toString(16).padStart(64,'0');let state=initial('graceful');
 for(let i=1;i<=MAX_SEEN_NONCES;i++)state=transition(frozen(state),challenge('ready',numbered(i)));
 const snapshot=JSON.stringify(state);assert.equal(state.used.length,16);assert.equal(state.pending,numbered(16));assert.deepEqual(state.used,Array.from({length:16},(_,i)=>numbered(i+1)));
 assert.throws(()=>transition(frozen(state),challenge('ready',numbered(17))));assert.equal(JSON.stringify(state),snapshot);
 for(let i=1;i<16;i++){assert.throws(()=>transition(state,release(numbered(i))));assert.throws(()=>transition(state,challenge('ready',numbered(i))));}
 const result=transition(state,release(numbered(16)));assert.equal(result.milestone,'result_ready');assert.equal(result.used.length,16);
 assert.throws(()=>transition(result,challenge('result_ready',numbered(17))));
 const overflow={...initial('graceful'),used:Array.from({length:17},(_,i)=>numbered(i+1))};assert.throws(()=>transition(overflow,challenge('ready',numbered(18))));
});

test('regex-backed witness fields reject arrays, numbers and null with the fixed error',async()=>{
 const {witness}=await modulePromise;
 const paths=[['nonce'],['containerMount','mountDevice'],['cgroupRoot','device'],['cgroupRoot','inode'],['init','startTicks'],['client','startTicks'],['children',0,'startTicks'],['children',1,'startTicks']];
 for(const processPath of [['init'],['client'],['children',0],['children',1]])for(const ns of ['pid','cgroup','mount','time'])paths.push([...processPath,'namespaces',ns]);
 for(const keys of paths){
 const good=fixture();let parent=good;for(const key of keys.slice(0,-1))parent=parent[key];const leaf=keys[keys.length-1],valid=parent[leaf];
 for(const malformed of [[valid],29,null]){
 const w=fixture();let target=w;for(const key of keys.slice(0,-1))target=target[key];target[leaf]=malformed;
 const before=JSON.stringify(w);assert.throws(()=>witness(frozen(w)),{name:'Error',message:'PHASE_WORKER_UNVERIFIED'});assert.equal(JSON.stringify(w),before);
 }
 }
});
test('regex-backed request and gate nonce fields reject coercible types with the fixed error',async()=>{
 const {request,transition}=await modulePromise;
 for(const malformed of [[nonce],29,null]){
 assert.throws(()=>request({...challenge(),nonce:malformed}),{name:'Error',message:'PHASE_WORKER_UNVERIFIED'});
 assert.throws(()=>request({...release(nonce),nonce:malformed}),{name:'Error',message:'PHASE_WORKER_UNVERIFIED'});
 assert.throws(()=>transition({...initial('graceful'),used:[malformed]},challenge()),{name:'Error',message:'PHASE_WORKER_UNVERIFIED'});
 // Null pending is the legitimate no-active-challenge state, not malformed.
 if(malformed!==null)assert.throws(()=>transition({...initial('graceful'),pending:malformed,used:[nonce]},challenge('ready',nextNonce)),{name:'Error',message:'PHASE_WORKER_UNVERIFIED'});
 }
});
