'use strict';
/* Source-only synthetic tests. No Docker, process launch, helper execution or
 * runtime acceptance. Synthetic engine strings are NOT a pinned runtime profile.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const {validateLiveWitness} = require('./kernel-contract.cjs');
const CODE = 'KERNEL_PROOF_UNVERIFIED';
const clone = value => JSON.parse(JSON.stringify(value));
function fixture(mode = 'linger', milestone = 'ready', driver = 'systemd') {
  const id = 'a'.repeat(64), nonce = 'b'.repeat(64);
  const hostNS = {pid:'pid:[100]', cgroup:'cgroup:[101]', mount:'mnt:[102]', time:'time:[103]'};
  const workerNS = {pid:'pid:[200]', cgroup:'cgroup:[201]', mount:'mnt:[202]', time:'time:[103]'};
  const bounds = {memoryMax:'1073741824',memorySwapMax:'0',cpuQuota:'100000',cpuPeriod:'100000',cpuBurst:'0',pidsMax:'128',cgroupType:'domain'};
  const template = driver === 'systemd' ? '/system.slice/docker-{id}.scope' : '/docker/{id}';
  const plan = {
    version:1,
    identity:{exactId:id,exactImageId:'sha256:'+'c'.repeat(64),run:'d'.repeat(64),nonce:'e'.repeat(64),mode},
    engineProfile:{exactServerVersion:'synthetic',exactServerGitCommit:'synthetic',apiVersion:'synthetic',cgroupVersion:'2',cgroupDriver:driver,defaultRuntime:'synthetic',runcVersion:'synthetic',runcGitCommit:'synthetic',containerdVersion:'synthetic',containerdGitCommit:'synthetic',hostCgroupPathTemplate:template,hostCgroupMountRoot:'/',hostCgroupMountPoint:'/sys/fs/cgroup',expectedCpuQuota:'100000',expectedCpuPeriod:'100000',expectedCpuBurst:'0',oomDisableCapability:false},
    config:{Synthetic:true},hostConfigCreated:{OomKillDisable:false},hostConfigPoststart:{OomKillDisable:null},observerNamespaces:clone(hostNS)
  };
  const before = {pid:'4321',startTicks:'900',state:'S',membership:'0::'+template.replace('{id}',id),oomScoreAdj:'0',procAnchor:{device:'5',inode:'500'},cgroupRoot:{device:'28',inode:'600',fsType:'63677270',mountRoot:'/',mountPoint:'/sys/fs/cgroup',mountDevice:'0:28'},observerNamespaces:clone(hostNS),bounds:clone(bounds)};
  const after = clone(before); after.state = 'R';
  function task(pid, ticks, state = 'S') {return {pid,startTicks:ticks,state,membership:'0::/',oomScoreAdj:'0',namespaces:clone(workerNS)};}
  const closed = mode === 'graceful' && milestone === 'result_ready';
  const witness = {version:1,nonce,milestone,init:task('1','900','R'),client:task('10','910','D'),cgroupRoot:{device:'28',inode:'600',fsType:'63677270'},containerMount:{root:'/',mountPoint:'/sys/fs/cgroup',mountDevice:'0:28',filesystem:'cgroup2',readOnly:true,unexpectedOvermounts:false},bounds:clone(bounds),children:closed ? [] : [{...task('11','905','I'),role:'node_child',executableClass:'node',ancestorToInit:true},{...task('12','906'),role:'chromium_main',executableClass:'chromium_main',ancestorToInit:true}],caseResult:{mode,childObserved:true,browserObserved:true,childrenAlive:!closed,childClosed:closed,browserClosed:closed,profileRemoved:closed,childCount:1}};
  return {plan,before,witness,after,nonce,milestone};
}
function check(f) {return validateLiveWitness(f.plan,f.before,f.witness,f.after,f.nonce,f.milestone);}
function deepFreeze(x) {if (x && typeof x === 'object') {Object.freeze(x); for (const v of Object.values(x)) deepFreeze(v);} return x;}
for (const mode of ['graceful','linger']) for (const milestone of ['ready','result_ready']) for (const driver of ['systemd','cgroupfs']) {
  test(`accept complete synthetic ${mode}/${milestone}/${driver}, no mutation`, () => {
    const f = fixture(mode,milestone,driver), original = clone(f);
    deepFreeze(f); assert.equal(check(f),true); assert.deepEqual(f,original);
  });
}
const rejected = [
  ['wrong exact ID', f => {f.plan.identity.exactId = 'f'.repeat(64);}],
  ['wrong host pid identity', f => {f.after.pid = '4322';}],
  ['wrong host ticks', f => {f.after.startTicks = '901';}],
  ['wrong init ticks', f => {f.witness.init.startTicks = '901';}],
  ['wrong proc device', f => {f.after.procAnchor.device = '6';}],
  ['wrong proc inode', f => {f.after.procAnchor.inode = '501';}],
  ['wrong mapped cgroup inode', f => {f.after.cgroupRoot.inode = '601';}],
  ['wrong worker cgroup inode', f => {f.witness.cgroupRoot.inode = '601';}],
  ['wrong worker cgroup device', f => {f.witness.cgroupRoot.device = '29';}],
  ['wrong cgroup magic', f => {f.before.cgroupRoot.fsType = '00000000';}],
  ['wrong worker cgroup magic', f => {f.witness.cgroupRoot.fsType = '00000000';}],
  ['wrong host mount root', f => {f.before.cgroupRoot.mountRoot = '/docker';}],
  ['wrong host mount point', f => {f.before.cgroupRoot.mountPoint = '/elsewhere';}],
  ['wrong host mount device', f => {f.before.cgroupRoot.mountDevice = '1:28';}],
  ['wrong container mount device', f => {f.witness.containerMount.mountDevice = '0:29';}],
  ['wrong container mount root', f => {f.witness.containerMount.root = '/docker';}],
  ['wrong container mount point', f => {f.witness.containerMount.mountPoint = '/elsewhere';}],
  ['wrong container mount filesystem', f => {f.witness.containerMount.filesystem = 'tmpfs';}],
  ['writable container mount', f => {f.witness.containerMount.readOnly = false;}],
  ['unexpected overmount', f => {f.witness.containerMount.unexpectedOvermounts = true;}],
  ['host wrong bound', f => {f.before.bounds.memoryMax = 'max';}],
  ['after wrong bound', f => {f.after.bounds.pidsMax = '129';}],
  ['worker wrong bound', f => {f.witness.bounds.cpuBurst = '1';}],
  ['non-domain cgroup', f => {f.witness.bounds.cgroupType = 'threaded';}],
  ['stale nonce correlation', f => {f.witness.nonce = 'f'.repeat(64);}],
  ['malformed expected nonce', f => {f.nonce = 'bad';}],
  ['wrong milestone', f => {f.witness.milestone = 'result_ready';}],
  ['missing expected milestone', f => {delete f.milestone;}],
  ['unknown milestone', f => {f.milestone = 'unrecognized';}],
  ['missing facts field', f => {delete f.before.procAnchor;}],
  ['extra facts field', f => {f.before.extra = true;}],
  ['extra witness field', f => {f.witness.extra = true;}],
  ['missing witness field', f => {delete f.witness.client;}],
  ['extra nested field', f => {f.witness.init.namespaces.extra = 'x';}],
  ['helper envelope is not HostFacts', f => {f.before = {version:1,op:'begun',facts:f.before};}],
  ['numeric PID shape', f => {f.before.pid = 4321;}],
  ['noncanonical ticks', f => {f.witness.init.startTicks = '0900';}],
  ['uint64 overflow', f => {f.before.procAnchor.inode = '18446744073709551616';}],
  ['host zombie', f => {f.before.state = 'Z';}],
  ['after dead', f => {f.after.state = 'X';}],
  ['worker zombie', f => {f.witness.client.state = 'Z';}],
  ['wrong host cgroup membership', f => {f.before.membership += '/extra';}],
  ['wrong init membership', f => {f.witness.init.membership = '0::/docker';}],
  ['wrong child membership', f => {f.witness.children[0].membership = '0::/escape';}],
  ['wrong init role PID', f => {f.witness.init.pid = '2';}],
  ['client masquerades as init', f => {f.witness.client.pid = '1';}],
  ['host and worker PID namespace equal', f => {f.witness.init.namespaces.pid = f.plan.observerNamespaces.pid; f.witness.client.namespaces.pid = f.plan.observerNamespaces.pid;}],
  ['observer namespace drift', f => {f.after.observerNamespaces.mount = 'mnt:[999]';}],
  ['wrong client namespace', f => {f.witness.client.namespaces.cgroup = 'cgroup:[999]';}],
  ['wrong child namespace', f => {f.witness.children[0].namespaces.mount = 'mnt:[999]';}],
  ['worker time incomparable', f => {f.witness.init.namespaces.time = 'time:[999]'; f.witness.client.namespaces.time = 'time:[999]';}],
  ['namespace type mismatch', f => {f.before.observerNamespaces.mount = 'mount:[102]';}],
  ['missing child', f => {f.witness.children.pop();}],
  ['extra child', f => {f.witness.children.push(clone(f.witness.children[0]));}],
  ['unknown child role', f => {f.witness.children[0].role = 'browser_descendant';}],
  ['duplicate role', f => {f.witness.children[1].role = 'node_child';}],
  ['duplicate child PID', f => {f.witness.children[1].pid = f.witness.children[0].pid;}],
  ['child is exec client', f => {f.witness.children[0].pid = f.witness.client.pid;}],
  ['wrong executable class', f => {f.witness.children[0].executableClass = 'chromium_main';}],
  ['unverified ancestry', f => {f.witness.children[0].ancestorToInit = false;}],
  ['child wrong oom score', f => {f.witness.children[0].oomScoreAdj = '1';}],
  ['init wrong oom score', f => {f.witness.init.oomScoreAdj = '1';}],
  ['host wrong oom score', f => {f.before.oomScoreAdj = '-1';}],
  ['wrong case mode', f => {f.witness.caseResult.mode = 'graceful';}],
  ['wrong ready result', f => {f.witness.caseResult.childClosed = true;}],
  ['wrong case child count', f => {f.witness.caseResult.childCount = 2;}],
  ['unknown plan field', f => {f.plan.mode = 'linger';}],
  ['wrong plan version', f => {f.plan.version = 2;}],
  ['unknown identity field', f => {f.plan.identity.other = true;}],
  ['unknown profile field', f => {f.plan.engineProfile.other = true;}],
  ['unsupported driver', f => {f.plan.engineProfile.cgroupDriver = 'unknown';}],
  ['wrong profile path', f => {f.plan.engineProfile.hostCgroupPathTemplate = '/docker/{id}';}],
  ['wrong profile CPU', f => {f.plan.engineProfile.expectedCpuQuota = '50000';}],
  ['unsupported oom profile', f => {f.plan.engineProfile.oomDisableCapability = true;}],
  ['missing profile field', f => {delete f.plan.engineProfile.exactServerVersion;}],
  ['inherited plan shape', f => {f.plan = Object.create(f.plan);}],
  ['accessor input rejected without invocation', f => {Object.defineProperty(f.before,'pid',{enumerable:true,get(){throw new Error('must not execute');}});}],
  ['sparse children', f => {delete f.witness.children[0];}],
  ['extra children array key', f => {f.witness.children.extra = true;}]
];
for (const [name, mutate] of rejected) test(`reject ${name}: exact ${CODE}`, () => {
  const f = fixture(); mutate(f);
  assert.throws(() => check(f), e => e instanceof Error && e.message === CODE && e.code === CODE);
});
test('graceful result rejects live children and wrong close claims', () => {
  for (const mutate of [f => {f.witness.children = fixture().witness.children;},f => {f.witness.caseResult.browserClosed = false;},f => {f.witness.caseResult.profileRemoved = false;}]) {
    const f = fixture('graceful','result_ready'); mutate(f);
    assert.throws(() => check(f), e => e.message === CODE && e.code === CODE);
  }
});
test('rejection does not mutate JSON inputs', () => {
  const f = fixture(); f.witness.bounds.memoryMax = '2'; const original = clone(f); deepFreeze(f);
  assert.throws(() => check(f), e => e.message === CODE && e.code === CODE); assert.deepEqual(f,original);
});
test('correlation is not replay history: same valid input stays pure', () => {
  const f = deepFreeze(fixture()); assert.equal(check(f),true); assert.equal(check(f),true);
});
