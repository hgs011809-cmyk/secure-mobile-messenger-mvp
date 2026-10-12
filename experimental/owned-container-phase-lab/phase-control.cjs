'use strict';
// Trusted isolated Linux CI only. No atomic/continuous hostile-host guarantee.
// Import is pure: no commands, filesystem reads, or helper loading.
const fs = require('node:fs/promises');
const { constants, writeSync } = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { randomBytes, createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const ERROR = 'PHASE_CONTAINMENT_UNVERIFIED';
const ID = /^[a-f0-9]{64}$/;
const IMAGE = /^sha256:[a-f0-9]{64}$/;
const MODES = ['graceful', 'linger'];
const WORKER = '/opt/fixture/phase-worker.mjs';
const PROFILE_KEYS = ['exactServerVersion','exactServerGitCommit','apiVersion','cgroupVersion','cgroupDriver','defaultRuntime','runcVersion','runcGitCommit','containerdVersion','containerdGitCommit','hostCgroupPathTemplate','hostCgroupMountRoot','hostCgroupMountPoint','expectedCpuQuota','expectedCpuPeriod','expectedCpuBurst','oomDisableCapability'];
const PLAN_KEYS = ['version','identity','engineProfile','config','hostConfigCreated','hostConfigPoststart','observerNamespaces'];
const NS = ['pid','cgroup','mount','time'];
const clone = v => JSON.parse(JSON.stringify(v));
function reject() { throw new Error(ERROR); }
function object(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  if (![Object.prototype,null].includes(Object.getPrototypeOf(v))) return false;
  return Reflect.ownKeys(v).every(k => typeof k === 'string' && Object.getOwnPropertyDescriptor(v,k)?.enumerable === true && Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'));
}
function keys(v, k) { if (!object(v) || !equal(Object.keys(v).sort(), [...k].sort())) reject(); }
function validateNamespaces(n) {
  keys(n, NS);
  for (const k of NS) if (typeof n[k] !== 'string' || !new RegExp('^'+(k === 'mount' ? 'mnt' : k)+':\\[[1-9][0-9]*\\]$').test(n[k])) reject();
}
function validateEngineProfile(p) {
  keys(p, PROFILE_KEYS);
  for (const k of ['exactServerVersion','exactServerGitCommit','apiVersion','runcVersion','runcGitCommit','containerdVersion','containerdGitCommit']) {
    if (typeof p[k] !== 'string' || p[k].length > 128 || !/^[A-Za-z0-9][A-Za-z0-9.+_~-]*$/.test(p[k]) || /unknown|unreviewed|placeholder|latest/i.test(p[k])) reject();
  }
  if (!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$/.test(p.exactServerVersion) || !/^1\.\d+$/.test(p.apiVersion) || p.cgroupVersion !== '2' || !['systemd','cgroupfs'].includes(p.cgroupDriver) || p.defaultRuntime !== 'runc' || p.oomDisableCapability !== false) reject();
  const template = p.cgroupDriver === 'systemd' ? '/system.slice/docker-{id}.scope' : '/docker/{id}';
  if (p.hostCgroupPathTemplate !== template || p.hostCgroupMountRoot !== '/' || p.hostCgroupMountPoint !== '/sys/fs/cgroup' || p.expectedCpuQuota !== '100000' || p.expectedCpuPeriod !== '100000' || p.expectedCpuBurst !== '0') reject();
  return true;
}
function validateEngineObservation(p, info, version) {
  validateEngineProfile(p);
  if (!object(info) || !object(version) || !object(version.Server)) reject();
  if (info.ServerVersion !== p.exactServerVersion || info.CgroupVersion !== p.cgroupVersion || info.CgroupDriver !== p.cgroupDriver || info.DefaultRuntime !== p.defaultRuntime || info.OomKillDisable !== p.oomDisableCapability) reject();
  const s = version.Server;
  if (s.Version !== p.exactServerVersion || s.GitCommit !== p.exactServerGitCommit || s.ApiVersion !== p.apiVersion || s.Os !== 'linux' || !Array.isArray(s.Components)) reject();
  for (const [name, v, g] of [['Engine',p.exactServerVersion,p.exactServerGitCommit],['runc',p.runcVersion,p.runcGitCommit],['containerd',p.containerdVersion,p.containerdGitCommit]]) {
    const entries = s.Components.filter(c => object(c) && c.Name === name);
    if (entries.length !== 1 || entries[0].Version !== v || entries[0].Details?.GitCommit !== g) reject();
  }
  if (!object(info.Runtimes) || !Object.hasOwn(info.Runtimes,p.defaultRuntime)) reject();
  return true;
}
function environment(env) {
  if (!Array.isArray(env)) reject();
  const m = new Map();
  for (const s of env) {
    if (typeof s !== 'string' || s.length > 4096) reject();
    const at = s.indexOf('='); const k = s.slice(0,at);
    if (at < 1 || !/^[A-Z_]+$/.test(k) || m.has(k)) reject();
    m.set(k,s.slice(at+1));
  }
  return m;
}
function validateImageEnvironment(env) {
  const m = environment(env);
  if (!equal([...m.keys()].sort(), ['NODE_VERSION','PATH','PLAYWRIGHT_BROWSERS_PATH','YARN_VERSION']) || m.get('PATH') !== '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' || !/^22\.\d+\.\d+$/.test(m.get('NODE_VERSION')) || !/^1\.\d+\.\d+$/.test(m.get('YARN_VERSION')) || m.get('PLAYWRIGHT_BROWSERS_PATH') !== '/opt/playwright') reject();
  return true;
}
function validateIdentity(i) {
  keys(i,['exactId','exactImageId','run','nonce','mode']);
  if (typeof i.exactId !== 'string' || typeof i.exactImageId !== 'string' || typeof i.run !== 'string' || typeof i.nonce !== 'string' || !ID.test(i.exactId) || !IMAGE.test(i.exactImageId) || !ID.test(i.run) || !ID.test(i.nonce) || !MODES.includes(i.mode)) reject();
}
function labels(i) { return {'owned-containment.run':i.run,'owned-containment.nonce':i.nonce,'owned-containment.mode':i.mode}; }
function security(c,h,i,n,oom) {
  if (!object(c) || !object(h)) reject();
  if (c.User !== '10001:10001' || !equal(c.Labels,labels(i)) || !equal(c.Entrypoint,['node',WORKER]) || !equal(c.Cmd,[i.mode]) || c.WorkingDir !== '/opt/fixture' || c.Tty !== false || c.OpenStdin !== false) reject();
  const env = environment(c.Env);
  const extra = NS.map(k => ['HOST_'+k.toUpperCase()+'_NAMESPACE',n[k]]);
  for (const [k,v] of extra) if (env.get(k) !== v) reject();
  const baseline = c.Env.filter(s => !extra.some(([k]) => s.startsWith(k+'=')));
  validateImageEnvironment(baseline);
  if (env.size !== 8) reject();
  if (h.Privileged !== false || h.ReadonlyRootfs !== true || h.NetworkMode !== 'none' || h.PidMode !== '' || h.IpcMode !== 'private' || h.UsernsMode !== '' || h.UTSMode !== '' || h.CgroupnsMode !== 'private' || h.AutoRemove !== false || h.Init !== false || h.PublishAllPorts !== false) reject();
  if (!equal(h.CapDrop,['ALL']) || !equal(h.SecurityOpt,['no-new-privileges']) || h.Memory !== 1073741824 || h.MemorySwap !== 1073741824 || h.NanoCpus !== 1000000000 || h.PidsLimit !== 128 || h.ShmSize !== 134217728 || !Object.hasOwn(h,'OomKillDisable') || h.OomKillDisable !== oom || !Object.hasOwn(h,'OomScoreAdj') || h.OomScoreAdj !== 0) reject();
  if (!equal(h.Tmpfs,{'/tmp':'rw,noexec,nosuid,nodev,size=256m,mode=1777'})) reject();
  // No added capabilities. Empty-array representation is NOT admitted without
  // an explicit reviewed source guarantee; currently the admitted value is null.
  if (!Object.hasOwn(h,'CapAdd') || h.CapAdd !== null) reject();
  for (const k of ['Binds','Devices','DeviceRequests','DeviceCgroupRules','VolumesFrom','Links','ExtraHosts','Mounts','GroupAdd','Ulimits','BlkioWeightDevice','BlkioDeviceReadBps','BlkioDeviceWriteBps','BlkioDeviceReadIOps','BlkioDeviceWriteIOps']) {
    if (!Object.hasOwn(h,k) || (h[k] !== null && !equal(h[k],[]))) reject();
  }
  for (const k of ['Dns','DnsOptions','DnsSearch']) if (!Object.hasOwn(h,k) || !equal(h[k],[])) reject();
  for (const k of ['PortBindings','Sysctls','StorageOpt','Annotations']) if (!Object.hasOwn(h,k) || (h[k] !== null && !equal(h[k],{}))) reject();
  for (const k of ['CpuShares','CpuPeriod','CpuQuota','CpuRealtimePeriod','CpuRealtimeRuntime','MemoryReservation','BlkioWeight','CpuCount','CpuPercent','IOMaximumIOps','IOMaximumBandwidth']) if (!Object.hasOwn(h,k) || h[k] !== 0) reject();
  for (const k of ['CgroupParent','Cgroup','ContainerIDFile','CpusetCpus','CpusetMems','Isolation']) if (!Object.hasOwn(h,k) || h[k] !== '') reject();
  if (!Object.hasOwn(h,'MemorySwappiness') || h.MemorySwappiness !== null || !equal(h.RestartPolicy,{Name:'no',MaximumRetryCount:0}) || (c.Volumes != null && !equal(c.Volumes,{}))) reject();
}
function validatePlan(p) {
  keys(p,PLAN_KEYS);
  if (p.version !== 1) reject();
  validateIdentity(p.identity); validateEngineProfile(p.engineProfile); validateNamespaces(p.observerNamespaces);
  security(p.config,p.hostConfigCreated,p.identity,p.observerNamespaces,false);
  security(p.config,p.hostConfigPoststart,p.identity,p.observerNamespaces,null);
  if (p.hostConfigCreated.Runtime !== p.engineProfile.defaultRuntime || p.hostConfigPoststart.Runtime !== p.engineProfile.defaultRuntime) reject();
  const post = clone(p.hostConfigCreated); post.OomKillDisable = null;
  if (!equal(post,p.hostConfigPoststart)) reject();
  return true;
}
function state(s) {
  if (!object(s) || typeof s.Running !== 'boolean' || !Number.isSafeInteger(s.Pid) || s.Pid < 0 || !Number.isInteger(s.ExitCode) || s.ExitCode < 0 || s.ExitCode > 255 || s.Paused !== false || s.Restarting !== false || s.OOMKilled !== false || s.Dead !== false || s.Error !== '') reject();
  if (s.Running ? (s.Status !== 'running' || s.Pid <= 0 || s.ExitCode !== 0) : (s.Pid !== 0 || !['created','exited'].includes(s.Status))) reject();
  if (s.Status === 'created' && s.ExitCode !== 0) reject();
}
function metadata(p,o) {
  if (!object(o) || o.Id !== p.identity.exactId || o.Image !== p.identity.exactImageId || !equal(o.Config,p.config) || !Array.isArray(o.Mounts) || !object(o.NetworkSettings?.Networks) || !equal(Object.keys(o.NetworkSettings.Networks),['none'])) reject();
  if (o.Mounts.some(m => !object(m) || m.Type !== 'tmpfs' || !['/tmp','/dev/shm'].includes(m.Destination))) reject();
  state(o.State);
}
function validatePhase(p,o,phase,purpose='case') {
  validatePlan(p);
  if (!['created','start-intent','started','terminal'].includes(phase) || !['case','cleanup'].includes(purpose)) reject();
  if (phase === 'start-intent' && purpose !== 'cleanup') reject();
  metadata(p,o);
  const h = o.HostConfig;
  if (phase === 'created' && (!equal(h,p.hostConfigCreated) || o.State.Status !== 'created')) reject();
  if (phase === 'start-intent' && !equal(h,p.hostConfigCreated) && !equal(h,p.hostConfigPoststart)) reject();
  if (['started','terminal'].includes(phase) && !equal(h,p.hostConfigPoststart)) reject();
  security(o.Config,h,p.identity,p.observerNamespaces,h?.OomKillDisable);
  if (phase === 'started' && ((purpose === 'case' && !o.State.Running) || (!o.State.Running && o.State.Status !== 'exited'))) reject();
  if (phase === 'terminal' && (o.State.Running || o.State.Status !== 'exited')) reject();
  return true;
}
function buildPlan(identity,profile,created,namespaces) {
  validateIdentity(identity); validateEngineProfile(profile); validateNamespaces(namespaces);
  security(created.Config,created.HostConfig,identity,namespaces,false);
  const post = clone(created.HostConfig); post.OomKillDisable = null;
  const p = {version:1,identity:clone(identity),engineProfile:clone(profile),config:clone(created.Config),hostConfigCreated:clone(created.HostConfig),hostConfigPoststart:post,observerNamespaces:clone(namespaces)};
  validatePhase(p,created,'created'); return p;
}
function validateJournal(p,j) {
  validatePlan(p); keys(j,['startIntent','started','terminal']);
  for (const k of ['startIntent','started','terminal']) if (j[k] !== null) {
    keys(j[k],['version','op','exactId']);
    if (j[k].version !== 1 || j[k].op !== ({startIntent:'start-intent',started:'started',terminal:'terminal'})[k] || j[k].exactId !== p.identity.exactId) reject();
  }
  if ((j.started && !j.startIntent) || (j.terminal && !j.started)) reject();
  return j.terminal ? 'terminal' : j.started ? 'started' : j.startIntent ? 'start-intent' : 'created';
}
function validateRelease(v,nonce,milestone) {
  if (!ID.test(nonce) || !['ready','result_ready'].includes(milestone)) reject();
  keys(v,['version','op','nonce','milestone']);
  if (!equal(v,{version:1,op:'released',nonce,milestone})) reject(); return true;
}
// Marker validation is a pure consistency contract, NOT independent lifecycle proof.
// Only runtime live() creates accepted markers after an owned helper session.
function validateCase(p,j,proofs,terminal) {
  if (validateJournal(p,j) !== 'terminal') reject();
  if (!Array.isArray(proofs) || proofs.length !== 2) reject();
  const nonces = new Set();
  for (let i=0;i<2;i++) {
    keys(proofs[i],['version','op','exactId','nonce','milestone']);
    if (proofs[i].version !== 1 || proofs[i].op !== 'accepted' || proofs[i].exactId !== p.identity.exactId || !ID.test(proofs[i].nonce) || nonces.has(proofs[i].nonce) || proofs[i].milestone !== ['ready','result_ready'][i]) reject();
    nonces.add(proofs[i].nonce);
  }
  validatePhase(p,terminal,'terminal');
  if (terminal.State.ExitCode !== (p.identity.mode === 'graceful' ? 0 : 137)) reject();
  return true;
}
// Explicit CI pipeline provenance guards, not binary authentication against an
// adversarial host/root. Workflow review must pin ALL reviewed sources and export
// these expectations solely from the pinned-C private compilation step.
function validateBuildProvenance(expectedSource,expectedBinary,observedSource,observedBinary) {
  for (const v of [expectedSource,expectedBinary,observedSource,observedBinary]) if (typeof v !== 'string' || v.length !== 64 || !ID.test(v)) reject();
  if (expectedSource !== observedSource || expectedBinary !== observedBinary) reject();
  return true;
}
function validateBuildFileFacts(f,uid,kind) {
  keys(f,['regular','symlink','uid','mode','nlink','size']);
  if (!Number.isSafeInteger(uid) || uid < 0 || !['source','binary'].includes(kind) || f.regular !== true || f.symlink !== false || f.uid !== uid || f.nlink !== 1 || !Number.isSafeInteger(f.size) || f.size <= 0 || f.size > (kind === 'source' ? 1048576 : 16777216)) reject();
  if (kind === 'binary' ? f.mode !== 0o700 : ![0o600,0o644].includes(f.mode)) reject();
  return true;
}
function validateHelperRecord(h,sourceSha256,binarySha256) {
  keys(h,['version','sourceSha256','binarySha256']);
  if (h.version !== 1) reject();
  validateBuildProvenance(sourceSha256,binarySha256,h.sourceSha256,h.binarySha256);
  return true;
}
module.exports = { ERROR, buildPlan, validatePlan, validatePhase, validateJournal, validateCase, validateRelease, validateEngineProfile, validateEngineObservation, validateImageEnvironment, validateBuildProvenance, validateBuildFileFacts, validateHelperRecord };

// Runtime authority is deliberately not exported. All public failures are fixed enums.
const STAGES = new Set(['gate','profile','helper','create','persist','start','proof','release','terminal','cleanup','residual','erase']);
let diag = {stage:'gate',createdCount:0,startedCount:0,completedCount:0};
let capturedBytes=0, transportCount=0; // Fixed total per-invocation private capture bounds.
function stage(s) { if (!STAGES.has(s)) reject(); diag.stage = s; }
async function privateDirectory(supplied,base) {
  if (!supplied || !process.env.RUNNER_TEMP || !path.isAbsolute(supplied) || !path.isAbsolute(process.env.RUNNER_TEMP)) reject();
  const parent = await fs.realpath(process.env.RUNNER_TEMP), root = path.resolve(supplied);
  if (path.dirname(root) !== parent || !new RegExp('^'+base+'\\.[A-Za-z0-9_-]+$').test(path.basename(root))) reject();
  const s = await fs.lstat(root);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o777) !== 0o700 || await fs.realpath(root) !== root) reject();
  return root;
}
async function roots() {
  if (process.platform !== 'linux' || process.env.CI !== 'true' || process.env.GITHUB_ACTIONS !== 'true' || process.env.GITHUB_REF !== 'refs/heads/lab-matrix-cleanup-followup' || typeof process.getuid !== 'function' || process.getuid() === 0) reject();
  const root = await privateDirectory(process.env.PRIVATE_PHASE_ROOT,'owned-phase');
  const logs = await privateDirectory(process.env.PRIVATE_PHASE_LOG_ROOT,'owned-phase-logs');
  if (root === logs) reject(); return {root,logs};
}
async function durable(root,name,v) {
  const f = await fs.open(path.join(root,name),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try { await f.writeFile(typeof v === 'string' ? v : JSON.stringify(v)); await f.sync(); } finally { await f.close(); }
  const d = await fs.open(root,constants.O_RDONLY|constants.O_DIRECTORY);
  try { await d.sync(); } finally { await d.close(); }
}
async function readPrivate(file,mode=0o600,max=4194304) {
  const f = await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const s = await f.stat();
    if (!s.isFile() || s.uid !== process.getuid() || (s.mode & 0o7777) !== mode || s.nlink !== 1 || s.size > max) reject();
    const b = await f.readFile(); if (b.length > max) reject(); return b;
  } finally { await f.close(); }
}
async function json(root,name,optional=false) {
  try { return JSON.parse((await readPrivate(path.join(root,name))).toString('utf8')); }
  catch (e) { if (optional && e.code === 'ENOENT') return null; reject(); }
}
function expectedBuild() {
  const sourceSha256=process.env.PHASE_KERNEL_SOURCE_SHA256;
  const binarySha256=process.env.PHASE_KERNEL_BINARY_SHA256;
  validateBuildProvenance(sourceSha256,binarySha256,sourceSha256,binarySha256);
  return {sourceSha256,binarySha256};
}
async function buildFileHash(file,kind) {
  const before=await fs.lstat(file);
  const facts=s=>({regular:s.isFile(),symlink:s.isSymbolicLink(),uid:s.uid,mode:s.mode & 0o7777,nlink:s.nlink,size:s.size});
  validateBuildFileFacts(facts(before),process.getuid(),kind);
  const f=await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const s=await f.stat(); validateBuildFileFacts(facts(s),process.getuid(),kind);
    if (s.dev !== before.dev || s.ino !== before.ino || s.size !== before.size || s.mode !== before.mode) reject();
    const bytes=await f.readFile(); const after=await f.stat();
    validateBuildFileFacts(facts(after),process.getuid(),kind);
    if (bytes.length !== s.size || after.size !== s.size || after.mtimeMs !== s.mtimeMs || after.ctimeMs !== s.ctimeMs) reject();
    return createHash('sha256').update(bytes).digest('hex');
  } finally { await f.close(); }
}
async function verifiedBuild(logs) {
  const expected=expectedBuild();
  const sourceSha256=await buildFileHash(path.join(__dirname,'kernel-fd-probe.c'),'source');
  const binarySha256=await buildFileHash(path.join(logs,'kernel-probe'),'binary');
  validateBuildProvenance(expected.sourceSha256,expected.binarySha256,sourceSha256,binarySha256);
  return {sourceSha256,binarySha256};
}
async function verifyHelper(root,logs) {
  const actual=await verifiedBuild(logs);
  // Persisted record is consistency-only, NEVER the origin of trusted expectations.
  validateHelperRecord(await json(root,'helper.json'),actual.sourceSha256,actual.binarySha256);
}
// Capture both streams privately with a combined 4MiB bound. Cancellation targets
// only this directly owned Docker CLI/helper child, never any host workload PID.
async function session(logs,command,args,interactive=false,timeout=15000) {
  if (++transportCount > 512) reject();
  const token = randomBytes(16).toString('hex');
  const out = await fs.open(path.join(logs,token+'.stdout'),'wx',0o600);
  let err;
  try { err = await fs.open(path.join(logs,token+'.stderr'),'wx',0o600); }
  catch (e) { await out.close(); throw e; }
  const env = {...process.env,DOCKER_HOST:'unix:///var/run/docker.sock'};
  delete env.DOCKER_CONTEXT; delete env.DOCKER_TLS_VERIFY; delete env.DOCKER_CERT_PATH;
  let child, timer, size=0, stdout='', stderr='', pending='', failure=false, exited=false;
  const lines=[], waiting=[];
  let resolveDone;
  const done = new Promise(r => { resolveDone=r; });
  function dispatch() { while (waiting.length && lines.length) waiting.shift().resolve(lines.shift()); }
  function abort() {
    failure=true;
    if (child && !exited) { child.stdin?.destroy(); child.stdout?.destroy(); child.stderr?.destroy(); child.kill('SIGKILL'); }
    while (waiting.length) waiting.shift().reject(new Error(ERROR));
  }
  function capture(handle,isOut) { return b => {
    size += b.length; capturedBytes += b.length;
    if (size > 4194304 || capturedBytes > 67108864) { abort(); return; }
    try {
      let offset=0; while (offset < b.length) { const n=writeSync(handle.fd,b,offset,b.length-offset); if (n <= 0) reject(); offset+=n; }
      if (isOut) { stdout += b.toString('utf8'); pending += b.toString('utf8');
        let at; while ((at=pending.indexOf('\n')) !== -1) { lines.push(pending.slice(0,at)); pending=pending.slice(at+1); } dispatch();
      } else stderr += b.toString('utf8');
    } catch { abort(); }
  }; }
  try { child=spawn(command,args,{stdio:[interactive?'pipe':'ignore','pipe','pipe'],env}); }
  catch { await out.close(); await err.close(); reject(); }
  child.stdout.on('data',capture(out,true)); child.stderr.on('data',capture(err,false));
  child.on('error',abort); child.stdin?.on('error',abort);
  child.on('close',async (code,signal) => {
    exited=true; clearTimeout(timer);
    if (pending && interactive) failure=true;
    while (waiting.length) waiting.shift().reject(new Error(ERROR));
    try { await out.sync(); await err.sync(); await out.close(); await err.close(); }
    catch { failure=true; }
    resolveDone({code,signal,stdout,stderr,failed:failure});
  });
  timer=setTimeout(abort,timeout);
  return {done,abort,async line() {
    if (failure || (exited && !lines.length)) reject();
    if (lines.length) return lines.shift();
    return new Promise((resolve,rejectLine) => waiting.push({resolve,reject:rejectLine}));
  },finish() { if (failure || exited || !interactive) reject(); child.stdin.end('finish\n'); }};
}
function successful(r) { if (r.failed || r.code !== 0 || r.signal !== null || r.stderr !== '') reject(); return r.stdout; }
function oneJSON(raw) {
  if (typeof raw !== 'string' || raw.length > 4194304) reject();
  const s = raw.endsWith('\n') ? raw.slice(0,-1) : raw;
  if (!s || s.includes('\n') || s.includes('\r')) reject();
  try { return JSON.parse(s); } catch { reject(); }
}
async function docker(logs,args,timeout=15000) {
  const s = await session(logs,'docker',['--host','unix:///var/run/docker.sock',...args],false,timeout);
  return s.done;
}
async function engine(logs,p) {
  const info = oneJSON(successful(await docker(logs,['info','--format','{{json .}}'])));
  const version = oneJSON(successful(await docker(logs,['version','--format','{{json .}}'])));
  validateEngineObservation(p,info,version);
}
async function inspect(logs,id,absent=false) {
  if (!ID.test(id)) reject();
  const r = await docker(logs,['container','inspect',id]);
  if (!r.failed && absent && r.code === 1 && r.signal === null && r.stdout.trim() === '[]' && ['Error: No such container: '+id,'Error response from daemon: No such container: '+id].includes(r.stderr.trim())) return null;
  let v; try { v=JSON.parse(successful(r)); } catch { reject(); }
  if (!Array.isArray(v) || v.length !== 1 || v[0]?.Id !== id) reject(); return v[0];
}
async function load(root,mode) {
  const p = await json(root,mode+'.plan.json'); validatePlan(p);
  if (p.identity.mode !== mode) reject();
  const exactId = (await readPrivate(path.join(root,mode+'.id'))).toString('utf8');
  if (exactId !== p.identity.exactId+'\n') reject();
  const j={startIntent:await json(root,mode+'.start-intent.json',true),started:await json(root,mode+'.started.json',true),terminal:await json(root,mode+'.terminal.json',true)};
  const phase = validateJournal(p,j);
  return {p,j,phase};
}
async function checked(logs,owned,cleanup=false,absent=false) {
  const o=await inspect(logs,owned.p.identity.exactId,absent);
  if (o) validatePhase(owned.p,o,owned.phase,cleanup?'cleanup':'case');
  return o;
}
function record(p,op) { return {version:1,op,exactId:p.identity.exactId}; }
async function nonceHistory(root) {
  const seen=new Set();
  for (const name of await fs.readdir(root)) if (name.startsWith('challenge.')) {
    if (!/^challenge\.[a-f0-9]{64}\.json$/.test(name)) reject();
    const v=await json(root,name); keys(v,['version','op','exactId','nonce','milestone','purpose']);
    if (v.version !== 1 || v.op !== 'challenge' || !ID.test(v.exactId) || !ID.test(v.nonce) || name !== 'challenge.'+v.nonce+'.json' || !['ready','result_ready'].includes(v.milestone) || !['case','cleanup'].includes(v.purpose) || seen.has(v.nonce)) reject();
    seen.add(v.nonce);
  }
  return seen;
}
async function live(root,logs,owned,milestone,purpose='case') {
  stage('proof');
  if (!['ready','result_ready'].includes(milestone) || !['case','cleanup'].includes(purpose)) reject();
  const cleanup=purpose==='cleanup';
  const before=await checked(logs,owned,cleanup);
  if (!before?.State.Running) reject();
  await verifyHelper(root,logs);
  const history=await nonceHistory(root); let nonce;
  do { nonce=randomBytes(32).toString('hex'); } while (history.has(nonce));
  await durable(root,'challenge.'+nonce+'.json',{version:1,op:'challenge',exactId:owned.p.identity.exactId,nonce,milestone,purpose});
  const s=await session(logs,path.join(logs,'kernel-probe'),[owned.p.identity.exactId,String(before.State.Pid),owned.p.engineProfile.cgroupDriver],true,30000);
  try {
    const begun=oneJSON(await s.line()); keys(begun,['version','op','facts']);
    if (begun.version !== 1 || begun.op !== 'begun' || begun.facts?.pid !== String(before.State.Pid)) reject();
    const witness=oneJSON(successful(await docker(logs,['container','exec',owned.p.identity.exactId,'node',WORKER,'--challenge',nonce,milestone],15000)));
    s.finish();
    const finished=oneJSON(await s.line()); keys(finished,['version','op','facts','processStayedAlive']);
    if (finished.version !== 1 || finished.op !== 'finished' || finished.processStayedAlive !== true) reject();
    const result=await s.done;
    if (result.failed || result.code !== 0 || result.stderr !== '' || result.stdout !== JSON.stringify(begun)+'\n'+JSON.stringify(finished)+'\n') {
      // Envelope formatting may contain spaces. Compare parsed complete lines instead.
      const lines=result.stdout.trimEnd().split('\n');
      if (result.failed || result.code !== 0 || result.stderr !== '' || lines.length !== 2 || !equal(oneJSON(lines[0]),begun) || !equal(oneJSON(lines[1]),finished)) reject();
    }
    const after=await checked(logs,owned,cleanup);
    if (!after?.State.Running || after.State.Pid !== before.State.Pid || !equal(after.HostConfig,before.HostConfig) || finished.facts?.pid !== String(after.State.Pid)) reject();
    require('./kernel-contract.cjs').validateLiveWitness(owned.p,begun.facts,witness,finished.facts,nonce,milestone);
    const accepted={version:1,op:'accepted',exactId:owned.p.identity.exactId,nonce,milestone};
    await durable(root,'accepted.'+nonce+'.json',accepted); return accepted;
  } catch { s.abort(); await s.done; reject(); }
}
async function release(root,logs,owned,proof) {
  stage('release');
  const v={version:1,op:'release-intent',exactId:owned.p.identity.exactId,nonce:proof.nonce,milestone:proof.milestone};
  await durable(root,owned.p.identity.mode+'.'+proof.milestone+'.release-intent.json',v);
  const response=oneJSON(successful(await docker(logs,['container','exec',owned.p.identity.exactId,'node',WORKER,'--release',proof.nonce])));
  validateRelease(response,proof.nonce,proof.milestone);
  await durable(root,owned.p.identity.mode+'.'+proof.milestone+'.released.json',response);
}
async function terminal(root,logs,owned,want) {
  stage('terminal'); const deadline=Date.now()+60000; let o;
  do {
    o=await checked(logs,owned,true);
    if (!o.State.Running) break;
    await new Promise(r=>setTimeout(r,200));
  } while (Date.now()<deadline);
  if (!o || o.State.Running || o.State.Status !== 'exited' || o.State.ExitCode !== want) reject();
  validatePhase(owned.p,o,'terminal','cleanup');
  await durable(root,owned.p.identity.mode+'.terminal.json',record(owned.p,'terminal'));
  return o;
}
async function run(root,logs) {
  stage('profile');
  const profile=JSON.parse((await readPrivate(path.join(__dirname,'accepted-engine-profile.json'),0o600,65536)).toString('utf8'));
  validateEngineProfile(profile);
  await durable(root,'accepted-engine-profile.json',profile);
  await engine(logs,profile); // Unknown/missing profile blocks before ANY create.
  stage('helper');
  if (!equal((await fs.readdir(logs)).filter(n=>!/^\w+\.(stdout|stderr)$/.test(n)),['kernel-probe'])) reject();
  const build=await verifiedBuild(logs);
  await durable(root,'helper.json',{version:1,sourceSha256:build.sourceSha256,binarySha256:build.binarySha256});
  const image=process.env.CONTAINMENT_IMAGE_ID;
  if (!IMAGE.test(image || '')) reject();
  const images=JSON.parse(successful(await docker(logs,['image','inspect',image])));
  if (!Array.isArray(images) || images.length !== 1 || images[0]?.Id !== image || !object(images[0].Config)) reject();
  validateImageEnvironment(images[0].Config.Env);
  if (!equal(images[0].Config.Entrypoint,['node',WORKER]) || images[0].Config.WorkingDir !== '/opt/fixture' || (images[0].Config.Volumes != null && !equal(images[0].Config.Volumes,{}))) reject();
  const namespaces={}; for (const n of NS) namespaces[n]=await fs.readlink('/proc/self/ns/'+(n==='mount'?'mnt':n));
  validateNamespaces(namespaces);
  const runId=randomBytes(32).toString('hex');
  // Both complete create admissions and immutable plans precede the FIRST start.
  for (const mode of MODES) {
    await verifyHelper(root,logs); // Recheck pinned source/build before each create.
    stage('create');
    const intent={version:1,run:runId,nonce:randomBytes(32).toString('hex'),mode,exactImageId:image};
    await durable(root,mode+'.create-intent.json',intent);
    const args=['container','create','--init=false','--oom-kill-disable=false','--oom-score-adj','0','--network','none','--ipc','private','--cgroupns','private','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777','--shm-size','128m','--memory','1g','--memory-swap','1g','--cpus','1','--pids-limit','128','--user','10001:10001'];
    for (const n of NS) args.push('--env','HOST_'+n.toUpperCase()+'_NAMESPACE='+namespaces[n]);
    for (const [k,v] of Object.entries(labels(intent))) args.push('--label',k+'='+v);
    args.push(image,mode);
    const id=successful(await docker(logs,args,30000)).trim(); if (!ID.test(id)) reject(); diag.createdCount++;
    stage('persist'); await durable(root,mode+'.id',id+'\n');
    const identity={exactId:id,exactImageId:image,run:runId,nonce:intent.nonce,mode};
    const observed=await inspect(logs,id);
    const expectedEnv=environment([...images[0].Config.Env,...NS.map(n=>'HOST_'+n.toUpperCase()+'_NAMESPACE='+namespaces[n])]);
    if (!equal([...environment(observed.Config?.Env)].sort(),[...expectedEnv].sort())) reject();
    const p=buildPlan(identity,profile,observed,namespaces);
    await durable(root,mode+'.plan.json',p);
  }
  const all=await Promise.all(MODES.map(mode=>load(root,mode)));
  if (all[0].p.identity.exactId === all[1].p.identity.exactId || all[0].p.identity.run !== all[1].p.identity.run || all.some(o=>o.phase!=='created')) reject();
  for (const owned of all) {
    await checked(logs,owned); await verifyHelper(root,logs); await engine(logs,profile);
    stage('start');
    const mode=owned.p.identity.mode;
    await durable(root,mode+'.start-intent.json',record(owned.p,'start-intent'));
    const output=successful(await docker(logs,['container','start',owned.p.identity.exactId]));
    if (output.trim() !== owned.p.identity.exactId) reject();
    // Validate predefined poststart metadata before committing successful start.
    validatePhase(owned.p,await inspect(logs,owned.p.identity.exactId),'started');
    await durable(root,mode+'.started.json',record(owned.p,'started')); diag.startedCount++;
    const started=await load(root,mode);
    const ready=await live(root,logs,started,'ready'); await release(root,logs,started,ready);
    const result=await live(root,logs,started,'result_ready');
    if (mode === 'graceful') await release(root,logs,started,result);
    else {
      // Second retained-FD proof has just bracketed this exact ID.
      const before=await checked(logs,started); if (!before.State.Running) reject();
      if (successful(await docker(logs,['container','stop','--time','3',started.p.identity.exactId])).trim() !== started.p.identity.exactId) reject();
    }
    const exited=await terminal(root,logs,started,mode==='graceful'?0:137);
    const finalOwned=await load(root,mode); validateCase(finalOwned.p,finalOwned.j,[ready,result],exited);
    diag.completedCount++;
  }
  console.log(JSON.stringify({status:'passed',cases:2,completedCount:2,liveMilestonesPerCase:2,continuousProtection:false,actualSDKIntegration:false}));
}
async function cleanupMilestone(root,owned) {
  const mode=owned.p.identity.mode;
  const intent=await json(root,mode+'.ready.release-intent.json',true);
  const released=await json(root,mode+'.ready.released.json',true);
  if (!intent && released) reject();
  if (intent) {
    keys(intent,['version','op','exactId','nonce','milestone']);
    if (intent.version !== 1 || intent.op !== 'release-intent' || intent.exactId !== owned.p.identity.exactId || !ID.test(intent.nonce) || intent.milestone !== 'ready') reject();
    if (!released) reject(); // Ambiguous release cannot select a live milestone.
    validateRelease(released,intent.nonce,'ready');
    return 'result_ready';
  }
  return 'ready';
}
async function cleanup(root,logs) {
  stage('cleanup');
  const all=[]; let failed=false;
  for (const mode of MODES) {
    try { all.push(await load(root,mode)); } catch { failed=true; }
  }
  if (failed || all.length !== 2 || all[0].p.identity.run !== all[1].p.identity.run || all[0].p.identity.exactId === all[1].p.identity.exactId || !equal(all[0].p.engineProfile,all[1].p.engineProfile)) reject();
  const saved=await json(root,'accepted-engine-profile.json'); validateEngineProfile(saved);
  if (!equal(saved,all[0].p.engineProfile)) reject();
  await engine(logs,saved);
  for (const owned of all) {
    try {
      let o=await checked(logs,owned,true,true);
      if (o?.State.Running) {
        await live(root,logs,owned,await cleanupMilestone(root,owned),'cleanup');
        o=await checked(logs,owned,true);
        if (!o.State.Running) reject(); // No fallback after a running-path failure.
        if (successful(await docker(logs,['container','stop','--time','3',owned.p.identity.exactId])).trim() !== owned.p.identity.exactId) reject();
        o=await checked(logs,owned,true);
        if (o.State.Running || o.State.Status !== 'exited') reject();
      }
      if (o) {
        if (o.State.Running || !['created','exited'].includes(o.State.Status)) reject();
        if (successful(await docker(logs,['container','rm',owned.p.identity.exactId])).trim() !== owned.p.identity.exactId) reject();
      }
      if (await checked(logs,owned,true,true) !== null) reject();
    } catch { failed=true; }
  }
  stage('residual');
  // Detection only; never use discovered IDs/PIDs/cgroups as cleanup authority.
  try {
    const residual=successful(await docker(logs,['container','ls','--all','--no-trunc','--quiet','--filter','label=owned-containment.run='+all[0].p.identity.run]));
    if (residual.trim() !== '') failed=true;
  } catch { failed=true; }
  if (failed) reject();
  stage('erase');
  const verified=await roots(); if (verified.root !== root || verified.logs !== logs) reject();
  // Destruction only after all exact-ID absences and residual detection succeeded.
  await fs.rm(logs,{recursive:true}); await fs.rm(root,{recursive:true});
  for (const p of [root,logs]) { try { await fs.lstat(p); reject(); } catch(e) { if (e.code !== 'ENOENT') throw e; } }
  console.log(JSON.stringify({status:'cleanup_verified',containersAbsent:true,privateRootAbsent:true,privateLogRootAbsent:true,continuousProtection:false}));
}
async function main() {
  if (process.argv.length !== 3 || !['--run','--cleanup'].includes(process.argv[2])) reject();
  expectedBuild(); // Both explicit reviewed-source/trusted-build hashes mandatory.
  const {root,logs}=await roots();
  if (process.argv[2] === '--run' && ((await fs.readdir(root)).length !== 0 || !equal(await fs.readdir(logs),['kernel-probe']))) reject();
  // Exclusive invocation lock; stale/crashed locks BLOCK rather than being stolen.
  await durable(root,'controller.lock',{version:1});
  try { if (process.argv[2] === '--run') await run(root,logs); else await cleanup(root,logs); }
  finally { try { await fs.unlink(path.join(root,'controller.lock')); } catch(e) { if (e.code !== 'ENOENT') throw e; } }
}
if (require.main === module) main().catch(()=> {
  const count=n=>Number.isInteger(n)&&n>=0&&n<=2?n:0;
  console.log(JSON.stringify({status:'blocked',reason:'containment_unverified',stage:STAGES.has(diag.stage)?diag.stage:'gate',createdCount:count(diag.createdCount),startedCount:count(diag.startedCount),completedCount:count(diag.completedCount)}));
  process.exitCode=1;
});
