'use strict';

/* Pure private-data decoder, not lifecycle authority. Trusted isolated host,
 * runtime and controller only; no atomicity or adversarial-host guarantee.
 * Inputs before/after are HostFacts, NOT helper envelopes. The controller must
 * authenticate one owned retained-FD helper session, inspect brackets, immutable
 * plan admission, full engine/config security, durable phases and replay history.
 */
const ERROR = 'KERNEL_PROOF_UNVERIFIED';
const U64 = 18446744073709551615n;
const NS_KEYS = ['pid', 'cgroup', 'mount', 'time'];
const BOUNDS = Object.freeze({memoryMax:'1073741824', memorySwapMax:'0', cpuQuota:'100000', cpuPeriod:'100000', cpuBurst:'0', pidsMax:'128', cgroupType:'domain'});
const HOST_KEYS = ['pid','startTicks','state','membership','oomScoreAdj','procAnchor','cgroupRoot','observerNamespaces','bounds'];
const PROCESS_KEYS = ['pid','startTicks','state','membership','oomScoreAdj','namespaces'];
const ENGINE_KEYS = ['exactServerVersion','exactServerGitCommit','apiVersion','cgroupVersion','cgroupDriver','defaultRuntime','runcVersion','runcGitCommit','containerdVersion','containerdGitCommit','hostCgroupPathTemplate','hostCgroupMountRoot','hostCgroupMountPoint','expectedCpuQuota','expectedCpuPeriod','expectedCpuBurst','oomDisableCapability'];
function fail() { throw new Error(ERROR); }
function need(value) { if (!value) fail(); }
function record(value) {
  need(value !== null && typeof value === 'object' && !Array.isArray(value));
  const proto = Object.getPrototypeOf(value);
  need(proto === Object.prototype || proto === null);
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    need(typeof key === 'string');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    need(desc && Object.hasOwn(desc, 'value') && desc.enumerable);
  }
  return keys;
}
function shape(value, keys) {
  const actual = record(value);
  need(actual.length === keys.length && keys.every(k => Object.hasOwn(value, k)));
}
function string(value) { need(typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\x00-\x1f\x7f]/.test(value)); }
function integer(value, positive = false, max = U64) {
  need(typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value));
  const n = BigInt(value);
  need(n <= max && (!positive || n > 0n));
  return n;
}
function hex(value) { need(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)); }
function namespaces(value) {
  shape(value, NS_KEYS);
  for (const key of NS_KEYS) {
    const type = key === 'mount' ? 'mnt' : key;
    need(typeof value[key] === 'string');
    const m = new RegExp(`^${type}:\\[([1-9][0-9]{0,19})\\]$`).exec(value[key]);
    need(m); integer(m[1], true);
  }
}
function sameFields(a, b, keys) { for (const k of keys) need(a[k] === b[k]); }
function bounds(value) { shape(value, Object.keys(BOUNDS)); sameFields(value, BOUNDS, Object.keys(BOUNDS)); }
function fdIdentity(value, withFilesystem = false) {
  shape(value, withFilesystem ? ['device','inode','fsType'] : ['device','inode']);
  integer(value.device); integer(value.inode, true);
  if (withFilesystem) need(value.fsType === '63677270');
}
/* Linux dev_t's userspace representation, matching C's st_dev decimal string. */
function devicePair(value) {
  const d = integer(value);
  const major = ((d >> 8n) & 0xfffn) | ((d >> 32n) & 0xfffff000n);
  const minor = (d & 0xffn) | ((d >> 12n) & 0xffffff00n);
  return `${major}:${minor}`;
}
function task(value, keys) {
  shape(value, keys);
  integer(value.pid, true, 2147483647n);
  integer(value.startTicks, true);
  need(typeof value.state === 'string' && /^[RSDI]$/.test(value.state));
  need(value.membership === '0::/' && value.oomScoreAdj === '0');
  namespaces(value.namespaces);
}
function host(value, membership, observer) {
  shape(value, HOST_KEYS);
  integer(value.pid, true, 2147483647n); integer(value.startTicks, true);
  need(typeof value.state === 'string' && /^[RSDI]$/.test(value.state));
  need(value.membership === membership && value.oomScoreAdj === '0');
  fdIdentity(value.procAnchor);
  shape(value.cgroupRoot, ['device','inode','fsType','mountRoot','mountPoint','mountDevice']);
  integer(value.cgroupRoot.device); integer(value.cgroupRoot.inode, true);
  need(value.cgroupRoot.fsType === '63677270' && value.cgroupRoot.mountRoot === '/'
    && value.cgroupRoot.mountPoint === '/sys/fs/cgroup'
    && value.cgroupRoot.mountDevice === devicePair(value.cgroupRoot.device));
  namespaces(value.observerNamespaces); sameFields(value.observerNamespaces, observer, NS_KEYS);
  bounds(value.bounds);
}
function denseArray(value, count) {
  need(Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype && value.length === count);
  const keys = Reflect.ownKeys(value);
  need(keys.length === count + 1 && keys.includes('length'));
  for (let i = 0; i < count; i++) {
    const d = Object.getOwnPropertyDescriptor(value, String(i));
    need(d && Object.hasOwn(d, 'value') && d.enumerable);
  }
}
function validateLiveWitness(plan, before, witness, after, expectedNonce, expectedMilestone) {
  try {
    shape(plan, ['version','identity','engineProfile','config','hostConfigCreated','hostConfigPoststart','observerNamespaces']);
    need(plan.version === 1);
    shape(plan.identity, ['exactId','exactImageId','run','nonce','mode']);
    hex(plan.identity.exactId); hex(plan.identity.run); hex(plan.identity.nonce);
    need(typeof plan.identity.exactImageId === 'string' && /^sha256:[0-9a-f]{64}$/.test(plan.identity.exactImageId));
    need(plan.identity.mode === 'graceful' || plan.identity.mode === 'linger');
    record(plan.config); record(plan.hostConfigCreated); record(plan.hostConfigPoststart);
    shape(plan.engineProfile, ENGINE_KEYS);
    for (const key of ENGINE_KEYS) if (key !== 'oomDisableCapability') string(plan.engineProfile[key]);
    need(plan.engineProfile.oomDisableCapability === false);
    const engine = plan.engineProfile;
    need(engine.cgroupVersion === '2' && (engine.cgroupDriver === 'systemd' || engine.cgroupDriver === 'cgroupfs'));
    const template = engine.cgroupDriver === 'systemd' ? '/system.slice/docker-{id}.scope' : '/docker/{id}';
    need(engine.hostCgroupPathTemplate === template && engine.hostCgroupMountRoot === '/'
      && engine.hostCgroupMountPoint === '/sys/fs/cgroup' && engine.expectedCpuQuota === BOUNDS.cpuQuota
      && engine.expectedCpuPeriod === BOUNDS.cpuPeriod && engine.expectedCpuBurst === BOUNDS.cpuBurst);
    namespaces(plan.observerNamespaces);
    hex(expectedNonce);
    need(expectedMilestone === 'ready' || expectedMilestone === 'result_ready');
    const membership = '0::' + template.replace('{id}', plan.identity.exactId);
    host(before, membership, plan.observerNamespaces); host(after, membership, plan.observerNamespaces);
    sameFields(before, after, ['pid','startTicks','membership','oomScoreAdj']);
    sameFields(before.procAnchor, after.procAnchor, ['device','inode']);
    sameFields(before.cgroupRoot, after.cgroupRoot, ['device','inode','fsType','mountRoot','mountPoint','mountDevice']);
    shape(witness, ['version','nonce','milestone','init','client','cgroupRoot','containerMount','bounds','children','caseResult']);
    need(witness.version === 1 && witness.nonce === expectedNonce && witness.milestone === expectedMilestone);
    task(witness.init, PROCESS_KEYS); task(witness.client, PROCESS_KEYS);
    need(witness.init.pid === '1' && witness.client.pid !== '1'
      && witness.init.startTicks === before.startTicks);
    sameFields(witness.init.namespaces, witness.client.namespaces, NS_KEYS);
    for (const key of ['pid','cgroup','mount']) need(witness.init.namespaces[key] !== plan.observerNamespaces[key]);
    need(witness.init.namespaces.time === plan.observerNamespaces.time);
    fdIdentity(witness.cgroupRoot, true);
    sameFields(witness.cgroupRoot, before.cgroupRoot, ['device','inode','fsType']);
    shape(witness.containerMount, ['root','mountPoint','mountDevice','filesystem','readOnly','unexpectedOvermounts']);
    const mount = witness.containerMount;
    need(mount.root === '/' && mount.mountPoint === '/sys/fs/cgroup'
      && mount.mountDevice === devicePair(witness.cgroupRoot.device) && mount.filesystem === 'cgroup2'
      && mount.readOnly === true && mount.unexpectedOvermounts === false);
    bounds(witness.bounds);
    shape(witness.caseResult, ['mode','childObserved','browserObserved','childrenAlive','childClosed','browserClosed','profileRemoved','childCount']);
    const closed = plan.identity.mode === 'graceful' && expectedMilestone === 'result_ready';
    const result = witness.caseResult;
    need(result.mode === plan.identity.mode && result.childObserved === true && result.browserObserved === true
      && result.childrenAlive === !closed && result.childClosed === closed && result.browserClosed === closed
      && result.profileRemoved === closed && result.childCount === 1);
    denseArray(witness.children, closed ? 0 : 2);
    const roles = new Set(); const pids = new Set(['1', witness.client.pid]);
    for (const child of witness.children) {
      task(child, [...PROCESS_KEYS,'role','executableClass','ancestorToInit']);
      need(child.role === 'node_child' || child.role === 'chromium_main');
      need(!roles.has(child.role) && !pids.has(child.pid));
      roles.add(child.role); pids.add(child.pid);
      need(child.executableClass === (child.role === 'node_child' ? 'node' : 'chromium_main')
        && child.ancestorToInit === true);
      sameFields(child.namespaces, witness.init.namespaces, NS_KEYS);
    }
    /* Nonterminal states deliberately need not match before/after/worker.
     * Nonce equality is correlation, NOT stateful replay protection. The two
     * main-child checks do not prove properties of every browser descendant.
     */
    return true;
  } catch (_) {
    const error = new Error(ERROR);
    error.code = ERROR;
    throw error;
  }
}
module.exports = {validateLiveWitness};
