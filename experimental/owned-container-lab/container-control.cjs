'use strict';
// CI-only host authority: Docker CLI, exact immutable IDs; never host workload signals.
const fs = require('node:fs/promises');
const { constants, writeSync } = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const ID = /^[a-f0-9]{64}$/;
const IMAGE = /^sha256:[a-f0-9]{64}$/;
const WORKER = '/opt/fixture/container-worker.mjs';
const MODES = ['graceful', 'linger'];
// Diagnostics exist only in CLI mode; exported validation remains a pure data contract.
const STAGES = new Set(['rootcheck', 'runempty', 'imageinspect', 'image_env_admission', 'intentspersisted', 'create', 'IDpersisted', 'created_security_admission', 'recordpersisted', 'start', 'gracefulwait', 'lingerready', 'probe', 'stop', 'cleanup_load', 'cleanup_stop', 'cleanup_remove', 'cleanup_absence', 'cleanup_residual', 'cleanup_rootremove']);
const GATES = new Set(['root', 'image_env', 'saved_record', 'absence', 'docker_cli', 'identity_config', 'env', 'namespace_config', 'bounds', 'tmpfs', 'host_mounts', 'ports', 'image_volumes', 'mounts', 'network_map', 'image_identity', 'create_id', 'created_state', 'workload_output', 'workload_state', 'persistence', 'private_file', 'cleanup_residual', 'root_absence', 'cli_args', 'intent']);
// Fixed public Docker schema names only. Unknown diff keys project to the literal 'other'.
// NetworkSettings is a container-inspect object, not Config/HostConfig; its shape has a separate observation.
const CONFIG_FIELDS = new Set(['Hostname', 'Domainname', 'User', 'AttachStdin', 'AttachStdout', 'AttachStderr', 'ExposedPorts', 'Tty', 'OpenStdin', 'StdinOnce', 'Env', 'Cmd', 'Healthcheck', 'ArgsEscaped', 'Image', 'Volumes', 'WorkingDir', 'Entrypoint', 'NetworkDisabled', 'MacAddress', 'OnBuild', 'Labels', 'StopSignal', 'StopTimeout', 'Shell']);
const HOST_FIELDS = new Set(['Binds', 'ContainerIDFile', 'LogConfig', 'NetworkMode', 'PortBindings', 'RestartPolicy', 'AutoRemove', 'VolumeDriver', 'VolumesFrom', 'ConsoleSize', 'Annotations', 'CapAdd', 'CapDrop', 'CgroupnsMode', 'Dns', 'DnsOptions', 'DnsSearch', 'ExtraHosts', 'GroupAdd', 'IpcMode', 'Cgroup', 'Links', 'OomScoreAdj', 'PidMode', 'Privileged', 'PublishAllPorts', 'ReadonlyRootfs', 'SecurityOpt', 'StorageOpt', 'Tmpfs', 'UTSMode', 'UsernsMode', 'ShmSize', 'Sysctls', 'Runtime', 'Isolation', 'CpuShares', 'Memory', 'NanoCpus', 'CgroupParent', 'BlkioWeight', 'BlkioWeightDevice', 'BlkioDeviceReadBps', 'BlkioDeviceWriteBps', 'BlkioDeviceReadIOps', 'BlkioDeviceWriteIOps', 'CpuPeriod', 'CpuQuota', 'CpuRealtimePeriod', 'CpuRealtimeRuntime', 'CpusetCpus', 'CpusetMems', 'Devices', 'DeviceCgroupRules', 'DeviceRequests', 'MemoryReservation', 'MemorySwap', 'MemorySwappiness', 'OomKillDisable', 'PidsLimit', 'Ulimits', 'CpuCount', 'CpuPercent', 'IOMaximumIOps', 'IOMaximumBandwidth', 'Mounts', 'MaskedPaths', 'ReadonlyPaths', 'Init']);
let diagnostic = null;
function diffFields(expected, observed, allowlist) {
  const names = new Set([...Object.keys(expected), ...Object.keys(observed)]);
  const changed = new Set();
  for (const name of names) {
    if (Object.hasOwn(expected, name) !== Object.hasOwn(observed, name) || !equal(expected[name], observed[name])) changed.add(allowlist.has(name) ? name : 'other');
  }
  return [...changed].sort(); // At most allowlist.size + 1; no input object/array is modified.
}
function projectFields(value, allowlist) {
  if (!Array.isArray(value)) return [];
  const projected = new Set();
  for (const name of value) projected.add(typeof name === 'string' && allowlist.has(name) ? name : 'other');
  return [...projected].sort();
}
function context(stage, gate) {
  if (diagnostic && STAGES.has(stage) && GATES.has(gate)) { diagnostic.stage = stage; diagnostic.gate = gate; }
}
function gate(code) { if (diagnostic && GATES.has(code)) diagnostic.gate = code; }
function failureProjection() {
  const count = key => Number.isInteger(diagnostic?.[key]) && diagnostic[key] >= 0 && diagnostic[key] <= 2 ? diagnostic[key] : 0;
  return { status: 'failed', reason: 'containment_unverified', stage: STAGES.has(diagnostic?.stage) ? diagnostic.stage : 'rootcheck', gate: GATES.has(diagnostic?.gate) ? diagnostic.gate : 'root', createdCount: count('createdCount'), startedCount: count('startedCount'), completedCount: count('completedCount'), networkMapObservation: ['empty', 'none_only', 'other', 'missing'].includes(diagnostic?.networkMapObservation) ? diagnostic.networkMapObservation : 'missing', imageEnvExpectedKeys: diagnostic?.imageEnvExpectedKeys === true, configComparison: ['not_observed', 'equal', 'different'].includes(diagnostic?.configComparison) ? diagnostic.configComparison : 'not_observed', hostConfigComparison: ['not_observed', 'equal', 'different'].includes(diagnostic?.hostConfigComparison) ? diagnostic.hostConfigComparison : 'not_observed', stateShape: ['not_observed', 'valid', 'invalid'].includes(diagnostic?.stateShape) ? diagnostic.stateShape : 'not_observed', changedConfigFields: projectFields(diagnostic?.changedConfigFields, CONFIG_FIELDS), changedHostConfigFields: projectFields(diagnostic?.changedHostConfigFields, HOST_FIELDS) };
}
const reject = code => { if (code) gate(code); throw new Error('containment_unverified'); };
function keys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !equal(Object.keys(value).sort(), [...expected].sort())) reject();
}
function labels(intent) {
  return { 'owned-containment.run': intent.run, 'owned-containment.nonce': intent.nonce, 'owned-containment.mode': intent.mode };
}
function environmentEntries(env) {
  if (!Array.isArray(env)) reject();
  const entries = new Map();
  for (const item of env) {
    if (typeof item !== 'string') reject();
    const split = item.indexOf('=');
    if (split < 1) reject();
    const key = item.slice(0, split), value = item.slice(split + 1);
    if (!/^[A-Z_]+$/.test(key) || entries.has(key)) reject();
    entries.set(key, value);
  }
  return entries;
}
function validateImageEnvironment(env) {
  // Observe only a fixed boolean, never unknown key names or values.
  if (diagnostic) {
    const names = Array.isArray(env) && env.every(item => typeof item === 'string' && item.indexOf('=') > 0) ? env.map(item => item.slice(0, item.indexOf('='))) : [];
    diagnostic.imageEnvExpectedKeys = equal([...names].sort(), ['NODE_VERSION', 'PATH', 'PLAYWRIGHT_BROWSERS_PATH', 'YARN_VERSION']);
  }
  const entries = environmentEntries(env);
  if (!equal([...entries.keys()].sort(), ['NODE_VERSION', 'PATH', 'PLAYWRIGHT_BROWSERS_PATH', 'YARN_VERSION'])) reject();
  if (entries.get('PATH') !== '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' || !/^22\.\d+\.\d+$/.test(entries.get('NODE_VERSION')) || !/^1\.\d+\.\d+$/.test(entries.get('YARN_VERSION')) || entries.get('PLAYWRIGHT_BROWSERS_PATH') !== '/opt/playwright') reject();
}
function validateIntent(i) {
  gate('intent');
  keys(i, ['version', 'run', 'nonce', 'mode', 'image', 'hostNamespace', 'imageEnvironment']);
  if (i.version !== 1 || !ID.test(i.run) || !ID.test(i.nonce) || !MODES.includes(i.mode) || !IMAGE.test(i.image) || !/^pid:\[\d+\]$/.test(i.hostNamespace)) reject();
  gate('image_env');
  validateImageEnvironment(i.imageEnvironment);
}
function security(s, i) {
  gate('identity_config');
  if (!s || !s.Config || !s.HostConfig || !s.NetworkSettings || !Array.isArray(s.Mounts)) reject();
  const h = s.HostConfig, c = s.Config;
  if (diagnostic) {
    const map = s.NetworkSettings.Networks;
    const names = map && typeof map === 'object' && !Array.isArray(map) ? Object.keys(map) : null;
    diagnostic.networkMapObservation = names === null ? 'missing' : names.length === 0 ? 'empty' : equal(names.sort(), ['none']) ? 'none_only' : 'other';
  }
  if (s.Image !== i.image || !equal(c.Labels, labels(i)) || c.User !== '10001:10001' || !equal(c.Entrypoint, ['node', WORKER]) || !equal(c.Cmd, [i.mode]) || c.WorkingDir !== '/opt/fixture' || c.Tty !== false || c.OpenStdin !== false) reject();
  // Validate admission before persisting any Config, not just its later equality to the record.
  gate('env');
  validateImageEnvironment(i.imageEnvironment);
  const actualEnvironment = [...environmentEntries(c.Env)].sort((a, b) => a[0].localeCompare(b[0]));
  const expectedEnvironment = [...environmentEntries([...i.imageEnvironment, 'HOST_PID_NAMESPACE=' + i.hostNamespace])].sort((a, b) => a[0].localeCompare(b[0]));
  if (!equal(actualEnvironment, expectedEnvironment)) reject();
  gate('namespace_config');
  if (h.Privileged !== false || h.ReadonlyRootfs !== true || h.NetworkMode !== 'none' || h.PidMode !== '' || h.IpcMode !== 'private' || h.UsernsMode !== '' || h.UTSMode !== '' || h.CgroupnsMode !== 'private' || h.AutoRemove !== false || h.Init !== false || h.PublishAllPorts !== false) reject();
  gate('bounds');
  if (!equal(h.CapDrop, ['ALL']) || (h.CapAdd != null && !equal(h.CapAdd, [])) || !equal(h.SecurityOpt, ['no-new-privileges']) || h.Memory !== 1073741824 || h.MemorySwap !== 1073741824 || h.NanoCpus !== 1000000000 || h.PidsLimit !== 128 || h.ShmSize !== 134217728) reject();
  gate('tmpfs');
  if (!equal(h.Tmpfs, { '/tmp': 'rw,noexec,nosuid,nodev,size=256m,mode=1777' })) reject();
  gate('host_mounts');
  for (const k of ['Binds', 'Devices', 'DeviceRequests', 'VolumesFrom', 'Links', 'ExtraHosts', 'CapAdd']) if (h[k] != null && !equal(h[k], [])) reject();
  gate('ports');
  if (h.PortBindings != null && !equal(h.PortBindings, {})) reject();
  gate('host_mounts');
  if (h.Mounts != null && !equal(h.Mounts, [])) reject();
  gate('image_volumes');
  if (c.Volumes != null && !equal(c.Volumes, {})) reject();
  gate('mounts');
  if (s.Mounts.some(m => m.Type !== 'tmpfs' || !['/tmp', '/dev/shm'].includes(m.Destination))) reject();
  gate('network_map');
  if (!equal(Object.keys(s.NetworkSettings.Networks || {}).sort(), ['none'])) reject();
}
// Pure contract: throws on absent/unknown/mismatched evidence. Export has no side effects.
function validateRecord(record, observed, intent, exactId) {
  if (diagnostic) {
    diagnostic.configComparison = 'not_observed'; diagnostic.hostConfigComparison = 'not_observed'; diagnostic.stateShape = 'not_observed';
    diagnostic.changedConfigFields = []; diagnostic.changedHostConfigFields = [];
  }
  validateIntent(intent);
  gate('saved_record');
  keys(record, ['version', 'id', 'intent', 'image', 'config', 'securityConfig']);
  if (record.version !== 1 || !ID.test(record.id) || !ID.test(exactId) || record.id !== exactId || !equal(record.intent, intent) || record.image !== intent.image) reject();
  if (!observed || observed.Id !== exactId) reject();
  security(observed, intent);
  security({ ...observed, Image: record.image, Config: record.config, HostConfig: record.securityConfig }, intent);
  gate('saved_record');
  // Observe before either full equality or state rejection, without changing acceptance.
  const validState = !!observed.State && typeof observed.State.Running === 'boolean' && Number.isInteger(observed.State.ExitCode);
  const configEqual = equal(record.config, observed.Config);
  const hostConfigEqual = equal(record.securityConfig, observed.HostConfig);
  if (diagnostic) {
    diagnostic.stateShape = validState ? 'valid' : 'invalid';
    diagnostic.configComparison = configEqual ? 'equal' : 'different';
    diagnostic.hostConfigComparison = hostConfigEqual ? 'equal' : 'different';
    diagnostic.changedConfigFields = diffFields(record.config, observed.Config, CONFIG_FIELDS);
    diagnostic.changedHostConfigFields = diffFields(record.securityConfig, observed.HostConfig, HOST_FIELDS);
  }
  if (!configEqual || !hostConfigEqual) reject();
  if (!validState) reject();
  return true;
}
module.exports = { validateRecord };

async function rootCheck() {
  gate('root');
  if (process.platform !== 'linux' || process.env.CI !== 'true' || process.env.GITHUB_ACTIONS !== 'true' || typeof process.getuid !== 'function') reject();
  const supplied = process.env.PRIVATE_CONTAINMENT_ROOT, temp = process.env.RUNNER_TEMP;
  if (!supplied || !temp || !path.isAbsolute(supplied) || !path.isAbsolute(temp)) reject();
  const parent = await fs.realpath(temp), root = path.resolve(supplied);
  if (path.dirname(root) !== parent || !/^owned-containment\.[A-Za-z0-9_-]+$/.test(path.basename(root))) reject();
  const st = await fs.lstat(root);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || (st.mode & 0o777) !== 0o700 || await fs.realpath(root) !== root) reject();
  return root;
}
async function durable(root, name, data) {
  const handle = await fs.open(path.join(root, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(data); await handle.sync(); } finally { await handle.close(); }
  const directory = await fs.open(root, constants.O_RDONLY | constants.O_DIRECTORY);
  try { await directory.sync(); } finally { await directory.close(); }
}
async function privateRead(root, name) {
  const handle = await fs.open(path.join(root, name), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const s = await handle.stat();
    if (!s.isFile() || s.uid !== process.getuid() || (s.mode & 0o777) !== 0o600 || s.nlink !== 1 || s.size > 4194304) reject();
    return await handle.readFile('utf8');
  } finally { await handle.close(); }
}
async function docker(root, args, timeout = 15000) {
  const callerGate = diagnostic?.gate;
  gate('docker_cli');
  const token = randomBytes(12).toString('hex');
  const out = await fs.open(path.join(root, token + '.stdout'), 'wx', 0o600);
  const err = await fs.open(path.join(root, token + '.stderr'), 'wx', 0o600);
  let child, timer;
  try {
    const result = await new Promise((resolve, fail) => {
      const environment = { ...process.env, DOCKER_HOST: 'unix:///var/run/docker.sock' };
      delete environment.DOCKER_CONTEXT; delete environment.DOCKER_TLS_VERIFY; delete environment.DOCKER_CERT_PATH;
      child = spawn('docker', ['--host', 'unix:///var/run/docker.sock', ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: environment });
      let size = 0, aborted = false;
      const abort = () => {
        if (aborted) return;
        aborted = true;
        child.stdout.destroy(); child.stderr.destroy();
        child.kill('SIGKILL');
        fail(new Error('containment_unverified'));
      };
      const capture = handle => chunk => {
        if (aborted) return;
        size += chunk.length;
        if (size > 4194304) { abort(); return; }
        try {
          let offset = 0;
          while (offset < chunk.length) offset += writeSync(handle.fd, chunk, offset, chunk.length - offset);
        } catch { abort(); }
      };
      child.stdout.on('data', capture(out)); child.stderr.on('data', capture(err));
      child.stdout.once('error', abort); child.stderr.once('error', abort);
      timer = setTimeout(abort, timeout);
      child.once('error', abort);
      // close, not exit: both capture streams must finish before private files are read.
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    await out.sync(); await err.sync();
    const stdout = await privateRead(root, token + '.stdout'), stderr = await privateRead(root, token + '.stderr');
    gate(callerGate);
    return { ...result, stdout, stderr };
  } catch { reject('docker_cli'); }
  finally {
    try { clearTimeout(timer); await out.close(); await err.close(); } catch { reject('docker_cli'); }
  }
}
function success(r) { if (r.code !== 0 || r.signal !== null) reject('docker_cli'); return r.stdout; }
function workload(r) { const stdout = success(r); if (r.stderr !== '') reject('workload_output'); return stdout; }
async function inspect(root, id, allowAbsent = false) {
  if (!ID.test(id)) reject('identity_config');
  const r = await docker(root, ['container', 'inspect', id]);
  if (r.code !== 0) {
    // Only this exact Docker daemon response establishes absence. Permission/RPC/CLI errors never do.
    if (allowAbsent && r.code === 1 && r.signal === null && r.stdout.trim() === '[]' && ['Error response from daemon: No such container: ' + id, 'Error: No such container: ' + id].includes(r.stderr.trim())) return null;
    reject('docker_cli');
  }
  gate('identity_config');
  let parsed;
  try { parsed = JSON.parse(success(r)); } catch { reject('docker_cli'); }
  if (!Array.isArray(parsed) || parsed.length !== 1 || parsed[0].Id !== id) reject();
  return parsed[0];
}
async function load(root, mode) {
  gate('saved_record');
  const intent = JSON.parse(await privateRead(root, mode + '.intent.json'));
  validateIntent(intent);
  if (intent.mode !== mode) reject();
  gate('saved_record');
  const id = (await privateRead(root, mode + '.id')).trim();
  const record = JSON.parse(await privateRead(root, mode + '.expected.json'));
  if (!ID.test(id) || record.id !== id || !equal(record.intent, intent)) reject();
  // Validate saved expectation even if the container is already absent.
  validateRecord(record, { Id: id, Image: record.image, Config: record.config, HostConfig: record.securityConfig, Mounts: [], NetworkSettings: { Networks: { none: {} } }, State: { Running: false, ExitCode: 0 } }, intent, id);
  return { intent, id, record };
}
async function checked(root, owned, absent = false) {
  const current = await inspect(root, owned.id, absent);
  if (current) validateRecord(owned.record, current, owned.intent, owned.id);
  return current;
}
function output(raw, mode, phase) {
  gate('workload_output');
  const lines = raw.trim().split('\n');
  if (lines.length !== 1) reject();
  const value = JSON.parse(lines[0]);
  const want = { version: 1, mode, phase, namespacePrivate: true, childObserved: true, browserObserved: true, childrenAlive: phase === 'alive', childClosed: phase === 'complete', browserClosed: phase === 'complete', profileRemoved: phase === 'complete', childCount: 1 };
  if (!equal(value, want)) reject();
}
const delay = ms => new Promise(r => setTimeout(r, ms));
async function stop(root, owned) {
  const before = await checked(root, owned, true);
  if (!before) return null;
  if (before.State.Running) {
    success(await docker(root, ['container', 'stop', '--time', '3', owned.id], 15000));
    const after = await checked(root, owned);
    if (after.State.Running) reject('workload_state');
    return after;
  }
  return before;
}
async function run(root) {
  context('runempty', 'root');
  if ((await fs.readdir(root)).length !== 0 || !IMAGE.test(process.env.CONTAINMENT_IMAGE_ID || '')) reject();
  // Inspect the exact immutable image before any intent or container creation.
  context('imageinspect', 'image_identity');
  const imageResult = await docker(root, ['image', 'inspect', process.env.CONTAINMENT_IMAGE_ID]);
  if (imageResult.stderr !== '') reject('docker_cli');
  let images;
  try { images = JSON.parse(success(imageResult)); } catch { reject('docker_cli'); }
  if (!Array.isArray(images) || images.length !== 1 || !images[0] || images[0].Id !== process.env.CONTAINMENT_IMAGE_ID || !images[0].Config) reject();
  const imageEnvironment = images[0].Config.Env;
  context('image_env_admission', 'image_env');
  validateImageEnvironment(imageEnvironment);
  const runId = randomBytes(32).toString('hex');
  gate('namespace_config');
  const hostNamespace = await fs.readlink('/proc/self/ns/pid');
  // Persist all intents before create; a create result lost before ID persistence is unknown, never killable by label.
  context('intentspersisted', 'persistence');
  for (const mode of MODES) await durable(root, mode + '.intent.json', JSON.stringify({ version: 1, run: runId, nonce: randomBytes(32).toString('hex'), mode, image: process.env.CONTAINMENT_IMAGE_ID, hostNamespace, imageEnvironment }));
  for (const mode of MODES) {
    context('create', 'saved_record');
    const intent = JSON.parse(await privateRead(root, mode + '.intent.json'));
    validateIntent(intent);
    const args = ['container', 'create', '--init=false', '--network', 'none', '--ipc', 'private', '--cgroupns', 'private', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777', '--shm-size', '128m', '--memory', '1g', '--memory-swap', '1g', '--cpus', '1', '--pids-limit', '128', '--user', '10001:10001', '--env', 'HOST_PID_NAMESPACE=' + hostNamespace];
    for (const [key, value] of Object.entries(labels(intent))) args.push('--label', key + '=' + value);
    args.push(intent.image, mode);
    gate('create_id');
    const id = success(await docker(root, args, 30000)).trim();
    if (!ID.test(id)) reject();
    diagnostic.createdCount += 1; // Accepted create plus full exact ID, not inferred from a timeout.
    context('IDpersisted', 'persistence');
    await durable(root, mode + '.id', id + '\n');
    context('created_security_admission', 'identity_config');
    const created = await inspect(root, id);
    security(created, intent);
    gate('created_state');
    if (created.State.Running !== false || created.State.Status !== 'created') reject();
    const record = { version: 1, id, intent, image: intent.image, config: created.Config, securityConfig: created.HostConfig };
    validateRecord(record, created, intent, id);
    context('recordpersisted', 'persistence');
    await durable(root, mode + '.expected.json', JSON.stringify(record));
    const owned = await load(root, mode);
    await checked(root, owned);
    context('start', 'docker_cli');
    success(await docker(root, ['container', 'start', id]));
    diagnostic.startedCount += 1; // Concrete successful Docker start response only.
    const deadline = Date.now() + 60000;
    let current;
    if (mode === 'graceful') {
      context('gracefulwait', 'workload_state');
      do { current = await checked(root, owned); if (!current.State.Running) break; await delay(400); } while (Date.now() < deadline);
      gate('workload_state');
      if (current.State.Running || current.State.ExitCode !== 0) reject();
      output(workload(await docker(root, ['container', 'logs', id])), mode, 'complete');
    } else {
      context('lingerready', 'workload_state');
      let ready = false;
      do {
        current = await checked(root, owned);
        if (!current.State.Running) reject('workload_state');
        const logs = workload(await docker(root, ['container', 'logs', id]));
        if (logs.trim()) { output(logs, mode, 'alive'); ready = true; break; }
        await delay(400);
      } while (Date.now() < deadline);
      if (!ready) reject('workload_state');
      // A separate in-namespace /proc assertion immediately before the intentional timeout stop.
      context('probe', 'workload_output');
      output(workload(await docker(root, ['container', 'exec', id, 'node', WORKER, '--probe'])), mode, 'alive');
      context('stop', 'workload_state');
      current = await stop(root, owned);
      if (!current || current.State.Running || current.State.ExitCode !== 137) reject('workload_state');
    }
    diagnostic.completedCount += 1; // Validated case output AND required actual terminal exit state.
  }
  console.log(JSON.stringify({ status: 'passed', cases: 2, pass: 2, fail: 0, graceful: true, timeout: true, preStartOwnership: true, genuineChromium: true, privatePIDNamespace: true, networkNone: true, noHostPIDSignals: true, actualSDKIntegration: false }));
}
async function cleanup(root) {
  let failed = false, firstFailure = null;
  const rememberFailure = () => { failed = true; if (!firstFailure) firstFailure = failureProjection(); };
  const intents = [];
  for (const mode of MODES) {
    try {
      context('cleanup_load', 'saved_record');
      const intent = JSON.parse(await privateRead(root, mode + '.intent.json'));
      validateIntent(intent); if (intent.mode !== mode) reject(); intents.push(intent);
      const owned = await load(root, mode);
      context('cleanup_stop', 'saved_record');
      const stopped = await stop(root, owned);
      if (stopped) {
        context('cleanup_remove', 'saved_record');
        const beforeRemove = await checked(root, owned);
        if (beforeRemove.State.Running) reject('workload_state');
        success(await docker(root, ['container', 'rm', owned.id]));
      }
      context('cleanup_absence', 'absence');
      if (await checked(root, owned, true) !== null) reject('absence');
    } catch { rememberFailure(); }
  }
  if (intents.length !== 2 || intents[0].run !== intents[1].run) { context('cleanup_load', 'saved_record'); rememberFailure(); }
  // Detection only: no IDs discovered here are ever passed to stop/remove.
  for (const intent of intents) {
    try {
      context('cleanup_residual', 'cleanup_residual');
      const residual = success(await docker(root, ['container', 'ls', '--all', '--no-trunc', '--quiet', '--filter', 'label=owned-containment.run=' + intent.run]));
      if (residual.trim() !== '') { gate('cleanup_residual'); rememberFailure(); }
    } catch { rememberFailure(); }
  }
  if (failed) {
    // Keep the FIRST failure, not the last cleanup attempt, without exposing an exception.
    diagnostic.stage = firstFailure.stage; diagnostic.gate = firstFailure.gate;
    diagnostic.networkMapObservation = firstFailure.networkMapObservation;
    diagnostic.imageEnvExpectedKeys = firstFailure.imageEnvExpectedKeys;
    diagnostic.configComparison = firstFailure.configComparison;
    diagnostic.hostConfigComparison = firstFailure.hostConfigComparison;
    diagnostic.stateShape = firstFailure.stateShape;
    diagnostic.changedConfigFields = [...firstFailure.changedConfigFields];
    diagnostic.changedHostConfigFields = [...firstFailure.changedHostConfigFields];
    reject();
  }
  // Root removal only after exact-ID absence and residual scan proof.
  context('cleanup_rootremove', 'root');
  if (await rootCheck() !== root) reject();
  await fs.rm(root, { recursive: true });
  gate('root_absence');
  try { await fs.lstat(root); reject(); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  console.log(JSON.stringify({ status: 'cleanup_verified', containersAbsent: true, privateRootAbsent: true }));
}
async function main() {
  diagnostic = { stage: 'rootcheck', gate: 'cli_args', createdCount: 0, startedCount: 0, completedCount: 0, networkMapObservation: 'missing', imageEnvExpectedKeys: false, configComparison: 'not_observed', hostConfigComparison: 'not_observed', stateShape: 'not_observed', changedConfigFields: [], changedHostConfigFields: [] };
  if (process.argv.length !== 3 || !['--run', '--cleanup'].includes(process.argv[2])) reject();
  context('rootcheck', 'root');
  const root = await rootCheck();
  if (process.argv[2] === '--run') await run(root); else await cleanup(root);
}
if (require.main === module) main().catch(() => {
  console.log(JSON.stringify(failureProjection()));
  process.exitCode = 1;
});
