'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { validateRecord } = require('./container-control.cjs');
// Pure data contracts only. No Docker, browser, child workload or simulated runtime claims.
function fixture() {
  const id = 'a'.repeat(64);
  const intent = { version: 1, run: 'b'.repeat(64), nonce: 'c'.repeat(64), mode: 'graceful', image: 'sha256:' + 'd'.repeat(64), hostNamespace: 'pid:[123]', imageEnvironment: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'NODE_VERSION=22.20.0', 'YARN_VERSION=1.22.22', 'PLAYWRIGHT_BROWSERS_PATH=/opt/playwright'] };
  const observed = {
    Id: id, Image: intent.image,
    Config: { Labels: { 'owned-containment.run': intent.run, 'owned-containment.nonce': intent.nonce, 'owned-containment.mode': intent.mode }, User: '10001:10001', Entrypoint: ['node', '/opt/fixture/container-worker.mjs'], Cmd: ['graceful'], WorkingDir: '/opt/fixture', Tty: false, OpenStdin: false, Env: [...intent.imageEnvironment, 'HOST_PID_NAMESPACE=pid:[123]'], Volumes: null },
    HostConfig: { Privileged: false, ReadonlyRootfs: true, NetworkMode: 'none', PidMode: '', IpcMode: 'private', UsernsMode: '', UTSMode: '', CgroupnsMode: 'private', AutoRemove: false, Init: false, PublishAllPorts: false, CapDrop: ['ALL'], CapAdd: null, SecurityOpt: ['no-new-privileges'], Memory: 1073741824, MemorySwap: 1073741824, NanoCpus: 1000000000, PidsLimit: 128, ShmSize: 134217728, Tmpfs: { '/tmp': 'rw,noexec,nosuid,nodev,size=256m,mode=1777' }, Binds: null, Devices: [], DeviceRequests: null, VolumesFrom: null, Links: null, ExtraHosts: null, PortBindings: {}, Mounts: [] },
    Mounts: [], NetworkSettings: { Networks: { none: {} } }, State: { Running: false, ExitCode: 0 }
  };
  const record = { version: 1, id, intent: structuredClone(intent), image: intent.image, config: structuredClone(observed.Config), securityConfig: structuredClone(observed.HostConfig) };
  return { id, intent, observed, record };
}
test('exact recorded full ID is the only authority', () => {
  const f = fixture();
  assert.equal(validateRecord(f.record, f.observed, f.intent, f.id), true);
  assert.throws(() => validateRecord(f.record, f.observed, f.intent, 'e'.repeat(64)), { message: 'containment_unverified' });
  f.observed.Id = 'f'.repeat(64);
  assert.throws(() => validateRecord(f.record, f.observed, f.intent, f.id), { message: 'containment_unverified' });
});
test('wrong nonce/run labels fail closed', () => {
  const f = fixture();
  f.observed.Config.Labels['owned-containment.nonce'] = '0'.repeat(64);
  assert.throws(() => validateRecord(f.record, f.observed, f.intent, f.id), { message: 'containment_unverified' });
  f.observed.Config.Labels = { ...f.record.config.Labels, unexpected: 'label' };
  assert.throws(() => validateRecord(f.record, f.observed, f.intent, f.id), { message: 'containment_unverified' });
});
test('image and full security configuration mismatches fail closed', () => {
  // Mutate BOTH expected and observed config: these must fail admission, not merely equality.
  for (const init of [null, undefined, 'false', 0, {}, true]) {
    const invalid = fixture();
    invalid.record.securityConfig.Init = init;
    invalid.observed.HostConfig.Init = init;
    if (init === undefined) { delete invalid.record.securityConfig.Init; delete invalid.observed.HostConfig.Init; }
    assert.throws(() => validateRecord(invalid.record, invalid.observed, invalid.intent, invalid.id), { message: 'containment_unverified' });
  }
  const validEnvironment = fixture().observed.Config.Env;
  for (const env of [
    [...validEnvironment, 'NODE_OPTIONS=--require=/unowned/module'],
    [...validEnvironment, validEnvironment[0]],
    [...validEnvironment, 'HOST_PID_NAMESPACE=pid:[123]'],
    validEnvironment.filter(item => !item.startsWith('PATH=')),
    validEnvironment.map(item => item.startsWith('PATH=') ? 'PATH=/unowned' : item),
    null, {}, 'PATH=/bin', [...validEnvironment, null], [...validEnvironment, {}]
  ]) {
    const invalid = fixture();
    invalid.record.config.Env = structuredClone(env);
    invalid.observed.Config.Env = structuredClone(env);
    assert.throws(() => validateRecord(invalid.record, invalid.observed, invalid.intent, invalid.id), { message: 'containment_unverified' });
  }
  // Even an altered immutable baseline must itself satisfy the image allowlist.
  for (const env of [
    [...fixture().intent.imageEnvironment, 'UNEXPECTED=value'],
    [...fixture().intent.imageEnvironment, fixture().intent.imageEnvironment[0]],
    [], null, [null], ['PATH=/bin'],
    fixture().intent.imageEnvironment.map(item => item.startsWith('NODE_VERSION=') ? 'NODE_VERSION=24.0.0' : item)
  ]) {
    const invalid = fixture();
    invalid.intent.imageEnvironment = structuredClone(env);
    invalid.record.intent = structuredClone(invalid.intent);
    invalid.record.config.Env = Array.isArray(env) ? [...env, 'HOST_PID_NAMESPACE=pid:[123]'] : env;
    invalid.observed.Config.Env = structuredClone(invalid.record.config.Env);
    assert.throws(() => validateRecord(invalid.record, invalid.observed, invalid.intent, invalid.id), { message: 'containment_unverified' });
  }
  const f = fixture();
  f.observed.HostConfig.Privileged = true;
  assert.throws(() => validateRecord(f.record, f.observed, f.intent, f.id), { message: 'containment_unverified' });
  f.observed.HostConfig = structuredClone(f.record.securityConfig);
  f.observed.HostConfig.PidMode = 'host';
  assert.throws(() => validateRecord(f.record, f.observed, f.intent, f.id), { message: 'containment_unverified' });
  f.observed.HostConfig = structuredClone(f.record.securityConfig);
  f.observed.Image = 'sha256:' + 'e'.repeat(64);
  assert.throws(() => validateRecord(f.record, f.observed, f.intent, f.id), { message: 'containment_unverified' });
});
test('unknown, missing, error-shaped or extra-record evidence is never absence', () => {
  const f = fixture();
  for (const unknown of [null, undefined, {}, { code: 'EACCES' }, { error: 'No such container' }]) assert.throws(() => validateRecord(f.record, unknown, f.intent, f.id), { message: 'containment_unverified' });
  assert.throws(() => validateRecord({ ...f.record, unknown: true }, f.observed, f.intent, f.id), { message: 'containment_unverified' });
  assert.throws(() => validateRecord(f.record, { ...f.observed, State: undefined }, f.intent, f.id), { message: 'containment_unverified' });
});
