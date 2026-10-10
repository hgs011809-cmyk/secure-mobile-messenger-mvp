import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Store } from '../src/store.js';
import { TtlMap } from '../src/ttlMap.js';
import { RateLimiter } from '../src/rateLimit.js';
import { fingerprintSpki, secretsEqual, turnCredentials } from '../src/crypto.js';

const root = process.env.TEST_TMP_DIR || path.resolve('.test-tmp');

async function makeStore() {
  await fs.mkdir(root, { recursive: true });
  const dir = await fs.mkdtemp(path.join(root, 'store-'));
  return { dir, file: path.join(dir, 'store.json'), store: new Store(path.join(dir, 'store.json')) };
}

test('Store atomically registers one device with a one-time invite', async () => {
  const { dir, store } = await makeStore();
  try {
    const invite = await store.createInvite(60000);
    const record = { deviceId: 'device_1234567890', peerId: 'dm-1234567890abcdef1234567890abcd', publicKeySpkiB64: 'key', fingerprint: 'fp', createdAt: 'now' };
    assert.equal((await store.registerDevice(`${invite.inviteId}.wrong`, record.peerId, record)).ok, false);
    assert.equal((await store.registerDevice(invite.inviteCode, record.peerId, record)).ok, true);
    assert.deepEqual(await store.getDevice(record.deviceId), record);
    assert.equal((await store.registerDevice(invite.inviteCode, record.peerId, { ...record, deviceId: 'device_abcdefghijk' })).ok, false);
    assert.equal(await store.revokeDevice(record.deviceId), true);
    assert.equal(await store.getDevice(record.deviceId), null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('Store creates an 8-digit one-time numeric invite', async () => {
  const { dir, store } = await makeStore();
  try {
    const invite = await store.createInvite(60000, { numeric: true });
    assert.match(invite.inviteCode, /^\d{8}$/);
    const record = { deviceId: 'device_numeric_1234', peerId: 'dm-abcdef1234567890abcdef12345678', publicKeySpkiB64: 'key', fingerprint: 'fp', createdAt: 'now' };
    assert.equal((await store.registerDevice('00000000', record.peerId, record)).ok, false);
    assert.equal((await store.registerDevice(invite.inviteCode, record.peerId, record)).ok, true);
    assert.equal((await store.registerDevice(invite.inviteCode, record.peerId, { ...record, deviceId: 'device_numeric_5678' })).ok, false);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('Store writes the database with mode 0600 on POSIX', async () => {
  const { dir, file, store } = await makeStore();
  try {
    await store.createInvite(60000);
    if (process.platform !== 'win32') assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('TTL map and rate limiter expire and cap entries', async () => {
  const map = new TtlMap();
  map.set('x', 1, 10);
  assert.equal(map.get('x'), 1);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(map.get('x'), undefined);
  map.set('once', { ok: true }, 1000);
  assert.deepEqual(map.take('once'), { ok: true });
  assert.equal(map.take('once'), undefined);
  const limiter = new RateLimiter({ windowMs: 60000, max: 2 });
  assert.equal(limiter.check('a'), true);
  assert.equal(limiter.check('a'), true);
  assert.equal(limiter.check('a'), false);
});

test('crypto helpers produce stable fingerprints and coturn REST credentials', () => {
  const key = Buffer.from('public-key').toString('base64url');
  assert.equal(fingerprintSpki(key).length, 64);
  assert.equal(secretsEqual('same', 'same'), true);
  assert.equal(secretsEqual('same', 'nope'), false);
  const turn = turnCredentials('turn-secret', 'device-id', 600);
  assert.equal(turn.credential, crypto.createHmac('sha1', 'turn-secret').update(turn.username).digest('base64'));
});
