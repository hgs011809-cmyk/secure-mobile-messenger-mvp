import test from 'node:test';
import assert from 'node:assert/strict';
import { createVoicePolicy, VoicePolicyError } from './voice-policy.mjs';

const makeBinding = () => ({ epoch: 'epoch-1', roomId: 'room-1', callId: 'call-1', endpoints: [
  { userId: 'alice', deviceId: 'alice-device', verified: true },
  { userId: 'bob', deviceId: 'bob-device', verified: true }
] });
const make = (overrides = {}) => createVoicePolicy({ binding: makeBinding(), authorize: async () => true,
  clock: () => 100, expiresAt: 1000, ...overrides });
const event = (type, seq, actor = 0, overrides = {}) => ({ type, seq, eventId: `event-${seq}`,
  epoch: 'epoch-1', roomId: 'room-1', callId: 'call-1',
  senderUserId: actor ? 'bob' : 'alice', senderDeviceId: actor ? 'bob-device' : 'alice-device', ...overrides });
const denied = (promise, code) => assert.rejects(promise, error => error instanceof VoicePolicyError && error.code === code);
const accept = async policy => { await policy.dispatch(event('ring', 1)); await policy.dispatch(event('accept', 2, 1)); };

// No SDK import, transport, microphone, media or live credentials are used here.
test('ordered lifecycle uses fresh before/after authorization for every transition', async () => {
  const calls = [];
  const p = make({ authorize: async context => { calls.push(context); return true; } });
  await accept(p);
  await p.dispatch(event('connect', 3));
  assert.equal(p.snapshot().state, 'connected');
  await p.dispatch(event('hangup', 4, 1));
  assert.equal(p.snapshot().state, 'ended');
  assert.deepEqual(calls.map(c => c.phase), ['before', 'after', 'before', 'after', 'before', 'after', 'before', 'after']);
  assert.ok(calls.every(c => Object.isFrozen(c) && Object.isFrozen(c.event) && Object.isFrozen(c.binding)));
  assert.equal(calls.at(-1).from, 'connected');
  assert.equal(calls.at(-1).to, 'ended');
});

test('binding is detached and recursively immutable', () => {
  const binding = makeBinding();
  const p = make({ binding });
  binding.epoch = 'changed'; binding.endpoints[0].verified = false; binding.endpoints.push({});
  assert.equal(p.snapshot().binding.epoch, 'epoch-1');
  assert.equal(p.snapshot().binding.endpoints.length, 2);
  assert.equal(p.snapshot().binding.endpoints[0].verified, true);
  assert.throws(() => { p.snapshot().binding.endpoints[0].userId = 'mallory'; }, TypeError);
  assert.ok(Object.isFrozen(p.snapshot()));
});

test('strictly two verified distinct users and devices are required', () => {
  for (const endpoints of [[], makeBinding().endpoints.slice(0, 1), [...makeBinding().endpoints, { userId: 'c', deviceId: 'c', verified: true }]]) {
    assert.throws(() => make({ binding: { ...makeBinding(), endpoints } }), /TWO_ENDPOINTS_REQUIRED/);
  }
  const bad = makeBinding(); bad.endpoints[1].verified = false;
  assert.throws(() => make({ binding: bad }), /UNVERIFIED_ENDPOINT/);
  for (const key of ['userId', 'deviceId']) {
    const duplicate = makeBinding(); duplicate.endpoints[1][key] = duplicate.endpoints[0][key];
    assert.throws(() => make({ binding: duplicate }), /DISTINCT_ENDPOINTS_REQUIRED/);
  }
});

test('group and SFU topologies are denied', () => {
  for (const mode of ['group', 'sfu', 'mesh', null]) assert.throws(() => make({ mode }), /TOPOLOGY_DENIED/);
});

test('epoch room and call substitution permanently deny admission', async () => {
  for (const key of ['epoch', 'roomId', 'callId']) {
    const p = make();
    await denied(p.dispatch(event('ring', 1, 0, { [key]: 'other' })), 'BINDING_MISMATCH');
    assert.equal(p.snapshot().state, 'ended');
    await denied(p.dispatch(event('ring', 1)), 'TERMINAL');
  }
});

test('sender must match both user and device in binding', async () => {
  for (const override of [{ senderUserId: 'mallory' }, { senderDeviceId: 'bob-device' }, { senderDeviceId: 'new-device' }]) {
    const p = make(); await denied(p.dispatch(event('ring', 1, 0, override)), 'SENDER_DENIED');
  }
});

test('only caller rings and only callee accepts', async () => {
  const p = make(); await denied(p.dispatch(event('ring', 1, 1)), 'TRANSITION_DENIED');
  const q = make(); await q.dispatch(event('ring', 1)); await denied(q.dispatch(event('accept', 2)), 'TRANSITION_DENIED');
});

test('connect cannot skip ringing or acceptance', async () => {
  for (const prior of [false, true]) {
    const p = make(); if (prior) await p.dispatch(event('ring', 1));
    await denied(p.dispatch(event('connect', prior ? 2 : 1)), 'TRANSITION_DENIED');
  }
});

test('hangup is terminal and cannot be retried idempotently', async () => {
  const p = make(); await p.dispatch(event('ring', 1)); await p.dispatch(event('hangup', 2));
  await denied(p.dispatch(event('hangup', 2)), 'TERMINAL');
  await denied(p.dispatch(event('ring', 3)), 'TERMINAL');
});

test('duplicate event identifiers fail closed even with fresh sequence', async () => {
  const p = make(); await p.dispatch(event('ring', 1));
  await denied(p.dispatch(event('accept', 2, 1, { eventId: 'event-1' })), 'REPLAY_OR_ORDER');
  assert.equal(p.snapshot().state, 'ended');
});

test('replay and gaps fail closed without idempotent success', async () => {
  for (const seq of [1, 3]) {
    const p = make(); await p.dispatch(event('ring', 1));
    await denied(p.dispatch(event('accept', seq, 1, { eventId: 'fresh' })), 'REPLAY_OR_ORDER');
  }
});

test('candidate admission is count only and bounded', async () => {
  const p = make({ maxCandidates: 2 }); await accept(p);
  await p.dispatch(event('candidate', 3)); await p.dispatch(event('candidate', 4, 1));
  assert.equal(p.snapshot().candidates, 2);
  await denied(p.dispatch(event('candidate', 5)), 'CANDIDATE_LIMIT');
  assert.equal(p.snapshot().candidates, 2);
  const early = make(); await denied(early.dispatch(event('candidate', 1)), 'TRANSITION_DENIED');
});

test('pre-authorization denial and thrown callbacks terminate', async () => {
  for (const authorize of [async () => false, async () => 'true', async () => { throw new Error('secret'); }]) {
    const p = make({ authorize });
    await assert.rejects(p.dispatch(event('ring', 1)), error => error instanceof VoicePolicyError && !error.message.includes('secret'));
    assert.equal(p.snapshot().sequence, 0); assert.equal(p.snapshot().state, 'ended');
  }
});

test('post-authorization revocation does not publish proposed transition', async () => {
  const phases = [];
  const p = make({ authorize: async ({ phase }) => { phases.push(phase); return phase === 'before'; } });
  await denied(p.dispatch(event('ring', 1)), 'AUTH_DENIED');
  assert.deepEqual(phases, ['before', 'after']);
  assert.equal(p.snapshot().sequence, 0); assert.equal(p.snapshot().state, 'ended');
});

test('expiry is checked initially and after each awaited authorization', async () => {
  assert.throws(() => make({ expiresAt: 100 }), /EXPIRED/);
  for (const expireAtPhase of ['before', 'after']) {
    let now = 100;
    const p = make({ clock: () => now, authorize: async ({ phase }) => { if (phase === expireAtPhase) now = 1000; return true; } });
    await denied(p.dispatch(event('ring', 1)), 'EXPIRED');
    assert.equal(p.snapshot().sequence, 0);
  }
});

test('clock rollback and clock failures deny transitions', async () => {
  let now = 100; const p = make({ clock: () => now }); now = 99;
  await denied(p.dispatch(event('ring', 1)), 'CLOCK_INVALID');
  let throws = false; const q = make({ clock: () => { if (throws) throw new Error('internal'); return 100; } }); throws = true;
  await denied(q.dispatch(event('ring', 1)), 'CLOCK_FAILED');
});

test('serialized queue preserves arrival order and detached event values', async () => {
  const p = make(); const first = event('ring', 1);
  const a = p.dispatch(first); first.callId = 'mutated';
  const b = p.dispatch(event('accept', 2, 1)); const c = p.dispatch(event('connect', 3));
  await Promise.all([a, b, c]);
  assert.equal(p.snapshot().state, 'connected'); assert.equal(p.snapshot().sequence, 3); assert.equal(p.snapshot().pending, 0);
});

test('queue saturation closes and prevents suspended authorization commit', async () => {
  let release; let started;
  const entered = new Promise(resolve => { started = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const p = make({ maxQueue: 1, authorize: async () => { started(); await gate; return true; } });
  const first = p.dispatch(event('ring', 1));
  const firstDenied = denied(first, 'TERMINAL');
  await entered;
  await denied(p.dispatch(event('accept', 2, 1)), 'QUEUE_LIMIT');
  release(); await firstDenied;
  assert.equal(p.snapshot().sequence, 0); assert.equal(p.snapshot().pending, 0);
});

test('payloads unknown fields and accessors never enter admission queue', async () => {
  for (const extra of [{ sdp: 'not-real' }, { candidate: 'not-real' }, { audio: new Uint8Array(1) }, { key: 'not-real' }, { group: true }, { sfu: true }]) {
    const p = make(); await denied(p.dispatch({ ...event('ring', 1), ...extra }), 'INVALID_EVENT');
    assert.equal(p.snapshot().sequence, 0);
  }
  let read = false; const input = event('ring', 1);
  Object.defineProperty(input, 'type', { get() { read = true; return 'ring'; }, enumerable: true });
  await denied(make().dispatch(input), 'INVALID_EVENT'); assert.equal(read, false);
});

test('finite event budget and malformed limits are enforced', async () => {
  for (const limits of [{ maxQueue: 0 }, { maxQueue: 65 }, { maxCandidates: Infinity }, { maxEvents: 4097 }]) assert.throws(() => make(limits), /INVALID_LIMIT/);
  const p = make({ maxEvents: 1 }); await p.dispatch(event('ring', 1));
  await denied(p.dispatch(event('accept', 2, 1)), 'EVENT_LIMIT');
});
