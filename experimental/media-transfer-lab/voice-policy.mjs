/* Offline synthetic admission model only. No signaling, WebRTC, network or media.
 * A rejected operation irreversibly closes this instance. A new instance is not
 * a persistent replay defense; production identity/epoch authority is external.
 */
export class VoicePolicyError extends Error {
  constructor(code) { super(code); this.name = 'VoicePolicyError'; this.code = code; }
}
const fail = code => { throw new VoicePolicyError(code); };
const id = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);
const bounded = (value, upper) => Number.isSafeInteger(value) && value > 0 && value <= upper;
const eventKeys = ['type', 'eventId', 'seq', 'epoch', 'roomId', 'callId', 'senderUserId', 'senderDeviceId'];
const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;

export function createVoicePolicy({ binding, authorize, clock, expiresAt,
  mode = 'direct', maxCandidates = 32, maxQueue = 8, maxEvents = 256 } = {}) {
  if (mode !== 'direct') fail('TOPOLOGY_DENIED');
  if (!plain(binding) || !id(binding.epoch) || !id(binding.roomId) || !id(binding.callId)) fail('INVALID_BINDING');
  if (!Array.isArray(binding.endpoints) || binding.endpoints.length !== 2) fail('TWO_ENDPOINTS_REQUIRED');
  const endpoints = binding.endpoints.map(endpoint => {
    if (!plain(endpoint) || !id(endpoint.userId) || !id(endpoint.deviceId) || endpoint.verified !== true) fail('UNVERIFIED_ENDPOINT');
    return Object.freeze({ userId: endpoint.userId, deviceId: endpoint.deviceId, verified: true });
  });
  if (endpoints[0].userId === endpoints[1].userId || endpoints[0].deviceId === endpoints[1].deviceId) fail('DISTINCT_ENDPOINTS_REQUIRED');
  if (typeof authorize !== 'function' || typeof clock !== 'function' || !Number.isSafeInteger(expiresAt)) fail('INVALID_AUTH_OR_CLOCK');
  if (!bounded(maxCandidates, 1024) || !bounded(maxQueue, 64) || !bounded(maxEvents, 4096)) fail('INVALID_LIMIT');
  const fixed = Object.freeze({ epoch: binding.epoch, roomId: binding.roomId, callId: binding.callId, endpoints: Object.freeze(endpoints) });
  let state = 'idle', sequence = 0, candidates = 0, pending = 0, lastTime = -Infinity;
  let tail = Promise.resolve();
  const seen = new Set();
  const snapshot = () => Object.freeze({ state, sequence, candidates, pending, binding: fixed });
  const close = code => { state = 'ended'; throw new VoicePolicyError(code); };
  const checkTime = () => {
    let now;
    try { now = clock(); } catch { close('CLOCK_FAILED'); }
    if (!Number.isSafeInteger(now) || now < lastTime) close('CLOCK_INVALID');
    lastTime = now;
    if (now >= expiresAt) close('EXPIRED');
  };
  checkTime();

  const authorizePhase = async (phase, event, from, to) => {
    const context = Object.freeze({ phase, binding: fixed, event, from, to });
    let allowed;
    try { allowed = await authorize(context); } catch { close('AUTH_FAILED'); }
    if (allowed !== true) close('AUTH_DENIED');
    if (state === 'ended') close('TERMINAL');
    checkTime();
  };
  const run = async event => {
    if (state === 'ended') fail('TERMINAL');
    checkTime();
    if (event.epoch !== fixed.epoch || event.roomId !== fixed.roomId || event.callId !== fixed.callId) close('BINDING_MISMATCH');
    const actor = endpoints.findIndex(e => e.userId === event.senderUserId && e.deviceId === event.senderDeviceId);
    if (actor < 0) close('SENDER_DENIED');
    if (seen.has(event.eventId) || event.seq !== sequence + 1) close('REPLAY_OR_ORDER');
    if (seen.size >= maxEvents) close('EVENT_LIMIT');
    let next;
    if (event.type === 'ring' && state === 'idle' && actor === 0) next = 'ringing';
    else if (event.type === 'accept' && state === 'ringing' && actor === 1) next = 'accepted';
    else if (event.type === 'connect' && state === 'accepted') next = 'connected';
    else if (event.type === 'candidate' && (state === 'accepted' || state === 'connected')) {
      if (candidates >= maxCandidates) close('CANDIDATE_LIMIT');
      next = state;
    } else if (event.type === 'hangup' && state !== 'idle') next = 'ended';
    else close('TRANSITION_DENIED');
    const from = state;
    await authorizePhase('before', event, from, next);
    // The post phase validates a proposed result, not a partially committed state.
    // Both fresh authorization checks must succeed before publishing the transition.
    await authorizePhase('after', event, from, next);
    state = next;
    sequence = event.seq;
    seen.add(event.eventId);
    if (event.type === 'candidate') candidates++;
    return snapshot();
  };

  const dispatch = input => {
    if (state === 'ended') return Promise.reject(new VoicePolicyError('TERMINAL'));
    if (pending >= maxQueue) {
      state = 'ended';
      return Promise.reject(new VoicePolicyError('QUEUE_LIMIT'));
    }
    // Reject accessors, unknown fields, SDP, ICE payloads, media and key material.
    // Only detached, bounded synthetic metadata may enter the serialized queue.
    let event;
    try {
      if (!plain(input)) fail('INVALID_EVENT');
      const descriptors = Object.getOwnPropertyDescriptors(input);
      if (Reflect.ownKeys(descriptors).length !== eventKeys.length ||
          eventKeys.some(key => !descriptors[key] || !Object.hasOwn(descriptors[key], 'value'))) fail('INVALID_EVENT');
      event = Object.fromEntries(eventKeys.map(key => [key, descriptors[key].value]));
      if (eventKeys.filter(key => key !== 'seq').some(key => !id(event[key])) || !bounded(event.seq, 4096)) fail('INVALID_EVENT');
      Object.freeze(event);
    } catch {
      state = 'ended';
      return Promise.reject(new VoicePolicyError('INVALID_EVENT'));
    }
    pending++;
    const operation = tail.then(() => run(event));
    const settled = operation.finally(() => { pending--; });
    tail = settled.catch(() => {});
    return settled;
  };
  return Object.freeze({ dispatch, snapshot });
}
