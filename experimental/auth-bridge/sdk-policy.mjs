import { createPublicKey, verify } from 'node:crypto';

// Experimental request policy only. No I/O, token handling, provisioning, or response filtering.
// Limits are intentionally smaller than Matrix's general-purpose API limits.
const SAS = ['request', 'ready', 'start', 'accept', 'key', 'mac', 'done', 'cancel'].map(x => `m.key.verification.${x}`);
const ALGORITHMS = ['m.olm.v1.curve25519-aes-sha2', 'm.megolm.v1.aes-sha2'];
const obj = x => x !== null && typeof x === 'object' && !Array.isArray(x) && [Object.prototype, null].includes(Object.getPrototypeOf(x));
const fields = (x, allowed, required = []) => obj(x) && Object.keys(x).every(k => allowed.includes(k)) && required.every(k => Object.hasOwn(x, k));
const text = (x, max = 256) => typeof x === 'string' && x.length > 0 && x.length <= max && !/[\x00-\x20\x7f\\/%]/.test(x) && x !== '.' && x !== '..';
const token = (x, max = 512) => typeof x === 'string' && x.length > 0 && x.length <= max && !/[\x00-\x1f\x7f]/.test(x);
function b64(x, bytes, max = 65536) {
  if (typeof x !== 'string' || !x.length || x.length > max || !/^[A-Za-z0-9+/]+={0,2}$/.test(x)) return false;
  const b = Buffer.from(x, 'base64');
  return (!bytes || b.length === bytes) && b.toString('base64').replace(/=+$/, '') === x.replace(/=+$/, '') && (x.includes('=') ? b.toString('base64') === x : true);
}
function canonical(x, depth = 0) {
  if (depth > 20) throw new Error('depth');
  if (x === null || typeof x === 'boolean' || typeof x === 'string') return JSON.stringify(x);
  if (typeof x === 'number' && Number.isSafeInteger(x)) return String(x);
  if (Array.isArray(x)) return '[' + x.map(v => canonical(v, depth + 1)).join(',') + ']';
  if (!obj(x)) throw new Error('json');
  return '{' + Object.keys(x).sort().map(k => JSON.stringify(k) + ':' + canonical(x[k], depth + 1)).join(',') + '}';
}
function signed(x, own) {
  const kid = `ed25519:${own.matrixDeviceId}`;
  if (!fields(x.signatures, [own.userId], [own.userId]) || !fields(x.signatures[own.userId], [kid], [kid]) || !b64(x.signatures[own.userId][kid], 64)) return false;
  const unsigned = Object.fromEntries(Object.entries(x).filter(([k]) => k !== 'signatures' && k !== 'unsigned'));
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(own.ed25519, 'base64')]), format: 'der', type: 'spki' });
  return verify(null, Buffer.from(canonical(unsigned)), key, Buffer.from(x.signatures[own.userId][kid], 'base64'));
}
function forcedFilter(binding) {
  const senders = binding.devices.map(d => d.userId);
  return {
    presence: { types: [] }, account_data: { types: [] },
    to_device: { senders, types: [...SAS, 'm.room.encrypted'] },
    room: { rooms: [binding.roomId], include_leave: false,
      account_data: { types: [] }, ephemeral: { types: [] },
      state: { rooms: [binding.roomId], lazy_load_members: false },
      timeline: { rooms: [binding.roomId], types: ['m.room.encrypted', 'm.room.redaction'], limit: 100 }
    }
  };
}
function parseTarget(target) {
  if (typeof target !== 'string' || target.length > 8192 || !target.startsWith('/') || target.startsWith('//') || /[\\\x00-\x20\x7f#]/.test(target)) return null;
  const parts = target.split('?'); if (parts.length > 2) return null;
  const raw = parts[0].split('/');
  const segments = raw.map((s, i) => {
    if (i === 0 || i === raw.length - 1 && s === '' && parts[0].endsWith('/pushrules/')) return '';
    const d = decodeURIComponent(s);
    if (!text(d) || encodeURIComponent(d) !== s) throw new Error('path encoding');
    return d;
  });
  // URLSearchParams is permissive: explicitly require canonical encoded name/value pairs.
  const query = new Map();
  if (parts.length === 2 && !parts[1]) return null;
  for (const pair of parts[1]?.split('&') || []) {
    const at = pair.indexOf('='); if (at < 1) return null;
    const rk = pair.slice(0, at), rv = pair.slice(at + 1), k = decodeURIComponent(rk), v = decodeURIComponent(rv);
    if (query.has(k) || encodeURIComponent(k) !== rk || encodeURIComponent(v) !== rv || /[\x00-\x1f\x7f]/.test(v)) return null;
    query.set(k, v);
  }
  return { segments: segments.slice(1), pathname: parts[0], query };
}
function queries(q, rules) {
  return [...q].every(([k, v]) => Object.hasOwn(rules, k) && rules[k](v));
}
const decimal = (v, max) => /^(0|[1-9]\d*)$/.test(v) && Number(v) <= max;
function keyUpload(body, own) {
  if (!fields(body, ['device_keys', 'one_time_keys', 'fallback_keys']) || !Object.keys(body).length) return false;
  if (Object.hasOwn(body, 'device_keys')) {
    const d = body.device_keys, ed = `ed25519:${own.matrixDeviceId}`, curve = `curve25519:${own.matrixDeviceId}`;
    if (!fields(d, ['user_id', 'device_id', 'algorithms', 'keys', 'signatures'], ['user_id', 'device_id', 'algorithms', 'keys', 'signatures']) || d.user_id !== own.userId || d.device_id !== own.matrixDeviceId || !Array.isArray(d.algorithms) || d.algorithms.length !== 2 || new Set(d.algorithms).size !== 2 || !d.algorithms.every(a => ALGORITHMS.includes(a)) || !fields(d.keys, [ed, curve], [ed, curve]) || d.keys[ed] !== own.ed25519 || d.keys[curve] !== own.curve25519 || !signed(d, own)) return false;
  }
  for (const name of ['one_time_keys', 'fallback_keys']) {
    if (!Object.hasOwn(body, name)) continue;
    const keys = body[name]; if (!obj(keys) || Object.keys(keys).length > (name === 'fallback_keys' ? 1 : 100)) return false;
    for (const [id, value] of Object.entries(keys)) {
      if (!/^signed_curve25519:[A-Za-z0-9_-]{1,128}$/.test(id) || !fields(value, ['key', 'signatures', 'fallback'], ['key', 'signatures']) || !b64(value.key, 32) || (name === 'fallback_keys' ? value.fallback !== true : Object.hasOwn(value, 'fallback')) || !signed(value, own)) return false;
    }
  }
  return true;
}
function keyLookup(body, binding, claim) {
  const name = claim ? 'one_time_keys' : 'device_keys';
  if (!fields(body, [name, 'timeout', ...(claim ? [] : ['token'])], [name]) || (Object.hasOwn(body, 'timeout') && (!Number.isInteger(body.timeout) || body.timeout < 1 || body.timeout > 30000)) || (Object.hasOwn(body, 'token') && !token(body.token))) return false;
  const map = body[name]; if (!obj(map) || !Object.keys(map).length || Object.keys(map).length > 2) return false;
  return Object.entries(map).every(([uid, values]) => {
    const device = binding.devices.find(d => d.userId === uid); if (!device) return false;
    return claim ? fields(values, [device.matrixDeviceId], [device.matrixDeviceId]) && values[device.matrixDeviceId] === 'signed_curve25519' : Array.isArray(values) && (values.length === 0 || values.length === 1 && values[0] === device.matrixDeviceId);
  });
}
function sasContent(type, c, own) {
  const name = type.slice('m.key.verification.'.length);
  const schemas = {
    request: ['from_device', 'methods', 'timestamp', 'transaction_id'], ready: ['from_device', 'methods', 'transaction_id'],
    start: ['from_device', 'method', 'key_agreement_protocols', 'hashes', 'message_authentication_codes', 'short_authentication_string', 'transaction_id'],
    accept: ['method', 'key_agreement_protocol', 'hash', 'message_authentication_code', 'short_authentication_string', 'commitment', 'transaction_id'],
    key: ['key', 'transaction_id'], mac: ['mac', 'keys', 'transaction_id'], done: ['transaction_id'], cancel: ['code', 'reason', 'transaction_id']
  };
  if (!fields(c, schemas[name], schemas[name]) || !text(c.transaction_id, 128) || (Object.hasOwn(c, 'from_device') && c.from_device !== own.matrixDeviceId)) return false;
  const list = (x, values) => Array.isArray(x) && x.length > 0 && x.length <= 8 && new Set(x).size === x.length && x.every(v => values.includes(v));
  if (name === 'request' || name === 'ready') return list(c.methods, ['m.sas.v1']) && (name !== 'request' || Number.isSafeInteger(c.timestamp) && c.timestamp >= 0);
  if (name === 'start') return c.method === 'm.sas.v1' && list(c.key_agreement_protocols, ['curve25519-hkdf-sha256', 'curve25519']) && list(c.hashes, ['sha256']) && list(c.message_authentication_codes, ['hkdf-hmac-sha256.v2', 'hkdf-hmac-sha256']) && list(c.short_authentication_string, ['decimal', 'emoji']);
  if (name === 'accept') return c.method === 'm.sas.v1' && ['curve25519-hkdf-sha256', 'curve25519'].includes(c.key_agreement_protocol) && c.hash === 'sha256' && ['hkdf-hmac-sha256.v2', 'hkdf-hmac-sha256'].includes(c.message_authentication_code) && list(c.short_authentication_string, ['decimal', 'emoji']) && b64(c.commitment, 32);
  if (name === 'key') return b64(c.key, 32);
  if (name === 'mac') return obj(c.mac) && Object.keys(c.mac).length > 0 && Object.keys(c.mac).length <= 3 && Object.entries(c.mac).every(([k,v]) => /^ed25519:[A-Za-z0-9+/_=-]{1,128}$/.test(k) && b64(v, 32)) && b64(c.keys, 32);
  return name === 'done' || name === 'cancel' && text(c.code, 128) && token(c.reason, 256);
}

/** Returns a detached, canonical upstream descriptor or null. Missing GET body is normalized to null.
 * Bindings must be two distinct users/devices with pre-admitted 32-byte Ed25519/Curve25519 pins.
 * identity.deviceId is the bridge session device ID; matrixDeviceId selects the Matrix pin.
 * ownerSigning is deliberately unused: cross-signing remains default-denied.
 */
export function authorizeSdkRequest({ method, target, body, identity, binding } = {}) {
  try {
    if (!['GET', 'POST', 'PUT'].includes(method)) return null;
    const p = parseTarget(target); if (!p) return null;
    const { segments: s, query: q } = p;
    const result = (b = null, path = target, publicFlag = false) => ({ path, method, body: b === null ? null : JSON.parse(canonical(b)), ...(publicFlag ? { public: true } : {}) });
    if (method === 'GET' && p.pathname === '/_matrix/client/versions' && !q.size && body == null) return result(null, p.pathname, true);
    if (!obj(binding) || !text(binding.roomId) || !binding.roomId.startsWith('!') || !Array.isArray(binding.devices) || binding.devices.length !== 2 || !binding.devices.every(d => obj(d) && text(d.userId) && d.userId.startsWith('@') && text(d.matrixDeviceId, 128) && b64(d.ed25519, 32) && b64(d.curve25519, 32) && (d.active === undefined || typeof d.active === 'boolean')) || new Set(binding.devices.map(d => d.userId)).size !== 2 || new Set(binding.devices.map(d => d.curve25519)).size !== 2 || new Set(binding.devices.map(d => d.ed25519)).size !== 2) return null;
    if (!obj(identity) || !text(identity.deviceId, 128)) return null;
    const own = binding.devices.find(d => d.userId === identity.userId && d.matrixDeviceId === identity.matrixDeviceId); if (!own || own.active === false) return null;
    if (s[0] !== '_matrix' || s[1] !== 'client' || !['v3', 'r0'].includes(s[2])) return null;
    const route = s.slice(3);
    if (body != null && canonical(body).length > 262144) return null;
    if (method === 'GET') {
      if (body != null) return null;
      if (['account/whoami', 'devices', 'capabilities', 'pushrules', 'pushrules/'].includes(route.join('/')) && !q.size) return result();
      if (route.length === 1 && route[0] === 'sync' && queries(q, { since: v => token(v), timeout: v => decimal(v, 30000), filter: v => token(v, 4096), full_state: v => ['true', 'false'].includes(v), set_presence: v => ['online','offline', 'unavailable'].includes(v), _cacheBuster: v => decimal(v,9999999999999), 'org.matrix.msc4222.use_state_after': v=>['true','false'].includes(v) })) {
        const forced = new URLSearchParams(); for (const [k, v] of q) if (k !== 'filter') forced.set(k, v);
        forced.set('set_presence','offline');forced.set('filter', canonical(forcedFilter(binding)));
        return result(null, p.pathname + '?' + forced.toString());
      }
      if (route[0] !== 'rooms' || route[1] !== binding.roomId) return null;
      if (route.length === 3 && route[2] === 'state' && !q.size) return result();
      if (route.length === 3 && route[2] === 'members' && queries(q, { at: v => token(v), membership: v => ['join', 'invite', 'leave', 'ban', 'knock'].includes(v), not_membership: v => ['join', 'invite', 'leave', 'ban', 'knock'].includes(v) })) return result();
      if (route.length === 3 && route[2] === 'messages' && queries(q, { from: v => token(v), to: v => token(v), dir: v => ['b', 'f'].includes(v), limit: v => decimal(v, 100) }) && q.has('dir')) return result();
      if (route.length === 4 && route[2] === 'event' && route[3].startsWith('$') && text(route[3], 256) && !q.size) return result();
      return null;
    }
    if (q.size || !obj(body)) return null;
    if (method === 'POST') {
      if (route.join('/') === 'keys/upload' && keyUpload(body, own)) return result(body);
      if (['keys/query', 'keys/claim'].includes(route.join('/')) && keyLookup(body, binding, route[1] === 'claim')) {
        if (route[1] === 'claim') return binding.devices.some(d => d.active === false) ? null : result(body);
        // SDK43 uses [] to mean all devices. Never forward that wildcard: pin explicitly.
        const rewritten = { ...body, device_keys: Object.fromEntries(Object.keys(body.device_keys).map(uid => [uid, [binding.devices.find(d => d.userId === uid).matrixDeviceId]])) };
        return result(rewritten);
      }
      if (route.length === 3 && route[0] === 'user' && route[1] === own.userId && route[2] === 'filter') return result(forcedFilter(binding));
      return null;
    }
    if (route[0] === 'sendToDevice' && binding.devices.some(d => d.active === false)) return null;
    if (route.length === 3 && route[0] === 'sendToDevice' && text(route[2], 128) && fields(body, ['messages'], ['messages']) && obj(body.messages) && Object.keys(body.messages).length === 1) {
      const recipient = binding.devices.find(d => d.userId !== own.userId && Object.hasOwn(body.messages, d.userId));
      if (!recipient || !fields(body.messages[recipient.userId], [recipient.matrixDeviceId], [recipient.matrixDeviceId])) return null;
      const c = body.messages[recipient.userId][recipient.matrixDeviceId];
      if (SAS.includes(route[1]) && sasContent(route[1], c, own)) return result(body);
      if (route[1] === 'm.room.encrypted' && fields(c, ['algorithm', 'sender_key', 'ciphertext'], ['algorithm', 'sender_key', 'ciphertext']) && c.algorithm === ALGORITHMS[0] && c.sender_key === own.curve25519 && fields(c.ciphertext, [recipient.curve25519], [recipient.curve25519])) {
        const envelope = c.ciphertext[recipient.curve25519];
        if (fields(envelope, ['type', 'body'], ['type', 'body']) && [0, 1].includes(envelope.type) && b64(envelope.body)) return result(body);
      }
      return null;
    }
    if (route[0] !== 'rooms' || route[1] !== binding.roomId || route.length !== 5 || !text(route[4], 128)) return null;
    if (route[2] === 'redact' && text(route[3], 256) && route[3].startsWith('$') && fields(body, [])) return result(body);
    if (route[2] === 'send' && binding.devices.some(d => d.active === false)) return null;
    if (route[2] === 'send' && route[3] === 'm.room.encrypted' && fields(body, ['algorithm', 'device_id', 'sender_key', 'session_id', 'ciphertext'], ['algorithm', 'device_id', 'sender_key', 'session_id', 'ciphertext']) && body.algorithm === ALGORITHMS[1] && body.device_id === own.matrixDeviceId && body.sender_key === own.curve25519 && b64(body.session_id, 32) && b64(body.ciphertext)) return result(body);
    return null;
  } catch { return null; }
}
