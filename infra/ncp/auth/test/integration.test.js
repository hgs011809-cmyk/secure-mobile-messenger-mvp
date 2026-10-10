import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createServer } from '../src/server.js';

const { subtle } = crypto.webcrypto;
const ADMIN_SECRET = 'test-admin-secret';
const ORIGIN = 'https://app.example.test';
const TURN_SECRET = 'test-turn-secret';
const PEER_ID = 'dm-1234567890abcdef1234567890abcd';
const root = process.env.TEST_TMP_DIR || path.resolve('.test-tmp');

async function start(overrides = {}) {
  await fs.mkdir(root, { recursive: true });
  const dataDir = await fs.mkdtemp(path.join(root, 'integration-'));
  const app = createServer({
    port: 0,
    dataDir,
    adminSecret: ADMIN_SECRET,
    allowedOrigin: ORIGIN,
    turnSecret: TURN_SECRET,
    signalHost: 'signal.example.test',
    signalPort: 443,
    signalPath: '/peerjs',
    signalSecure: true,
    stunUrls: ['stun:turn.example.test:3478'],
    turnUrls: ['turn:turn.example.test:3478?transport=udp', 'turn:turn.example.test:3478?transport=tcp'],
    rateLimitMax: 1000,
    ...overrides,
  });
  const port = await app.listen();
  return { app, dataDir, base: `http://127.0.0.1:${port}` };
}

async function stop(app, dataDir) {
  await app.close();
  await fs.rm(dataDir, { recursive: true, force: true });
}

async function json(base, pathName, body, headers = {}) {
  const response = await fetch(`${base}${pathName}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN, ...headers },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

async function admin(base, pathName, body = {}) {
  const response = await fetch(`${base}${pathName}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-admin-secret': ADMIN_SECRET },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

async function keyPair() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const spki = Buffer.from(await subtle.exportKey('spki', pair.publicKey)).toString('base64url');
  return { pair, spki };
}

async function sign(privateKey, text) {
  return Buffer.from(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, Buffer.from(text))).toString('base64url');
}

test('invite, registration, signed session, TURN credentials, signaling gate, and revocation', async () => {
  const { app, dataDir, base } = await start();
  try {
    const invitation = await admin(base, '/internal/admin/invites', { ttlSeconds: 60, format: 'numeric' });
    assert.equal(invitation.response.status, 201);
    assert.match(invitation.body.inviteCode, /^\d{8}$/);
    const { pair, spki } = await keyPair();

    const registration = await json(base, '/v1/register', { invite: invitation.body.inviteCode, peerId: PEER_ID, publicKey: spki });
    assert.equal(registration.response.status, 201);
    assert.ok(registration.body.deviceId);
    const deviceId = registration.body.deviceId;

    const reused = await json(base, '/v1/register', { invite: invitation.body.inviteCode, peerId: PEER_ID, publicKey: spki });
    assert.equal(reused.response.status, 400);
    assert.equal(reused.body.error, 'invite_invalid');

    const challenge = await json(base, '/v1/challenge', { deviceId, peerId: PEER_ID });
    assert.equal(challenge.response.status, 200);
    assert.ok(challenge.body.challengeText.startsWith('direct-auth-v1\n'));
    const signature = await sign(pair.privateKey, challenge.body.challengeText);

    const session = await json(base, '/v1/session', { deviceId, peerId: PEER_ID, challengeId: challenge.body.challengeId, signature });
    assert.equal(session.response.status, 200);
    assert.equal(session.body.signaling.host, 'signal.example.test');
    assert.equal(session.body.iceServers.length, 2);
    const turn = session.body.iceServers[1];
    assert.equal(turn.credential, crypto.createHmac('sha1', TURN_SECRET).update(turn.username).digest('base64'));

    const replaySession = await json(base, '/v1/session', { deviceId, peerId: PEER_ID, challengeId: challenge.body.challengeId, signature });
    assert.equal(replaySession.response.status, 401);

    const verify = await fetch(`${base}/internal/verify-signal`, {
      headers: { 'x-forwarded-uri': `/peerjs/peerjs?key=peerjs&id=${PEER_ID}&token=${session.body.signalToken}&version=1.5.5` },
    });
    assert.equal(verify.status, 200);
    const replayToken = await fetch(`${base}/internal/verify-signal`, {
      headers: { 'x-forwarded-uri': `/peerjs/peerjs?key=peerjs&id=${PEER_ID}&token=${session.body.signalToken}&version=1.5.5` },
    });
    assert.equal(replayToken.status, 401);

    const challenge2 = await json(base, '/v1/challenge', { deviceId, peerId: PEER_ID });
    const signature2 = await sign(pair.privateKey, challenge2.body.challengeText);
    const session2 = await json(base, '/v1/session', { deviceId, peerId: PEER_ID, challengeId: challenge2.body.challengeId, signature: signature2 });
    const wrongPath = await fetch(`${base}/internal/verify-signal`, {
      headers: { 'x-forwarded-uri': `/peerjs/peerjsEvil?key=peerjs&id=${PEER_ID}&token=${session2.body.signalToken}` },
    });
    assert.equal(wrongPath.status, 400);
    const concurrent = await Promise.all([
      fetch(`${base}/internal/verify-signal`, { headers: { 'x-forwarded-uri': `/peerjs/peerjs?key=peerjs&id=${PEER_ID}&token=${session2.body.signalToken}` } }),
      fetch(`${base}/internal/verify-signal`, { headers: { 'x-forwarded-uri': `/peerjs/peerjs?key=peerjs&id=${PEER_ID}&token=${session2.body.signalToken}` } }),
    ]);
    assert.deepEqual(concurrent.map((response) => response.status).sort(), [200, 401]);

    const revoked = await admin(base, '/internal/admin/devices/revoke', { deviceId });
    assert.equal(revoked.response.status, 200);
    assert.equal(revoked.body.revoked, true);
    const afterRevoke = await json(base, '/v1/challenge', { deviceId, peerId: PEER_ID });
    assert.equal(afterRevoke.response.status, 404);
    assert.equal(afterRevoke.body.error, 'device_not_found');
  } finally {
    await stop(app, dataDir);
  }
});

test('invalid signature is rejected and challenge cannot be retried', async () => {
  const { app, dataDir, base } = await start();
  try {
    const invite = await admin(base, '/internal/admin/invites');
    const registeredKey = await keyPair();
    const wrongKey = await keyPair();
    const registration = await json(base, '/v1/register', { invite: invite.body.inviteCode, peerId: PEER_ID, publicKey: registeredKey.spki });
    const deviceId = registration.body.deviceId;
    const challenge = await json(base, '/v1/challenge', { deviceId, peerId: PEER_ID });
    const badSignature = await sign(wrongKey.pair.privateKey, challenge.body.challengeText);
    const first = await json(base, '/v1/session', { deviceId, peerId: PEER_ID, challengeId: challenge.body.challengeId, signature: badSignature });
    assert.equal(first.response.status, 401);
    assert.equal(first.body.error, 'signature_invalid');
    const second = await json(base, '/v1/session', { deviceId, peerId: PEER_ID, challengeId: challenge.body.challengeId, signature: badSignature });
    assert.equal(second.body.error, 'challenge_expired');
  } finally {
    await stop(app, dataDir);
  }
});

test('exact-origin CORS, peer binding, admin auth, and rate limits are enforced', async () => {
  const { app, dataDir, base } = await start({ rateLimitMax: 2 });
  try {
    const preflight = await fetch(`${base}/v1/challenge`, { method: 'OPTIONS', headers: { origin: ORIGIN } });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('access-control-allow-origin'), ORIGIN);
    const badOrigin = await fetch(`${base}/v1/challenge`, { method: 'OPTIONS', headers: { origin: 'https://evil.example' } });
    assert.equal(badOrigin.status, 403);
    assert.equal((await fetch(`${base}/internal/admin/devices`)).status, 401);

    const one = await json(base, '/v1/challenge', { deviceId: 'missing_device_123', peerId: PEER_ID });
    const two = await json(base, '/v1/challenge', { deviceId: 'missing_device_123', peerId: PEER_ID });
    const three = await json(base, '/v1/challenge', { deviceId: 'missing_device_123', peerId: PEER_ID });
    assert.equal(one.response.status, 404);
    assert.equal(two.response.status, 404);
    assert.equal(three.response.status, 429);
  } finally {
    await stop(app, dataDir);
  }
});
