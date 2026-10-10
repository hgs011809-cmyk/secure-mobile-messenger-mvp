import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import webPush from 'web-push';
import { validateSubscription, createPushService, PUSH_PAYLOAD } from '../src/push.js';
import { createServer } from '../src/server.js';
import { Store } from '../src/store.js';

function subscription(endpoint = 'https://fcm.googleapis.com/send/test') {
  const ecdh = crypto.createECDH('prime256v1');
  return { endpoint, keys: { p256dh: ecdh.generateKeys().toString('base64url'), auth: crypto.randomBytes(16).toString('base64url') } };
}
const vapid = webPush.generateVAPIDKeys();
const config = { vapidPublicKey: vapid.publicKey, vapidPrivateKey: vapid.privateKey, vapidSubject: 'mailto:push@example.test', pushTimeoutMs: 25 };

test('strict endpoint allowlist and canonical valid P256/auth keys', () => {
  for (const host of ['fcm.googleapis.com', 'updates.push.services.mozilla.com']) assert.ok(validateSubscription(subscription(`https://${host}:443/send/test`)));
  for (const endpoint of ['http://fcm.googleapis.com/send/a', 'https://127.0.0.1/a', 'https://[::1]/a', 'https://fcm.googleapis.com.evil.test/a', 'https://evil.test/a', 'https://fcm.googleapis.com:444/a', 'https://user:pass@fcm.googleapis.com/a', 'https://user@fcm.googleapis.com/a', 'https://fcm.googleapis.com/a#x', 'https://fcm.googleapis.com/a#', 'https://fcm.googleapis.com./a', 'https://%66cm.googleapis.com/a', 'https://fcm.googleapis.com\\@evil.test/a', 'data:text/plain,a']) assert.throws(() => validateSubscription(subscription(endpoint)));
  for (const field of ['p256dh', 'auth']) {
    for (const value of ['', 'a', '!!!!', Buffer.alloc(field === 'auth' ? 15 : 64).toString('base64url')]) {
      const sub = subscription(); sub.keys[field] = value;
      assert.throws(() => validateSubscription(sub));
    }
  }
  const badPoint = subscription(); badPoint.keys.p256dh = Buffer.alloc(65, 4).toString('base64url');
  assert.throws(() => validateSubscription(badPoint));
  assert.throws(() => validateSubscription({}));
});

test('fixed payload, short TTL, bounded transport and safe provider errors', async () => {
  let call;
  const service = createPushService(config, async (...args) => { call = args; });
  assert.equal(await service.send(subscription()), 'sent');
  assert.equal(call[1], PUSH_PAYLOAD);
  assert.deepEqual(JSON.parse(call[1]), { title: 'New activity', body: 'Open the app to connect.' });
  assert.equal(call[2].TTL, 60); assert.equal(call[2].timeout, 25);
  for (const statusCode of [404, 410, 500]) assert.equal(await createPushService(config, async () => { throw { statusCode }; }).send(subscription()), statusCode === 500 ? 'failed' : 'gone');
  assert.equal(await createPushService(config, () => new Promise(() => {})).send(subscription()), 'failed');
  assert.equal(createPushService({}).enabled, false);
  assert.throws(() => createPushService({ ...config, vapidPrivateKey: 'bad' }), /Invalid VAPID/);
});

async function setup(t, overrides = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-push-'));
  const calls = [];
  const app = createServer({ ...config, dataDir: dir, adminSecret: 'admin', turnSecret: 'turn', allowedOrigin: 'https://app.test', signalHost: 'signal.test', stunUrls: ['stun:test'], turnUrls: ['turn:test'], rateLimitMax: 1000, pushSenderMax: 20, pushTargetMax: 20, pushTransport: async (...args) => { calls.push(args); }, ...overrides });
  const port = await app.listen(0);
  t.after(async () => { await app.close(); await fs.rm(dir, { recursive: true, force: true }); });
  const post = async (route, body, admin = false) => {
    const res = await fetch(`http://127.0.0.1:${port}${route}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(admin ? { 'x-admin-secret': 'admin' } : {}) }, body: JSON.stringify(body) });
    return { status: res.status, body: await res.json() };
  };
  async function user(n) {
    const peerId = 'dm-' + n.toString(16).padStart(30, '0');
    const pair = await crypto.webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const invite = await post('/internal/admin/invites', {}, true);
    const reg = await post('/v1/register', { invite: invite.body.inviteCode, peerId, publicKey: Buffer.from(await crypto.webcrypto.subtle.exportKey('spki', pair.publicKey)).toString('base64url') });
    assert.equal(reg.status, 201);
    const deviceId = reg.body.deviceId;
    const challenge = await post('/v1/challenge', { deviceId, peerId });
    const signature = Buffer.from(await crypto.webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(challenge.body.challengeText))).toString('base64url');
    const session = await post('/v1/session', { deviceId, peerId, challengeId: challenge.body.challengeId, signature });
    assert.equal(session.status, 200);
    return { deviceId, peerId, ...session.body };
  }
  return { app, post, user, calls, dir, port };
}

test('signed reusable push token isolated from signal; mutual pairing, persistence, pruning and revocation', async t => {
  const { app, post, user, calls } = await setup(t);
  const a = await user(1), b = await user(2), c = await user(3);
  assert.notEqual(a.signalToken, a.pushToken); assert.ok(a.pushExpiresAt > Date.now());
  assert.equal((await post('/v1/push/public-key', {})).body.publicKey, vapid.publicKey);
  for (const pushToken of [undefined, '', a.signalToken, 'invalid']) assert.equal((await post('/v1/push/subscribe', { pushToken, subscription: subscription() })).status, 401);
  assert.equal((await post('/v1/push/subscribe', { pushToken: b.pushToken, subscription: subscription('https://localhost/a') })).status, 400);
  const sub = subscription();
  assert.equal((await post('/v1/push/subscribe', { pushToken: b.pushToken, subscription: sub })).status, 200);
  const wake = () => post('/v1/push/wake', { pushToken: a.pushToken, targetPeerId: b.peerId, message: 'secret' });
  assert.equal((await wake()).status, 403);
  assert.equal((await post('/v1/push/pair', { pushToken: a.pushToken, targetPeerId: a.peerId })).status, 400);
  assert.equal((await post('/v1/push/pair', { pushToken: a.pushToken, targetPeerId: 'dm-' + 'f'.repeat(30) })).status, 403);
  await post('/v1/push/pair', { pushToken: a.pushToken, targetPeerId: b.peerId });
  assert.equal((await wake()).status, 403);
  await post('/v1/push/pair', { pushToken: b.pushToken, targetPeerId: a.peerId });
  assert.equal((await wake()).status, 202); assert.equal((await wake()).status, 202);
  assert.equal(calls.length, 2); assert.equal(calls[0][1], PUSH_PAYLOAD);
  const persisted = new Store(app.config.storeFile);
  assert.deepEqual((await persisted.pushTarget(a.deviceId, b.peerId)).subscription, sub);
  assert.equal((await post('/v1/push/wake', { pushToken: c.pushToken, targetPeerId: b.peerId })).status, 403);
  assert.equal((await post('/v1/push/unsubscribe', { pushToken: b.pushToken })).status, 200);
  assert.equal((await wake()).status, 202); assert.equal(calls.length, 2);
  await post('/v1/push/subscribe', { pushToken: b.pushToken, subscription: sub });
  await post('/internal/admin/devices/revoke', { deviceId: b.deviceId }, true);
  assert.equal((await post('/v1/push/unsubscribe', { pushToken: b.pushToken })).status, 401);
  assert.equal((await wake()).status, 403);
  assert.equal((await fs.readFile(app.config.storeFile, 'utf8')).includes(sub.endpoint), false);
  app._internals.pushTokens.delete(a.pushToken);
  assert.equal((await post('/v1/push/pair', { pushToken: a.pushToken, targetPeerId: c.peerId })).status, 401);
});

test('separate sender/target rate limits and expiry', async t => {
  const { app, post, user } = await setup(t, { pushSenderMax: 1, pushTargetMax: 1 });
  const a = await user(11), b = await user(12), c = await user(13);
  for (const x of [a,c]) {
    await post('/v1/push/pair', { pushToken: x.pushToken, targetPeerId: b.peerId });
    await post('/v1/push/pair', { pushToken: b.pushToken, targetPeerId: x.peerId });
  }
  const wake = x => post('/v1/push/wake', { pushToken: x.pushToken, targetPeerId: b.peerId });
  assert.equal((await wake(a)).status, 202);
  assert.equal((await wake(a)).status, 429);
  assert.equal((await wake(c)).status, 429);
  app._internals.pushTokens.set(a.pushToken, { deviceId: a.deviceId, peerId: a.peerId }, -1);
  assert.equal((await wake(a)).status, 401);
});

for (const statusCode of [404,410]) test(`provider ${statusCode} prunes persisted subscription`, async t => {
  const { app, post, user } = await setup(t, { pushTransport: async () => { throw { statusCode }; } });
  const a = await user(21), b = await user(22);
  await post('/v1/push/subscribe', { pushToken: b.pushToken, subscription: subscription() });
  await post('/v1/push/pair', { pushToken: a.pushToken, targetPeerId: b.peerId });
  await post('/v1/push/pair', { pushToken: b.pushToken, targetPeerId: a.peerId });
  assert.equal((await post('/v1/push/wake', { pushToken: a.pushToken, targetPeerId: b.peerId })).status, 202);
  assert.equal((await app.store.pushTarget(a.deviceId,b.peerId)).subscription, null);
});

test('missing VAPID leaves auth and metadata operational', async t => {
  const { post, user } = await setup(t, { vapidPublicKey: '', vapidPrivateKey: '', vapidSubject: '' });
  const a = await user(31);
  assert.deepEqual((await post('/v1/push/public-key', {})).body, { enabled: false, publicKey: null });
  assert.equal((await post('/v1/push/subscribe', { pushToken: a.pushToken, subscription: subscription() })).status, 503);
  assert.equal((await post('/v1/push/unsubscribe', { pushToken: a.pushToken })).status, 200);
});
