import { createPushService, validateSubscription } from './push.js';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.js';
import { Store } from './store.js';
import {
  importP256PublicKey,
  verifyEcdsaSignature,
  fingerprintSpki,
  randomToken,
  turnCredentials,
  secretsEqual,
} from './crypto.js';
import { RateLimiter } from './rateLimit.js';
import { TtlMap } from './ttlMap.js';

const MAX_BODY_BYTES = 16 * 1024;
const DEVICE_ID_RE = /^[A-Za-z0-9_-]{12,128}$/;
const PEER_ID_RE = /^dm-[a-f0-9]{30}$/;

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) return reject(Object.assign(new Error('payload_too_large'), { status: 413 }));
      if (!chunks.length) return resolve({});
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(value && typeof value === 'object' && !Array.isArray(value) ? value : {});
      } catch {
        reject(Object.assign(new Error('invalid_json'), { status: 400 }));
      }
    });
    req.on('error', () => reject(Object.assign(new Error('request_error'), { status: 400 })));
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-content-type-options', 'nosniff');
  res.writeHead(status, { 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

function sendError(res, status, code) {
  sendJson(res, status, { error: code });
}

export function createServer(overrides = {}) {
  const config = loadConfig(overrides);
  const store = new Store(config.storeFile);
  const rateLimiter = new RateLimiter({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax });
  const challenges = new TtlMap();
  const signalTokens = new TtlMap();
  const pushTokens = new TtlMap();
  const pushService = createPushService(config, overrides.pushTransport);
  const senderLimiter = new RateLimiter({ windowMs: config.pushRateWindowMs, max: config.pushSenderMax });
  const targetLimiter = new RateLimiter({ windowMs: config.pushRateWindowMs, max: config.pushTargetMax });
  const cleanupInterval = setInterval(() => {
    rateLimiter.cleanup();
    challenges.cleanup();
    signalTokens.cleanup();
    pushTokens.cleanup();
    senderLimiter.cleanup();
    targetLimiter.cleanup();
  }, 30000);
  cleanupInterval.unref?.();

  function clientKey(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
    return req.socket?.remoteAddress || 'unknown';
  }

  function limited(req, scope, subject = '') {
    return !rateLimiter.check(`${scope}:${clientKey(req)}:${subject}`);
  }

  async function bodyOrError(req, res) {
    try {
      return await readJsonBody(req);
    } catch (error) {
      sendError(res, error.status || 400, error.status === 413 ? 'payload_too_large' : 'bad_request');
      return null;
    }
  }

  async function handleRegister(req, res) {
    if (limited(req, 'register')) return sendError(res, 429, 'rate_limited');
    const body = await bodyOrError(req, res);
    if (!body) return;
    const invite = String(body.invite || '').trim();
    const peerId = String(body.peerId || '');
    const publicKeySpkiB64 = String(body.publicKey || '');
    if (!invite || !PEER_ID_RE.test(peerId) || !publicKeySpkiB64) {
      return sendError(res, 400, 'invalid_payload');
    }
    try {
      await importP256PublicKey(publicKeySpkiB64);
    } catch {
      return sendError(res, 400, 'invalid_public_key');
    }
    const deviceId = randomToken(18);
    const record = {
      deviceId,
      peerId,
      publicKeySpkiB64,
      fingerprint: fingerprintSpki(publicKeySpkiB64),
      createdAt: new Date().toISOString(),
    };
    const result = await store.registerDevice(invite, peerId, record);
    if (!result.ok) {
      return sendError(res, result.reason === 'peer_already_registered' ? 409 : 400, result.reason);
    }
    return sendJson(res, 201, { deviceId, peerId, createdAt: record.createdAt });
  }

  async function handleChallenge(req, res) {
    const body = await bodyOrError(req, res);
    if (!body) return;
    const deviceId = String(body.deviceId || '');
    const peerId = String(body.peerId || '');
    if (!DEVICE_ID_RE.test(deviceId) || !PEER_ID_RE.test(peerId)) {
      return sendError(res, 400, 'invalid_payload');
    }
    if (limited(req, 'challenge', deviceId)) return sendError(res, 429, 'rate_limited');
    const device = await store.getDevice(deviceId);
    if (!device) return sendError(res, 404, 'device_not_found');
    if (device.peerId !== peerId) return sendError(res, 403, 'peer_mismatch');

    const challengeId = randomToken(18);
    const nonce = randomToken(32);
    const expiresAt = Date.now() + config.challengeTtlSeconds * 1000;
    const challengeText = ['direct-auth-v1', challengeId, nonce, deviceId, peerId].join('\n');
    challenges.set(challengeId, { deviceId, peerId, challengeText }, config.challengeTtlSeconds * 1000);
    return sendJson(res, 200, { challengeId, challengeText, expiresAt });
  }

  async function handleSession(req, res) {
    const body = await bodyOrError(req, res);
    if (!body) return;
    const deviceId = String(body.deviceId || '');
    const peerId = String(body.peerId || '');
    const challengeId = String(body.challengeId || '');
    const signature = String(body.signature || '');
    if (!DEVICE_ID_RE.test(deviceId) || !PEER_ID_RE.test(peerId) || !challengeId || !signature) {
      return sendError(res, 400, 'invalid_payload');
    }
    if (limited(req, 'session', deviceId)) return sendError(res, 429, 'rate_limited');

    const challenge = challenges.get(challengeId);
    challenges.delete(challengeId);
    if (!challenge) return sendError(res, 401, 'challenge_expired');
    if (challenge.deviceId !== deviceId || challenge.peerId !== peerId) {
      return sendError(res, 403, 'peer_mismatch');
    }
    const device = await store.getDevice(deviceId);
    if (!device) return sendError(res, 404, 'device_not_found');
    if (device.peerId !== peerId) return sendError(res, 403, 'peer_mismatch');

    let verified = false;
    try {
      const publicKey = await importP256PublicKey(device.publicKeySpkiB64);
      verified = await verifyEcdsaSignature(publicKey, challenge.challengeText, signature);
    } catch {
      verified = false;
    }
    if (!verified) return sendError(res, 401, 'signature_invalid');

    const signalToken = randomToken(32);
    const signalTtlMs = config.signalTokenTtlSeconds * 1000;
    signalTokens.set(signalToken, { deviceId, peerId }, signalTtlMs);
    const pushToken = randomToken(32);
    const pushTtlMs = config.pushTokenTtlSeconds * 1000;
    pushTokens.set(pushToken, { deviceId, peerId }, pushTtlMs);
    const turn = turnCredentials(config.turnSecret, deviceId, config.turnTtlSeconds);
    const iceServers = [];
    if (config.stunUrls.length) iceServers.push({ urls: config.stunUrls });
    iceServers.push({ urls: config.turnUrls, username: turn.username, credential: turn.credential });

    return sendJson(res, 200, {
      signalToken,
      pushToken,
      pushExpiresAt: Date.now() + pushTtlMs,
      expiresAt: Date.now() + signalTtlMs,
      iceServers,
      turnExpiresAt: turn.expiry * 1000,
      signaling: {
        host: config.signalHost,
        port: config.signalPort,
        path: config.signalPath,
        secure: config.signalSecure,
      },
    });
  }

  async function handleVerifySignal(req, res) {
    const forwardedUri = req.headers['x-forwarded-uri'];
    if (typeof forwardedUri !== 'string' || !forwardedUri) return sendError(res, 400, 'missing_forwarded_uri');
    let url;
    try {
      url = new URL(forwardedUri, 'https://signal.invalid');
    } catch {
      return sendError(res, 400, 'invalid_forwarded_uri');
    }
    const peerSocketPath = `${config.signalPath.replace(/\/$/, '')}/peerjs`;
    if (url.pathname !== peerSocketPath && url.pathname !== `${peerSocketPath}/`) {
      return sendError(res, 400, 'invalid_forwarded_uri');
    }
    const peerId = url.searchParams.get('id') || '';
    const token = url.searchParams.get('token') || '';
    if (!PEER_ID_RE.test(peerId) || !token) return sendError(res, 401, 'invalid_token');
    if (limited(req, 'signal', peerId)) return sendError(res, 429, 'rate_limited');

    const entry = signalTokens.take(token);
    if (!entry) return sendError(res, 401, 'invalid_token');
    if (entry.peerId !== peerId) return sendError(res, 403, 'peer_mismatch');
    const device = await store.getDevice(entry.deviceId);
    if (!device || device.peerId !== peerId) return sendError(res, 403, 'device_revoked');
    res.writeHead(200, { 'content-length': 0, 'cache-control': 'no-store' });
    res.end();
  }

  async function handlePush(req, res, route) {
    if (route === 'public-key') return sendJson(res, 200, { enabled: pushService.enabled, publicKey: pushService.enabled ? config.vapidPublicKey : null });
    const body = await bodyOrError(req, res);
    if (!body) return;
    const entry = typeof body.pushToken === 'string' ? pushTokens.get(body.pushToken) : null;
    if (!entry) return sendError(res, 401, 'invalid_push_token');
    const device = await store.getDevice(entry.deviceId);
    if (!device || device.peerId !== entry.peerId) return sendError(res, 403, 'device_revoked');
    if (route !== 'wake' && !rateLimiter.check('push-control:' + entry.deviceId)) return sendError(res, 429, 'rate_limited');
    if (route === 'unsubscribe') {
      if (!await store.setPushSubscription(entry.deviceId, null)) return sendError(res, 403, 'device_revoked');
      return sendJson(res, 200, { ok: true });
    }
    if (route === 'subscribe') {
      let subscription;
      try { subscription = validateSubscription(body.subscription); }
      catch { return sendError(res, 400, 'invalid_subscription'); }
      if (!pushService.enabled) return sendError(res, 503, 'push_unavailable');
      if (!await store.setPushSubscription(entry.deviceId, subscription)) return sendError(res, 403, 'device_revoked');
      return sendJson(res, 200, { ok: true });
    }
    if (typeof body.targetPeerId !== 'string' || !PEER_ID_RE.test(body.targetPeerId) || body.targetPeerId === entry.peerId) return sendError(res, 400, 'invalid_target');
    if (route === 'pair') {
      if (!await store.pairPush(entry.deviceId, body.targetPeerId)) return sendError(res, 403, 'pair_not_allowed');
      return sendJson(res, 200, { ok: true });
    }
    const target = await store.pushTarget(entry.deviceId, body.targetPeerId);
    if (!target) return sendError(res, 403, 'pair_required');
    // Keys exclude IP and token: token refresh/IP rotation cannot bypass limits.
    if (!senderLimiter.check(entry.deviceId) || !targetLimiter.check(body.targetPeerId)) return sendError(res, 429, 'rate_limited');
    if (!pushService.enabled) return sendError(res, 503, 'push_unavailable');
    if (target.subscription) {
      const result = await pushService.send(target.subscription);
      if (result === 'gone') await store.prunePushSubscription(target.deviceId, target.subscription);
    }
    // Never expose subscription existence or provider errors to the caller.
    return sendJson(res, 202, { ok: true });
  }

  function requireAdmin(req, res) {
    const supplied = req.headers['x-admin-secret'];
    if (typeof supplied !== 'string' || !secretsEqual(supplied, config.adminSecret)) {
      sendError(res, 401, 'unauthorized');
      return false;
    }
    return true;
  }

  async function handleAdminCreateInvite(req, res) {
    if (!requireAdmin(req, res)) return;
    const body = await bodyOrError(req, res);
    if (!body) return;
    const ttlSeconds = Number(body.ttlSeconds || config.inviteTtlSeconds);
    if (!Number.isFinite(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 2592000) {
      return sendError(res, 400, 'invalid_ttl');
    }
    const format = body.format === undefined ? 'standard' : String(body.format);
    if (format !== 'standard' && format !== 'numeric') {
      return sendError(res, 400, 'invalid_invite_format');
    }
    const invite = await store.createInvite(ttlSeconds * 1000, { numeric: format === 'numeric' });
    return sendJson(res, 201, invite);
  }

  async function handleAdminListDevices(req, res) {
    if (!requireAdmin(req, res)) return;
    return sendJson(res, 200, { devices: await store.listDevices() });
  }

  async function handleAdminRevokeDevice(req, res) {
    if (!requireAdmin(req, res)) return;
    const body = await bodyOrError(req, res);
    if (!body) return;
    const deviceId = String(body.deviceId || '');
    if (!DEVICE_ID_RE.test(deviceId)) return sendError(res, 400, 'invalid_payload');
    const revoked = await store.revokeDevice(deviceId);
    for (const [token, wrapped] of signalTokens.entries()) {
      if (wrapped.value?.deviceId === deviceId) signalTokens.delete(token);
    }
    for (const [token, wrapped] of pushTokens.entries()) {
      if (wrapped.value?.deviceId === deviceId) pushTokens.delete(token);
    }
    return sendJson(res, 200, { deviceId, revoked });
  }

  async function handleRequest(req, res) {
    let url;
    try {
      url = new URL(req.url, 'http://internal.invalid');
    } catch {
      return sendError(res, 400, 'bad_request');
    }
    const { pathname } = url;
    const method = req.method || 'GET';

    if (method === 'GET' && pathname === '/healthz') return sendJson(res, 200, { status: 'ok' });

    if (pathname.startsWith('/v1/')) {
      const origin = req.headers.origin;
      if (method === 'OPTIONS') {
        if (origin !== config.allowedOrigin) return sendError(res, 403, 'origin_not_allowed');
        res.writeHead(204, {
          'access-control-allow-origin': config.allowedOrigin,
          'access-control-allow-methods': 'POST, OPTIONS',
          'access-control-allow-headers': 'content-type',
          'access-control-max-age': '600',
          'cache-control': 'no-store',
          vary: 'Origin',
        });
        return res.end();
      }
      if (origin && origin !== config.allowedOrigin) return sendError(res, 403, 'origin_not_allowed');
      if (origin) {
        res.setHeader('access-control-allow-origin', config.allowedOrigin);
        res.setHeader('vary', 'Origin');
      }
      if (method === 'POST' && ['public-key', 'subscribe', 'unsubscribe', 'pair', 'wake'].some(route => pathname === '/v1/push/' + route)) return handlePush(req, res, pathname.split('/').pop());
      if (method === 'POST' && pathname === '/v1/register') return handleRegister(req, res);
      if (method === 'POST' && pathname === '/v1/challenge') return handleChallenge(req, res);
      if (method === 'POST' && pathname === '/v1/session') return handleSession(req, res);
      return sendError(res, 404, 'not_found');
    }

    if (method === 'GET' && pathname === '/internal/verify-signal') return handleVerifySignal(req, res);
    if (method === 'POST' && pathname === '/internal/admin/invites') return handleAdminCreateInvite(req, res);
    if (method === 'GET' && pathname === '/internal/admin/devices') return handleAdminListDevices(req, res);
    if (method === 'POST' && pathname === '/internal/admin/devices/revoke') return handleAdminRevokeDevice(req, res);
    return sendError(res, 404, 'not_found');
  }

  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch(() => {
      if (!res.headersSent) sendError(res, 500, 'internal_error');
      else res.end();
    });
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 5000;

  function listen(port = config.port) {
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '0.0.0.0', () => resolve(server.address().port));
    });
  }

  function close() {
    clearInterval(cleanupInterval);
    return new Promise((resolve) => server.close(resolve));
  }

  return { server, config, store, listen, close, _internals: { challenges, signalTokens, pushTokens, rateLimiter, senderLimiter, targetLimiter } };
}

function isMainModule() {
  try {
    return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
  } catch {
    return false;
  }
}

if (isMainModule()) {
  const app = createServer();
  app.listen().then((port) => process.stdout.write(`auth service listening on port ${port}\n`)).catch((error) => {
    process.stderr.write(`failed to start auth service: ${error.message}\n`);
    process.exit(1);
  });
  const shutdown = async () => { await app.close(); process.exit(0); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}
