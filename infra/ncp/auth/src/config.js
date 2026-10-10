import path from 'node:path';
import fs from 'node:fs';

function list(value) {
  return String(value || '').split(',').map((item) => item.trim()).filter(Boolean);
}

function secret(overrides, overrideName, envName, fileName) {
  if (overrides[overrideName] !== undefined) return overrides[overrideName];
  if (process.env[envName]) return process.env[envName];
  const filePath = process.env[fileName];
  if (!filePath) return '';
  return fs.readFileSync(filePath, 'utf8').trim();
}

export function loadConfig(overrides = {}) {
  const env = process.env;
  const turnHost = overrides.turnHost ?? env.TURN_HOST ?? '';
  const config = {
    port: Number(overrides.port ?? env.PORT ?? 8080),
    dataDir: overrides.dataDir ?? env.DATA_DIR ?? '/data',
    storeFile: overrides.storeFile,
    adminSecret: secret(overrides, 'adminSecret', 'ADMIN_SECRET', 'ADMIN_SECRET_FILE'),
    turnSecret: secret(overrides, 'turnSecret', 'TURN_SECRET', 'TURN_SECRET_FILE'),
    allowedOrigin: overrides.allowedOrigin ?? env.ALLOWED_ORIGIN ?? '',
    signalHost: overrides.signalHost ?? env.SIGNAL_HOST ?? '',
    signalPort: Number(overrides.signalPort ?? env.SIGNAL_PORT ?? 443),
    signalPath: overrides.signalPath ?? env.SIGNAL_PATH ?? '/peerjs',
    signalSecure: String(overrides.signalSecure ?? env.SIGNAL_SECURE ?? 'true') !== 'false',
    stunUrls: overrides.stunUrls ?? list(env.STUN_URLS || (turnHost ? `stun:${turnHost}:3478` : '')),
    turnUrls: overrides.turnUrls ?? list(env.TURN_URLS || (turnHost ? `turn:${turnHost}:3478?transport=udp,turn:${turnHost}:3478?transport=tcp` : '')),
    turnTtlSeconds: Number(overrides.turnTtlSeconds ?? env.TURN_TTL_SECONDS ?? 600),
    challengeTtlSeconds: Number(overrides.challengeTtlSeconds ?? env.CHALLENGE_TTL_SECONDS ?? 120),
    signalTokenTtlSeconds: Number(overrides.signalTokenTtlSeconds ?? env.SIGNAL_TOKEN_TTL_SECONDS ?? 120),
    vapidPublicKey: secret(overrides, 'vapidPublicKey', 'VAPID_PUBLIC_KEY', 'VAPID_PUBLIC_KEY_FILE'),
    vapidPrivateKey: secret(overrides, 'vapidPrivateKey', 'VAPID_PRIVATE_KEY', 'VAPID_PRIVATE_KEY_FILE'),
    vapidSubject: secret(overrides, 'vapidSubject', 'VAPID_SUBJECT', 'VAPID_SUBJECT_FILE'),
    pushTokenTtlSeconds: Number(overrides.pushTokenTtlSeconds ?? env.PUSH_TOKEN_TTL_SECONDS ?? 300),
    pushTimeoutMs: Number(overrides.pushTimeoutMs ?? env.PUSH_TIMEOUT_MS ?? 5000),
    pushRateWindowMs: Number(overrides.pushRateWindowMs ?? env.PUSH_RATE_WINDOW_MS ?? 60000),
    pushSenderMax: Number(overrides.pushSenderMax ?? env.PUSH_SENDER_MAX ?? 5),
    pushTargetMax: Number(overrides.pushTargetMax ?? env.PUSH_TARGET_MAX ?? 10),
    inviteTtlSeconds: Number(overrides.inviteTtlSeconds ?? env.INVITE_TTL_SECONDS ?? 604800),
    rateLimitWindowMs: Number(overrides.rateLimitWindowMs ?? env.RATE_LIMIT_WINDOW_MS ?? 60000),
    rateLimitMax: Number(overrides.rateLimitMax ?? env.RATE_LIMIT_MAX ?? 30),
  };
  for (const [name, max] of [['pushTokenTtlSeconds', 900], ['pushTimeoutMs', 10000], ['pushRateWindowMs', 3600000], ['pushSenderMax', 100], ['pushTargetMax', 100]]) {
    if (!Number.isInteger(config[name]) || config[name] < 1 || config[name] > max) throw new Error('Invalid push configuration');
  }
  config.storeFile ||= path.join(config.dataDir, 'store.json');

  const missing = [];
  if (!config.adminSecret) missing.push('ADMIN_SECRET_FILE');
  if (!config.turnSecret) missing.push('TURN_SECRET_FILE');
  if (!config.allowedOrigin) missing.push('ALLOWED_ORIGIN');
  if (!config.signalHost) missing.push('SIGNAL_HOST');
  if (!config.stunUrls.length) missing.push('STUN_URLS or TURN_HOST');
  if (!config.turnUrls.length) missing.push('TURN_URLS or TURN_HOST');
  if (missing.length) throw new Error(`Missing required configuration: ${missing.join(', ')}`);
  return config;
}
