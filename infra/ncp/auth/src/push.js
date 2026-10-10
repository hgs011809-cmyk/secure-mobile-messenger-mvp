import webPush from 'web-push';
import crypto from 'node:crypto';

const HOSTS = new Set(['fcm.googleapis.com', 'updates.push.services.mozilla.com']);
export const PUSH_PAYLOAD = JSON.stringify({ title: 'New activity', body: 'Open the app to connect.' });
function key(value, size) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid_subscription');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== size || bytes.toString('base64url') !== value) throw new Error('invalid_subscription');
  return bytes;
}
export function validateSubscription(value) {
  if (!value || typeof value.endpoint !== 'string' || value.endpoint.length > 4096) throw new Error('invalid_subscription');
  const url = new URL(value.endpoint);
  if (url.protocol !== 'https:' || !HOSTS.has(url.hostname) || url.port || url.username || url.password || url.hash || value.endpoint.includes('#')) throw new Error('invalid_subscription');
  if (!/^https:\/\/(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com)(?::443)?\//.test(value.endpoint) || value.endpoint.includes('\\')) throw new Error('invalid_subscription');
  const publicKey = key(value.keys?.p256dh, 65);
  if (publicKey[0] !== 4) throw new Error('invalid_subscription');
  try { crypto.ECDH.convertKey(publicKey, 'prime256v1'); } catch { throw new Error('invalid_subscription'); }
  key(value.keys?.auth, 16);
  return { endpoint: url.href, keys: { p256dh: value.keys.p256dh, auth: value.keys.auth } };
}
export function createPushService(config, transport = (subscription, payload, options) => webPush.sendNotification(subscription, payload, options)) {
  const enabled = Boolean(config.vapidPublicKey && config.vapidPrivateKey && config.vapidSubject);
  if (enabled) {
    try { webPush.setVapidDetails(config.vapidSubject, config.vapidPublicKey, config.vapidPrivateKey); }
    catch { throw new Error('Invalid VAPID configuration'); }
  }
  return {
    enabled,
    async send(subscription) {
      let timer;
      try {
        await Promise.race([
          Promise.resolve().then(() => transport(validateSubscription(subscription), PUSH_PAYLOAD, {
            TTL: 60, urgency: 'normal', timeout: config.pushTimeoutMs,
            vapidDetails: { subject: config.vapidSubject, publicKey: config.vapidPublicKey, privateKey: config.vapidPrivateKey },
          })),
          new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('push_timeout')), config.pushTimeoutMs); }),
        ]);
        return 'sent';
      } catch (error) { return [404, 410].includes(error.statusCode) ? 'gone' : 'failed'; }
      finally { clearTimeout(timer); }
    },
  };
}
