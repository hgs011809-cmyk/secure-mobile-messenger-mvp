import crypto from 'node:crypto';

const { subtle } = crypto.webcrypto;

export async function importP256PublicKey(spkiB64Url) {
  if (typeof spkiB64Url !== 'string' || spkiB64Url.length > 512) throw new Error('invalid_key');
  const der = Buffer.from(spkiB64Url, 'base64url');
  if (der.length < 64 || der.length > 256) throw new Error('invalid_key');
  return subtle.importKey('spki', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

export async function verifyEcdsaSignature(publicKey, message, signatureB64Url) {
  if (typeof signatureB64Url !== 'string' || signatureB64Url.length > 256) return false;
  const signature = Buffer.from(signatureB64Url, 'base64url');
  if (signature.length !== 64) return false;
  return subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signature,
    Buffer.from(message, 'utf8'),
  );
}

export function fingerprintSpki(spkiB64Url) {
  return crypto.createHash('sha256').update(Buffer.from(spkiB64Url, 'base64url')).digest('hex');
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function turnCredentials(secret, deviceId, ttlSeconds) {
  const expiry = Math.floor(Date.now() / 1000) + ttlSeconds;
  const username = `${expiry}:${deviceId}`;
  const credential = crypto.createHmac('sha1', secret).update(username).digest('base64');
  return { username, credential, ttl: ttlSeconds, expiry };
}

export function secretsEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}
