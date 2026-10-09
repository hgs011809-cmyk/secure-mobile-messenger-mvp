import fs from 'node:fs';
import crypto from 'node:crypto';
import tls from 'node:tls';

const API_BASE = process.env.API_BASE || 'https://api.thevault73.com';
const SIGNAL_HOST = process.env.SIGNAL_HOST || 'signal.thevault73.com';
const OUTPUT_DIR = process.env.OUTPUT_DIR || '/tmp';
const mode = process.argv[2] || 'auth';

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

async function post(path, body) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }
  return { response, data };
}

function websocketHandshake(host, requestPath) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: true });
    let response = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('WebSocket handshake timed out'));
    }, 8000);

    socket.once('secureConnect', () => {
      const key = crypto.randomBytes(16).toString('base64');
      socket.write([
        `GET ${requestPath} HTTP/1.1`,
        `Host: ${host}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Key: ${key}`,
        'Sec-WebSocket-Version: 13',
        'Origin: https://hgs011809-cmyk.github.io',
        '',
        '',
      ].join('\r\n'));
    });

    socket.on('data', (chunk) => {
      response += chunk.toString('latin1');
      if (!response.includes('\r\n\r\n')) return;
      clearTimeout(timer);
      socket.destroy();
      const statusLine = response.split('\r\n', 1)[0];
      const match = statusLine.match(/^HTTP\/1\.1\s+(\d{3})/);
      if (!match) reject(new Error(`Unexpected WebSocket response: ${statusLine}`));
      else resolve(Number(match[1]));
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function runAuthSmoke() {
  const invite = JSON.parse(fs.readFileSync(`${OUTPUT_DIR}/invite.json`, 'utf8')).inviteCode;
  expect(invite, 'Invite creation did not return inviteCode');

  const keyPair = await crypto.webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const publicKey = Buffer.from(
    await crypto.webcrypto.subtle.exportKey('spki', keyPair.publicKey),
  ).toString('base64url');
  const peerId = `dm-${crypto.randomBytes(15).toString('hex')}`;

  const registration = await post('/v1/register', { invite, peerId, publicKey });
  expect(registration.response.status === 201, `Registration failed: ${registration.response.status} ${JSON.stringify(registration.data)}`);
  const deviceId = registration.data.deviceId;
  expect(deviceId, 'Registration response omitted deviceId');

  const reused = await post('/v1/register', {
    invite,
    peerId: `dm-${crypto.randomBytes(15).toString('hex')}`,
    publicKey,
  });
  expect(reused.response.status === 400 && reused.data.error === 'invite_invalid', 'Invite reuse was not rejected');

  const challenge = await post('/v1/challenge', { deviceId, peerId });
  expect(challenge.response.status === 200, `Challenge failed: ${challenge.response.status} ${JSON.stringify(challenge.data)}`);
  const signature = Buffer.from(
    await crypto.webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      new TextEncoder().encode(challenge.data.challengeText),
    ),
  ).toString('base64url');
  const sessionBody = {
    deviceId,
    peerId,
    challengeId: challenge.data.challengeId,
    signature,
  };
  const session = await post('/v1/session', sessionBody);
  expect(session.response.status === 200, `Session failed: ${session.response.status} ${JSON.stringify(session.data)}`);

  const challengeReplay = await post('/v1/session', sessionBody);
  expect(challengeReplay.response.status === 401 && challengeReplay.data.error === 'challenge_expired', 'Challenge replay was not rejected');

  const turn = session.data.iceServers?.find((entry) => entry.username && entry.credential);
  expect(turn?.username && turn?.credential, 'Session omitted TURN credentials');
  expect(session.data.signalToken, 'Session omitted signaling token');

  const signalPath = `${String(session.data.signaling?.path || '/peerjs').replace(/\/$/, '')}/peerjs`;
  const query = new URLSearchParams({ key: 'peerjs', id: peerId, token: session.data.signalToken });
  const requestPath = `${signalPath}?${query}`;
  const firstStatus = await websocketHandshake(SIGNAL_HOST, requestPath);
  expect(firstStatus === 101, `Authenticated WebSocket handshake returned ${firstStatus}`);
  const replayStatus = await websocketHandshake(SIGNAL_HOST, requestPath);
  expect(replayStatus === 401, `Signaling token replay returned ${replayStatus}, expected 401`);

  fs.writeFileSync(`${OUTPUT_DIR}/turn-user`, turn.username, { mode: 0o600 });
  fs.writeFileSync(`${OUTPUT_DIR}/turn-pass`, turn.credential, { mode: 0o600 });
  fs.writeFileSync(`${OUTPUT_DIR}/device-id`, deviceId, { mode: 0o600 });
  fs.writeFileSync(`${OUTPUT_DIR}/peer-id`, peerId, { mode: 0o600 });
  console.log('Authenticated API, invite replay, challenge replay, and WSS token replay checks passed.');
}

async function runRevocationSmoke() {
  const deviceId = fs.readFileSync(`${OUTPUT_DIR}/device-id`, 'utf8').trim();
  const peerId = fs.readFileSync(`${OUTPUT_DIR}/peer-id`, 'utf8').trim();
  const challenge = await post('/v1/challenge', { deviceId, peerId });
  expect(challenge.response.status === 404 && challenge.data.error === 'device_not_found', 'Revoked device was still accepted');
  console.log('Device revocation check passed.');
}

if (mode === 'auth') await runAuthSmoke();
else if (mode === 'revoked') await runRevocationSmoke();
else throw new Error(`Unknown smoke-test mode: ${mode}`);
