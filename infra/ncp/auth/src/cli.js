#!/usr/bin/env node
import fs from 'node:fs';

const baseUrl = process.env.AUTH_BASE_URL || 'http://127.0.0.1:8080';
const adminSecret = process.env.ADMIN_SECRET || (process.env.ADMIN_SECRET_FILE ? fs.readFileSync(process.env.ADMIN_SECRET_FILE, 'utf8').trim() : '');

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

async function request(path, method, body) {
  if (!adminSecret) fail('ADMIN_SECRET_FILE or ADMIN_SECRET is required');
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-admin-secret': adminSecret },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) fail(`Request failed (${response.status}): ${data.error || 'unknown_error'}`);
  return data;
}

function usage() {
  process.stderr.write([
    'Usage:',
    '  node src/cli.js create-invite [ttlSeconds] [standard|numeric]',
    '  node src/cli.js list-devices',
    '  node src/cli.js revoke-device <deviceId>',
  ].join('\n') + '\n');
}

const [command, argument, format] = process.argv.slice(2);
if (command === 'create-invite') {
  const ttlSeconds = argument ? Number(argument) : undefined;
  const body = {};
  if (ttlSeconds) body.ttlSeconds = ttlSeconds;
  if (format) body.format = format;
  console.log(JSON.stringify(await request('/internal/admin/invites', 'POST', body), null, 2));
} else if (command === 'list-devices') {
  console.log(JSON.stringify(await request('/internal/admin/devices', 'GET'), null, 2));
} else if (command === 'revoke-device') {
  if (!argument) { usage(); process.exit(1); }
  console.log(JSON.stringify(await request('/internal/admin/devices/revoke', 'POST', { deviceId: argument }), null, 2));
} else {
  usage();
  process.exit(command ? 1 : 0);
}
