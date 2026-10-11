// Actual LOOPBACK TCP disconnect tests only, not real internet, Android, or
// Matrix-authenticated transfer. The fixture capability is not product admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createCipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { SyntheticReceiver } from './receiver.mjs';

const HOST = '127.0.0.1';
const CHUNK = 256 * 1024;
const TOTAL = 8 * 1024 * 1024;
const WAIT = 8000;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
async function bounded(promise) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('fixture_timeout')), WAIT); })]); }
  finally { clearTimeout(timer); }
}
async function absent(file) {
  try { await fs.lstat(file); return false; } catch (error) { return error.code === 'ENOENT'; }
}
function ciphertextFixture() {
  // One standard complete-file AES-256-CTR encryption, never chunk-specific crypto.
  // Key, IV, plaintext and capability stay in memory; only ciphertext is persisted.
  const key = randomBytes(32), iv = randomBytes(16), plain = Buffer.alloc(TOTAL);
  for (let i = 0; i < TOTAL; i++) plain[i] = i % 251;
  try {
    const cipher = createCipheriv('aes-256-ctr', key, iv);
    return Buffer.concat([cipher.update(plain), cipher.final()]);
  } finally { key.fill(0); iv.fill(0); plain.fill(0); }
}
function authorized(value, capability) {
  if (typeof value !== 'string' || value.length !== capability.length) return false;
  return timingSafeEqual(Buffer.from(value), Buffer.from(capability));
}
function readBody(req, f) {
  return new Promise(resolve => {
    let size = 0, buffered = 0, done = false;
    const parts = [];
    const finish = result => { if (!done) { done = true; parts.length = 0; resolve(result); } };
    req.on('data', bytes => {
      if (done) return;
      size += bytes.length;
      if (size > CHUNK) { finish({ status: 413 }); req.pause(); return; }
      parts.push(bytes); buffered += bytes.length;
      f.maxBuffered = Math.max(f.maxBuffered, buffered);
      if (f.partialGate && size >= CHUNK / 2) f.partialGate.resolve();
    });
    req.on('end', () => {
      if (!done) { const bytes = Buffer.concat(parts, size); finish({ status: 200, bytes }); }
    });
    req.on('aborted', () => { finish({ status: 0 }); f.abortedGate?.resolve(); });
    req.on('error', () => { finish({ status: 0 }); f.abortedGate?.resolve(); });
  });
}
function reply(res, status, values = {}) {
  if (res.destroyed) return;
  if(process.env.MEDIA_LAB_DIAGNOSTIC==='true')console.log('loopback_response_status='+status);
  try {
    res.writeHead(status, { 'content-type': 'application/json', connection: 'close' });
    res.end(JSON.stringify(values));
  } catch { res.destroy(); }
}
function trackClient(f, socket) {
  f.clients.add(socket);
  const closed = new Promise(resolve => socket.once('close', () => { f.clients.delete(socket); resolve(); }));
  f.clientClosures.add(closed);
  void closed.then(() => f.clientClosures.delete(closed));
}
async function start(f) {
  const sockets = new Set(), socketClosures=new Set(), jobs = new Set();
  const server = http.createServer({ maxHeaderSize: 4096 }, (req, res) => {
    const job = (async () => {
      if (!authorized(req.headers['x-fixture-authorization'], f.capability)) { reply(res, 401); return; }
      if (req.headers['x-synthetic-binding'] !== f.m.bindingId) { reply(res, 403); return; }
      const length = req.headers['content-length'];
      if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > CHUNK)) { reply(res, 413); return; }
      if ((req.url === '/resume' || req.url === '/finalize') &&
          (Number(length || 0) !== 0 || req.headers['transfer-encoding'])) { reply(res, 413); return; }
      if (req.method === 'GET' && req.url === '/resume') {
        const state = await f.r.resume(); reply(res, 200, { count: state.present.length, totalBytes: state.totalBytes }); return;
      }
      if (req.method === 'POST' && req.url === '/finalize') {
        const result = await f.r.finalize(); reply(res, 200, { complete: result.complete, totalBytes: result.totalBytes }); return;
      }
      const route = /^\/chunk\/(\d+)$/.exec(req.url || '');
      if (req.method !== 'PUT' || !route) { reply(res, 404); return; }
      const body = await readBody(req, f);
      if (body.status !== 200) { if (body.status) reply(res, body.status); return; }
      const index = Number(route[1]);
      const result = await f.r.accept({ index, offset: index * CHUNK, bytes: body.bytes, sha256: req.headers['x-chunk-sha256'] });
      if (f.dropAck === index) {
        f.dropAck = -1; f.acceptedGate?.resolve();
        // Destroy the accepted TCP connection BEFORE writing any HTTP ack.
        req.socket.destroy(); return;
      }
      reply(res, 200, { accepted: result.accepted, repeated: result.repeated });
    })().catch(error => { const safeCodes=['invalid_manifest','invalid_config','backpressure','expired','invalid_clock','not_authorized','unsafe_root','deleted','invalid_index','unsafe_transfer_dir','invalid_stored_chunk','manifest_changed','invalid_chunk','conflicting_retry','incomplete','integrity_failed']; f.lastError=safeCodes.includes(error?.message)?error.message:'fixture_operation_failed'; console.log('loopback_fixture_error='+f.lastError); reply(res, 403); });
    jobs.add(job); void job.finally(() => jobs.delete(job));
  });
  server.requestTimeout = WAIT; server.headersTimeout = WAIT;
  server.timeout = WAIT; server.keepAliveTimeout = 1;
  server.on('connection', socket => {
    sockets.add(socket);const closed=new Promise(resolve=>socket.once('close',()=>{sockets.delete(socket);resolve();}));socketClosures.add(closed);void closed.then(()=>socketClosures.delete(closed));
    socket.on('error', () => {}); socket.setTimeout(WAIT, () => socket.destroy());
  });
  server.on('clientError', (_error, socket) => socket.destroy());
  await bounded(new Promise((resolve, reject) => {
    server.once('error', () => reject(new Error('fixture_listener')));
    server.listen(0, HOST, resolve);
  }));
  const address = server.address();
  assert.equal(address.address, HOST); assert.equal(address.port > 0, true);
  f.port = address.port;
  f.stop = async () => {
    const closed = new Promise(resolve => server.close(resolve));
    for (const socket of sockets) socket.destroy();
    for (const socket of f.clients) socket.destroy();
    await bounded(closed); await bounded(Promise.all([...jobs]));
    // server.close callback is not proof that our socket close observers have fired.
    await bounded(Promise.all([...socketClosures]));await bounded(Promise.all([...f.clientClosures])); await bounded(f.r.tail);
    if(process.env.MEDIA_LAB_DIAGNOSTIC==='true')console.log('loopback_shutdown_counts='+sockets.size+','+f.clients.size+'; listening='+server.listening);
    assert.equal(server.listening, false); assert.equal(sockets.size, 0); assert.equal(f.clients.size, 0);
  };
}
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'synthetic-loopback-'));
  const bytes = ciphertextFixture();
  const f = { root, bytes, capability: randomBytes(32).toString('hex'), active: true, currentBinding: 'b'.repeat(64), maxBuffered: 0, dropAck: -1, clients: new Set(), clientClosures: new Set() };
  f.m = { version: 1, transferId: 'a'.repeat(32), bindingId: 'b'.repeat(64), totalBytes: TOTAL, chunkBytes: CHUNK, sha256: sha(bytes), expiresAt: 2000 };
  f.config = { root, manifest: f.m, authorize: async binding => f.active && binding === f.currentBinding, clock: () => 1000 };
  t.after(async () => {
    let clean = false,cleanupPhase='stop';
    try {
      if (f.stop) await f.stop();
      cleanupPhase='tail';await bounded(f.r?.tail || Promise.resolve());
      cleanupPhase='remove';await fs.rm(root, { recursive: true, force: true }); clean = await absent(root);
    } catch(error) { clean = false; if(process.env.MEDIA_LAB_DIAGNOSTIC==='true')console.log('loopback_cleanup_failed_phase='+cleanupPhase+'; error_code='+(typeof error?.code==='string'?error.code.replace(/[^A-Z_]/g,''):'fixed_failure')); }
    finally { bytes.fill(0); f.capability = ''; }
    assert.equal(clean, true, 'listener/socket shutdown and fixture absence');
  });
  await fs.chmod(root, 0o700);
  f.r = new SyntheticReceiver(f.config); await f.r.initialize(); await start(f);
  return f;
}
function request(f, { method = 'GET', route = '/resume', index = 0, body, auth = true, binding = f.m.bindingId, streaming = false } = {}) {
  const headers = { 'x-synthetic-binding': binding };
  if (auth) headers['x-fixture-authorization'] = f.capability;
  if (body) { headers['x-chunk-sha256'] = sha(body); if (!streaming) headers['content-length'] = body.length; }
  return bounded(new Promise(resolve => {
    let done = false;
    const finish = result => { if (!done) { done = true; resolve(result); } };
    const req = http.request({ host: HOST, port: f.port, method, path: route === '/chunk' ? '/chunk/' + index : route, headers, agent: false }, res => {
      let size = 0; const parts = [];
      res.on('data', b => { size += b.length; if (size > 1024) { res.destroy(); finish({ status: 0 }); } else parts.push(b); });
      res.on('end', () => { try { finish({ status: res.statusCode, ...JSON.parse(Buffer.concat(parts).toString('utf8')) }); } catch { finish({ status: 0 }); } });
      res.on('error', () => finish({ status: 0 })); res.on('aborted', () => finish({ status: 0 }));
    });
    req.on('socket', socket => trackClient(f, socket));
    req.on('error', () => finish({ status: 0 }));
    req.setTimeout(WAIT, () => { req.destroy(); finish({ status: 0 }); });
    if (body) req.write(body); req.end();
  }));
}
const upload = (f, index) => request(f, { method: 'PUT', route: '/chunk', index, body: f.bytes.subarray(index * CHUNK, (index + 1) * CHUNK) });
async function halfwayDisconnect(f, index) {
  f.partialGate = deferred(); f.abortedGate = deferred();
  const closed = deferred();
  const socket = net.createConnection({ host: HOST, port: f.port });
  trackClient(f, socket);
  socket.on('error', () => {}); socket.on('close', () => closed.resolve());
  socket.setTimeout(WAIT, () => socket.destroy());
  try {
    await bounded(new Promise(resolve => socket.once('connect', resolve)));
    const bytes = f.bytes.subarray(index * CHUNK, (index + 1) * CHUNK);
    const headers = ['PUT /chunk/' + index + ' HTTP/1.1', 'Host: 127.0.0.1', 'Connection: close', 'Content-Length: ' + CHUNK,
      'X-Fixture-Authorization: ' + f.capability, 'X-Synthetic-Binding: ' + f.m.bindingId, 'X-Chunk-Sha256: ' + sha(bytes), '', ''].join('\r\n');
    socket.write(headers); socket.write(bytes.subarray(0, CHUNK / 2));
    await bounded(f.partialGate.promise);
    // Server has observed half the advertised body, never a complete chunk.
    socket.destroy(); await bounded(closed.promise); await bounded(f.abortedGate.promise); await bounded(f.r.tail);
  } finally { socket.destroy(); f.partialGate = null; f.abortedGate = null; }
}
async function recreate(f) {
  await f.stop(); f.stop = null;
  f.r = new SyntheticReceiver(f.config); await f.r.initialize(); await start(f);
}
function check(name, fn) {
  test(name, { timeout: 60000, concurrency: false }, async t => {
    // Never expose raw transport/receiver errors, credentials or payloads.
    let passed = false;
    try { await fn(t); passed = true; } catch { passed = false; if(process.env.MEDIA_LAB_DIAGNOSTIC==='true')console.log('loopback_case_failed='+name); }
    assert.equal(passed, true, 'scalar loopback result');
  });
}

check('LOOPBACK TCP disconnect midway through body commits no chunk', async t => {
  const f = await fixture(t); await halfwayDisconnect(f, 0);
  const state = await request(f);
  assert.equal(state.status, 200); assert.equal(state.count, 0); assert.equal(state.totalBytes, 0);
  assert.equal(await absent(f.r.file(0)), true); assert.equal(await absent(f.r.file(0) + '.pending'), true);
});
check('LOOPBACK TCP disconnect after acceptance before ack retries idempotently', async t => {
  const f = await fixture(t); f.dropAck = 0; f.acceptedGate = deferred();
  assert.equal((await upload(f, 0)).status, 0); await bounded(f.acceptedGate.promise);
  assert.equal((await request(f)).count, 1);
  const retry = await upload(f, 0);
  assert.equal(retry.status, 200); assert.equal(retry.repeated, true); assert.equal((await request(f)).count, 1);
});
check('listener and receiver recreation resume only committed ciphertext chunks', async t => {
  const f = await fixture(t);
  for (let i = 0; i < 3; i++) assert.equal((await upload(f, i)).status, 200);
  await halfwayDisconnect(f, 3); await recreate(f);
  const state = await request(f);
  assert.equal(state.status, 200); assert.equal(state.count, 3); assert.equal(state.totalBytes, 3 * CHUNK);
  assert.equal((await upload(f, 3)).repeated, false); assert.equal((await request(f)).count, 4);
});
check('changed synthetic binding fails both wire binding and receiver authority', async t => {
  const f = await fixture(t); const body = f.bytes.subarray(0, CHUNK);
  assert.equal((await request(f, { method: 'PUT', route: '/chunk', body, binding: 'c'.repeat(64) })).status, 403);
  f.currentBinding = 'c'.repeat(64); assert.equal((await upload(f, 0)).status, 403);
  f.currentBinding = f.m.bindingId; assert.equal((await request(f)).count, 0);
});
check('revoked synthetic binding rejects upload resume and finalization', async t => {
  const f = await fixture(t);
  assert.equal((await upload(f, 0)).status, 200); f.active = false;
  assert.equal((await upload(f, 1)).status, 403); assert.equal((await request(f)).status, 403);
  assert.equal((await request(f, { method: 'POST', route: '/finalize' })).status, 403);
  f.active = true; assert.equal((await request(f)).count, 1);
});
check('missing memory-only fixture authorization header rejected before persistence', async t => {
  const f = await fixture(t);
  assert.equal((await request(f, { method: 'PUT', route: '/chunk', body: f.bytes.subarray(0, CHUNK), auth: false })).status, 401);
  assert.equal((await request(f, { auth: false })).status, 401);
  assert.equal((await request(f, { method: 'POST', route: '/finalize', auth: false })).status, 401);
  assert.equal((await request(f)).count, 0);
});
check('8 MiB trusted whole ciphertext SHA across multiple LOOPBACK TCP reconnects', async t => {
  const f = await fixture(t);
  for (let i = 0; i < TOTAL / CHUNK; i++) {
    if (i === 4 || i === 20) await halfwayDisconnect(f, i);
    if (i === 8 || i === 24) {
      f.dropAck = i; f.acceptedGate = deferred();
      assert.equal((await upload(f, i)).status, 0); await bounded(f.acceptedGate.promise);
      const retry = await upload(f, i); assert.equal(retry.status, 200); assert.equal(retry.repeated, true);
    } else assert.equal((await upload(f, i)).status, 200);
    if (i === 10 || i === 26) { await recreate(f); assert.equal((await request(f)).count, i + 1); }
  }
  const result = await request(f, { method: 'POST', route: '/finalize' });
  assert.equal(result.status, 200); assert.equal(result.complete, true); assert.equal(result.totalBytes, TOTAL);
  assert.equal((await request(f)).count, 32);
  // Independently hash persisted ciphertext, compare only a scalar boolean.
  const digest = createHash('sha256');
  for (let i = 0; i < 32; i++) digest.update(await fs.readFile(f.r.file(i)));
  assert.equal(digest.digest('hex') === f.m.sha256, true); assert.equal(f.r.maxPayloadBytes, CHUNK);
  // Same-length corruption cannot pass the trusted whole-file digest.
  const corrupt = Buffer.from(f.bytes.subarray(31 * CHUNK)); corrupt[0] ^= 1;
  await fs.writeFile(f.r.file(31), corrupt);
  assert.equal((await request(f, { method: 'POST', route: '/finalize' })).status, 403);
});
check('HTTP body bounded for advertised and streaming oversized requests', async t => {
  const f = await fixture(t), body = Buffer.alloc(CHUNK + 1, 7);
  assert.equal((await request(f, { method: 'PUT', route: '/chunk', body })).status, 413);
  assert.equal((await request(f, { method: 'PUT', route: '/chunk', body, streaming: true })).status, 413);
  assert.equal((await request(f)).count, 0); assert.equal(f.maxBuffered <= CHUNK, true);
  assert.equal(f.r.maxPayloadBytes, 0); assert.equal(await absent(f.r.file(0)), true);
});
