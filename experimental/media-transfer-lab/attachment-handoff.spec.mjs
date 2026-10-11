// Exactly five flat POSIX-only SYNTHETIC preservation tests. No production change.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createHash, timingSafeEqual} from 'node:crypto';
import {encryptStream, decryptVerifiedStream} from './attachment-stream.mjs';
import {SyntheticReceiver, validateManifest} from './receiver.mjs';

const CHUNK = 256 * 1024;
const POSIX = {skip: process.platform === 'win32'};
const sha = b => createHash('sha256').update(b).digest('hex');
const check = (condition, label) => assert.ok(condition === true, label);
async function absent(p) {
  try { await fs.lstat(p); return false; }
  catch (e) { return e?.code === 'ENOENT'; }
}
async function denied(promise, code) {
  let matched = false;
  try { await promise; }
  catch (e) { matched = e?.code === code || e?.message === code; }
  check(matched, 'expected safe rejection code');
}
async function privateDirectory(p) {
  await fs.mkdir(p, {mode: 0o700});
  await fs.chmod(p, 0o700);
  await privateMode(p, 0o700, true);
}
async function privateMode(p, mode, directory = false) {
  const s = await fs.lstat(p);
  check(!s.isSymbolicLink() && (directory ? s.isDirectory() : s.isFile()) &&
    (s.mode & 0o7777) === mode && s.uid === process.getuid(), 'owner-private fixture');
}
// Independently attempt every cleanup even if another cleanup/assertion fails.
async function cleanup(f) {
  let good = true;
  for (const p of [f.sourceRoot, f.receiverRoot, f.decryptRoot]) {
    try { await fs.rm(p, {recursive: true, force: true}); }
    catch { good = false; }
    if (!await absent(p)) good = false;
  }
  try { await fs.rm(f.root, {recursive: true, force: true}); }
  catch { good = false; }
  if (!await absent(f.root)) good = false;
  check(good, 'all fixture files and namespaces removed');
}
async function fixture(total, run) {
  let f;
  try {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'attachment-handoff-'));
    f = {root, sourceRoot: path.join(root, 'source'),
      receiverRoot: path.join(root, 'receiver'), decryptRoot: path.join(root, 'decrypt'),
      total, count: total / CHUNK, active: true, r: null};
    await fs.chmod(root, 0o700);
    await privateMode(root, 0o700, true);
    for (const p of [f.sourceRoot, f.receiverRoot, f.decryptRoot]) await privateDirectory(p);
    const expected = createHash('sha256');
    async function* generate() {
      for (let index = 0; index < f.count; index++) {
        const b = Buffer.alloc(CHUNK);
        for (let i = 0; i < b.length; i++) b[i] = (index * 29 + i * 13 + 7) & 255;
        expected.update(b);
        try { yield b; } finally { b.fill(0); }
      }
    }
    let index = 0;
    const enc = await encryptStream({source: generate(), authorize: async () => f.active,
      maxBytes: total, chunkBytes: CHUNK, writeCiphertext: async b => {
        check(b.length === CHUNK, 'bounded ciphertext payload');
        const p = path.join(f.sourceRoot, 'cipher-' + index++);
        const h = await fs.open(p, 'wx', 0o600);
        try { await h.writeFile(b); await h.sync(); } finally { await h.close(); }
        await privateMode(p, 0o600);
      }});
    check(enc.bytes === total && index === f.count && enc.maxPayload <= CHUNK, 'stream generation complete');
    f.descriptor = enc.descriptor; // Never serialize this descriptor or its key.
    f.expected = expected.digest();
    f.manifest = validateManifest({version: 1, transferId: 'a'.repeat(32),
      bindingId: 'b'.repeat(64), totalBytes: total, chunkBytes: CHUNK,
      sha256: Buffer.from(enc.descriptor.hashes.sha256, 'base64').toString('hex'),
      expiresAt: 2000});
    check(Object.isFrozen(f.manifest), 'immutable trusted manifest');
    f.config = {root: f.receiverRoot, manifest: f.manifest,
      authorize: async binding => {
        // Optional fixture revocation is evaluated by the real receiver gate.
        if (f.revokeAfterChecks !== undefined && --f.revokeAfterChecks === 0) f.active = false;
        return f.active && binding === f.manifest.bindingId;
      },
      clock: () => 1000}; // Valid monotonic fixture time; no bypass of expiry checks.
    f.r = new SyntheticReceiver(f.config);
    await f.r.initialize();
    await privateMode(f.r.dir, 0o700, true);
    await privateMode(path.join(f.r.dir, 'manifest.json'), 0o600);
    await run(f);
  } catch {
    // Deliberately suppress raw filesystem/crypto errors, descriptors and bytes.
    throw new Error('HANDOFF_CASE_FAILED');
  } finally {
    if (f) await cleanup(f);
  }
}
async function readBounded(p) {
  await privateMode(p, 0o600);
  const h = await fs.open(p, 'r');
  try {
    check((await h.stat()).size === CHUNK, 'bounded stored ciphertext');
    const b = Buffer.alloc(CHUNK); let n = 0;
    while (n < b.length) {
      const r = await h.read(b, n, b.length - n, n);
      check(r.bytesRead > 0, 'complete bounded read'); n += r.bytesRead;
    }
    return b;
  } finally { await h.close(); }
}
function send(r, b, index) {
  return r.accept({index, offset: index * CHUNK, bytes: b, sha256: sha(b)});
}
async function deliver(f, index) {
  const p = path.join(f.sourceRoot, 'cipher-' + index);
  const b = await readBounded(p);
  const ack = await send(f.r, b, index);
  check(ack.accepted === true && ack.repeated === false, 'durable acceptance');
  await privateMode(f.r.file(index), 0o600);
}
async function restart(f, present) {
  // All serial operations have settled; discard old instance, reuse exact config/files.
  f.r = new SyntheticReceiver(f.config);
  await f.r.initialize();
  const state = await f.r.resume();
  check(state.totalBytes === present * CHUNK && state.present.length === present &&
    state.present.every((value, index) => value === index), 'same-files restart state');
}
async function complete(f) {
  for (let i = 0; i < f.count; i++) await deliver(f, i);
  const result = await f.r.finalize();
  check(result.complete === true && result.totalBytes === f.total, 'receiver trusted whole hash');
}
async function* persisted(f, onEnd = async () => {}) {
  // read() itself is NOT an authorization API: explicit guard boundaries surround
  // each read and handoff. decrypt's own fresh authorize gate remains mandatory.
  await f.r.resume();
  for (let i = 0; i < f.count; i++) {
    await f.r.guard();
    await privateMode(f.r.file(i), 0o600);
    const b = await f.r.read(i);
    await f.r.guard();
    check(b.length === CHUNK, 'bounded persisted ciphertext read');
    yield b;
  }
  await onEnd();
}
function decrypt(f, source, writePlaintext) {
  return decryptVerifiedStream({source, descriptor: f.descriptor,
    tempRoot: f.decryptRoot, maxBytes: f.total, chunkBytes: CHUNK,
    authorize: async () => f.active, writePlaintext});
}
async function noSpool(f) {
  check((await fs.readdir(f.decryptRoot)).length === 0, 'decrypt namespace removed');
}


const TOTAL = 8 * 1024 * 1024;
// This measures logical live ciphertext file bytes, not physical allocation/RSS.
async function live(f, ceiling = 3 * TOTAL) {
  let bytes = 0;
  async function walk(p) {
    for (const name of await fs.readdir(p)) {
      const q = path.join(p, name), st = await fs.lstat(q);
      check(!st.isSymbolicLink(), 'no fixture symlink');
      if (st.isDirectory()) { await privateMode(q, 0o700, true); await walk(q); }
      else {
        await privateMode(q, 0o600);
        if (/^cipher-\d+$|^chunk-\d+\.bin(?:\.pending)?$|^ciphertext$/.test(name)) bytes += st.size;
      }
    }
  }
  await walk(f.root);
  check(bytes <= ceiling && ceiling <= 64 * 1024 * 1024, 'logical live ciphertext bound');
  return bytes;
}
async function fingerprint(f, receiverCount) {
  const digests = [];
  for (let i = 0; i < f.count; i++) digests.push(sha(await readBounded(path.join(f.sourceRoot, 'cipher-' + i))));
  for (let i = 0; i < receiverCount; i++) digests.push(sha(await readBounded(f.r.file(i))));
  return digests.join(','); // RAM only, never logged or serialized.
}
async function retained(f, before, count) {
  check(await fingerprint(f, count) === before, 'prior ciphertext byte-intact');
  await live(f);
}
async function zeroRelease(f, source, code) {
  let calls = 0, bytes = 0;
  await denied(decrypt(f, source, async b => { calls++; bytes += b.length; }), code);
  check(calls === 0 && bytes === 0, 'zero plaintext callbacks');
  await noSpool(f);
}
// External trusted room descriptor/device/binding and trusted filesystem ancestors
// remain fixtures, not Matrix authentication. No protocol or module changes.
test('01 retained eight-MiB restart and sender lost-ack retry, full plaintext digest', POSIX, async () => {
  await fixture(TOTAL, async f => {
    const half = f.count / 2;
    for (let i = 0; i < half; i++) await deliver(f, i);
    const prior = await fingerprint(f, half);
    await restart(f, half);
    const retry = await send(f.r, await readBounded(path.join(f.sourceRoot, 'cipher-' + (half - 1))), half - 1);
    check(retry.accepted && retry.repeated, 'sender lost-ack idempotent retry');
    await retained(f, prior, half);
    for (let i = half; i < f.count; i++) await deliver(f, i);
    check((await f.r.finalize()).complete, 'trusted whole ciphertext hash');
    const before = await fingerprint(f, f.count);
    const actual = createHash('sha256'); let bytes = 0, peak = 0;
    const out = await decrypt(f, persisted(f), async b => {
      check(b.length <= CHUNK, 'bounded plaintext callback');
      peak = Math.max(peak, await live(f));
      actual.update(b); bytes += b.length;
    });
    check(peak === 3 * TOTAL && bytes === TOTAL && out.bytes === TOTAL &&
      out.maxPayload <= CHUNK && f.r.maxPayloadBytes <= CHUNK, 'three-copy logical bound');
    check(timingSafeEqual(actual.digest(), f.expected), 'full plaintext digest');
    await noSpool(f); await retained(f, before, f.count);
    // Conservatively keep both copies even after success; only explicit cleanup removes.
    check(await live(f) === 2 * TOTAL, 'both ciphertext copies retained after success');
  });
});
test('02 cached corruption releases zero plaintext and preserves sender ciphertext', POSIX, async () => {
  await fixture(TOTAL, async f => {
    await complete(f);
    const sender = await fingerprint(f, 0);
    const h = await fs.open(f.r.file(1), 'r+');
    try { const b = Buffer.alloc(1); await h.read(b,0,1,0); b[0] ^= 1; await h.write(b,0,1,0); await h.sync(); }
    finally { await h.close(); }
    const corrupted = await fingerprint(f, f.count);
    await denied(f.r.finalize(), 'integrity_failed');
    await zeroRelease(f, persisted(f), 'HASH_MISMATCH');
    await retained(f, sender, 0); await retained(f, corrupted, f.count);
    // Conflicting cached retry is NOT a repair API.
    await denied(send(f.r, await readBounded(path.join(f.sourceRoot, 'cipher-1')), 1), 'conflicting_retry');
    await retained(f, corrupted, f.count);
  });
});
test('03 post-spool fresh revocation releases zero plaintext with cached copies intact', POSIX, async () => {
  await fixture(TOTAL, async f => {
    await complete(f); const before = await fingerprint(f, f.count); let ended = false;
    const source = persisted(f, async () => {
      check(await live(f) === 3 * TOTAL, 'full quarantine exists before fresh denial');
      ended = true; f.active = false;
    });
    await zeroRelease(f, source, 'AUTHORIZATION_DENIED');
    check(ended && !f.active, 'post-spool revocation reached');
    await retained(f, before, f.count);
  });
});
test('04 explicit receiver delete tombstone blocks restore; source awaits explicit cleanup', POSIX, async () => {
  await fixture(TOTAL, async f => {
    await complete(f); const source = await fingerprint(f, 0);
    const deletion = await f.r.erase();
    check(deletion.deleted && deletion.physicalErasure === false && await absent(f.r.dir), 'explicit logical receiver deletion');
    await privateMode(f.r.tomb, 0o600);
    f.r = new SyntheticReceiver(f.config);
    await denied(f.r.initialize(), 'deleted'); await denied(f.r.resume(), 'deleted');
    await denied(f.r.finalize(), 'deleted');
    await zeroRelease(f, persisted(f), 'SOURCE_FAILED');
    await retained(f, source, 0);
    await denied(send(f.r, await readBounded(path.join(f.sourceRoot, 'cipher-0')), 0), 'deleted');
    check(await absent(f.r.dir), 'tombstone blocks restoration');
    // Explicit local sender cleanup, not implied remote deletion authority.
    await fs.rm(f.sourceRoot, {recursive:true});
    check(await absent(f.sourceRoot), 'source removed only by explicit cleanup');
    await privateDirectory(f.sourceRoot);
  });
});
test('05 resumed acceptance denial preserves prior copies and permits only supported retry', POSIX, async () => {
  await fixture(TOTAL, async f => {
    const half = f.count / 2;
    for (let i = 0; i < half; i++) await deliver(f, i);
    await restart(f, half);
    const before = await fingerprint(f, half);
    f.revokeAfterChecks = 3;
    await denied(send(f.r, await readBounded(path.join(f.sourceRoot, 'cipher-' + half)), half), 'not_authorized');
    check(!f.active && await absent(f.r.file(half)) && await absent(f.r.file(half)+'.pending'), 'pre-write authorization denial');
    await retained(f, before, half);
    await zeroRelease(f, persisted(f), 'AUTHORIZATION_DENIED');
    await retained(f, before, half);
    // Explicit fixture reauthorization, not automatic retry or actual auth policy.
    delete f.revokeAfterChecks; f.active = true;
    await restart(f, half);
    await deliver(f, half); // Existing accept permits retry of an absent chunk.
    await retained(f, before, half);
    for (let i = half + 1; i < f.count; i++) await deliver(f, i);
    check((await f.r.finalize()).complete, 'retry completed trusted ciphertext');
    const all = await fingerprint(f, f.count); const actual = createHash('sha256'); let bytes = 0;
    await decrypt(f, persisted(f), async b => { await live(f); actual.update(b); bytes += b.length; });
    check(bytes === TOTAL && timingSafeEqual(actual.digest(),f.expected), 'retry full digest');
    await retained(f, all, f.count); await noSpool(f);
    // Mid-write interruption/crash repair is not provided or claimed here.
  });
});
