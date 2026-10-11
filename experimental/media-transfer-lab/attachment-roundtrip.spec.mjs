// Five flat POSIX-only synthetic composition tests. No network or services.
// Descriptor/device/binding admission and trusted filesystem ancestors are fixture
// assumptions, NOT Matrix SDK/admission, Internet, Android or physical-erasure proof.
// Fresh standard-v2 crypto comes only from encryptStream; descriptors stay in RAM.
// At most 8 MiB ciphertext payload on disk: destructive handoff removes the source
// chunk before receiver persistence, and receiver chunk before decrypt spooling.
// Small filesystem metadata is additional; this is not an RSS or crash-safe handoff
// claim. Recreation is the receiver's supported same-files restart (no close API).
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
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'attachment-roundtrip-'));
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
    throw new Error('ROUNDTRIP_CASE_FAILED');
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
  await fs.unlink(p); // No plaintext fixture; avoid duplicate disk payload storage.
  check(await absent(p), 'source ciphertext handed off');
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
    await fs.unlink(f.r.file(i));
    check(await absent(f.r.file(i)), 'persisted ciphertext handed to verifier');
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

test('01 fresh v2 eight-MiB stream: durable restart, lost-ack retry, verified plaintext digest', POSIX, async () => {
  await fixture(8 * 1024 * 1024, async f => {
    const halfway = f.count / 2;
    for (let i = 0; i < halfway; i++) await deliver(f, i);
    // Last acceptance happened, but the simulated sender lost its acknowledgement.
    await restart(f, halfway);
    const retry = await send(f.r, await readBounded(f.r.file(halfway - 1)), halfway - 1);
    check(retry.accepted === true && retry.repeated === true, 'lost-ack retry idempotent');
    check((await f.r.resume()).totalBytes === halfway * CHUNK, 'retry did not duplicate data');
    for (let i = halfway; i < f.count; i++) await deliver(f, i);
    check((await f.r.finalize()).complete === true, 'complete receiver hash verified');
    const actual = createHash('sha256'); let bytes = 0;
    const out = await decrypt(f, persisted(f), async b => {
      check(b.length <= CHUNK, 'bounded plaintext callback'); actual.update(b); bytes += b.length;
    });
    check(out.bytes === f.total && bytes === f.total && out.maxPayload <= CHUNK &&
      f.r.maxPayloadBytes <= CHUNK, 'complete bounded roundtrip');
    check(timingSafeEqual(actual.digest(), f.expected), 'full plaintext digest comparison');
    await noSpool(f);
    check((await fs.readdir(f.sourceRoot)).length === 0, 'source files removed');
    check((await fs.readdir(f.r.dir)).every(n => n === 'manifest.json'), 'receiver chunks removed after handoff');
    check((await f.r.erase()).physicalErasure === false, 'no physical erasure claim');
    check(await absent(f.r.dir), 'receiver namespace removed');
  });
});

test('02 corrupted stored ciphertext rejects trusted hashes with zero plaintext', POSIX, async () => {
  await fixture(2 * CHUNK, async f => {
    await complete(f);
    const h = await fs.open(f.r.file(1), 'r+');
    try {
      const one = Buffer.alloc(1);
      check((await h.read(one, 0, 1, 0)).bytesRead === 1, 'corruption read');
      one[0] ^= 1; check((await h.write(one, 0, 1, 0)).bytesWritten === 1, 'corruption write');
      await h.sync();
    } finally { await h.close(); }
    await denied(f.r.finalize(), 'integrity_failed');
    let bytes = 0, calls = 0;
    await denied(decrypt(f, persisted(f), async b => { bytes += b.length; calls++; }), 'HASH_MISMATCH');
    check(bytes === 0 && calls === 0, 'no plaintext before trusted full hash');
    await noSpool(f);
  });
});

test('03 fresh binding revocation after ciphertext handoff prevents first plaintext', POSIX, async () => {
  await fixture(2 * CHUNK, async f => {
    await complete(f); let ended = false, bytes = 0, calls = 0;
    const source = persisted(f, async () => { ended = true; f.active = false; });
    await denied(decrypt(f, source, async b => { bytes += b.length; calls++; }), 'AUTHORIZATION_DENIED');
    check(ended && !f.active && bytes === 0 && calls === 0, 'fresh gate blocks completed decrypt and release');
    await noSpool(f);
  });
});

test('04 completed receiver tombstone survives reopening and blocks plaintext continuation', POSIX, async () => {
  await fixture(2 * CHUNK, async f => {
    await complete(f);
    const deletion = await f.r.erase();
    check(deletion.deleted === true && deletion.physicalErasure === false, 'exact local delete semantics');
    check(await absent(f.r.dir), 'completed ciphertext namespace removed');
    await privateMode(f.r.tomb, 0o600);
    f.r = new SyntheticReceiver(f.config);
    await denied(f.r.initialize(), 'deleted');
    await denied(f.r.resume(), 'deleted');
    await denied(f.r.finalize(), 'deleted');
    let calls = 0, bytes = 0;
    await denied(decrypt(f, persisted(f), async b => { calls++; bytes += b.length; }), 'SOURCE_FAILED');
    check(calls === 0 && bytes === 0 && await absent(f.r.dir), 'reopen cannot restore or release');
    await noSpool(f);
    check((await f.r.erase()).deleted === true, 'idempotent tombstoned local deletion');
  });
});

test('05 revocation during resumed chunk delivery blocks further persistence and release', POSIX, async () => {
  await fixture(4 * CHUNK, async f => {
    await deliver(f, 0); await deliver(f, 1);
    await restart(f, 2);
    await deliver(f, 2); // A real post-restart delivery succeeds before revocation.
    const before = (await fs.readdir(f.r.dir)).sort().join(',');
    const next = await readBounded(path.join(f.sourceRoot, 'cipher-3'));
    // accept's initial guard has two checks; revoke at its next pre-write gate.
    f.revokeAfterChecks = 3;
    await denied(send(f.r, next, 3), 'not_authorized');
    check(!f.active && f.revokeAfterChecks === 0, 'binding revoked inside resumed acceptance');
    check(await absent(f.r.file(3)) && await absent(f.r.file(3) + '.pending'), 'no further ciphertext persisted');
    check((await fs.readdir(f.r.dir)).sort().join(',') === before, 'existing durable files unchanged');
    await denied(f.r.resume(), 'not_authorized');
    await denied(f.r.finalize(), 'not_authorized');
    let bytes = 0, calls = 0;
    await denied(decrypt(f, persisted(f), async b => { bytes += b.length; calls++; }), 'AUTHORIZATION_DENIED');
    check(bytes === 0 && calls === 0, 'revoked resumed delivery cannot release plaintext');
    await noSpool(f);
  });
});
