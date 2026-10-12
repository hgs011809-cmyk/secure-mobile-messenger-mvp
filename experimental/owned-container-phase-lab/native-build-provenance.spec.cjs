'use strict';

// Exactly 30 flat, synthetic-only tests. No real files, subprocesses or helpers.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { attestBuildProvenance, parseElf64Amd64Header, validateExpectedSourceSHA256,
  SOURCE_CAP, BINARY_CAP, MAX_READ_CALLS } = require('./native-build-provenance.cjs');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function elf(type = 2, length = 64) {
  const b = Buffer.alloc(length);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(b);
  b.writeUInt16LE(type, 16);
  b.writeUInt16LE(62, 18);
  b.writeUInt32LE(1, 20);
  return b;
}
function fixture(options = {}) {
  const source = { bytes: Buffer.from('int main(void) { return 0; }\n'), ...options.source };
  const binary = { bytes: elf(), ...options.binary };
  const files = { source, binary };
  const handles = new Map();
  const log = { opened: [], closed: [], reads: { source: 0, binary: 0 }, allocations: [] };
  let nextFD = 10;
  const io = {
    constants: { O_RDONLY: 0, O_NOFOLLOW: 0x20000, O_NONBLOCK: 0x800 },
    getuid: () => options.uid === undefined ? 1000 : options.uid,
    openSync(name, flags) {
      const f = files[name];
      assert.ok(f);
      if (f.openError) throw new Error('sensitive mocked open diagnostic');
      const fd = nextFD++;
      handles.set(fd, { name, f, offset: 0, stats: 0 });
      log.opened.push({ fd, name, flags });
      return fd;
    },
    fstatSync(fd, opts) {
      assert.deepEqual(opts, { bigint: true });
      const h = handles.get(fd);
      h.stats++;
      if (h.f.fstatErrorAt === h.stats) throw new Error('sensitive mocked stat diagnostic');
      const original = { dev: 1n, ino: BigInt(fd),
        mode: h.name === 'source' ? 0o100644n : 0o100700n,
        uid: 1000n, gid: 1000n, nlink: 1n, size: BigInt(h.f.bytes.length),
        mtimeNs: 123456789n, ctimeNs: 234567890n, ...h.f.stat };
      return h.stats > 1 ? { ...original, ...h.f.after } : original;
    },
    readSync(fd, buffer, offset, length, position) {
      const h = handles.get(fd);
      assert.equal(position, null);
      assert.equal(offset + length, buffer.length);
      log.allocations.push({ name: h.name, bytes: buffer.length });
      const call = ++log.reads[h.name];
      if (h.f.readErrorAt === call) throw new Error('sensitive mocked read diagnostic');
      if (Object.hasOwn(h.f, 'readResult')) {
        return typeof h.f.readResult === 'function' ? h.f.readResult(length, call) : h.f.readResult;
      }
      const count = Math.min(length, h.f.bytes.length - h.offset, h.f.chunk || Infinity);
      h.f.bytes.copy(buffer, offset, h.offset, h.offset + count);
      h.offset += count;
      return count;
    },
    closeSync(fd) {
      const h = handles.get(fd);
      assert.ok(h);
      log.closed.push(fd);
      handles.delete(fd);
      if (h.f.closeError) throw new Error('sensitive mocked close diagnostic');
    }
  };
  const input = { sourcePath: 'source', binaryPath: 'binary', expectedSourceSHA256: sha(source.bytes) };
  return { io, input, log, source, binary };
}
function closed(f) {
  assert.deepEqual(f.log.closed, f.log.opened.map(x => x.fd));
}
function rejected(f, input = f.input) {
  assert.throws(() => attestBuildProvenance(input, f.io), { message: 'build_provenance_failed' });
  closed(f);
}

 test('01 ET_EXEC attestation has exact immutable safe record', () => {
  const f = fixture();
  const r = attestBuildProvenance(f.input, f.io);
  assert.deepEqual(r, { version: 1, sourceSha256: sha(f.source.bytes), binarySha256: sha(f.binary.bytes),
    sourceBytes: f.source.bytes.length, binaryBytes: 64, sourceVerified: true,
    nativeHelperExecuted: false, trustedBuildBoundaryOnly: true });
  assert.ok(Object.isFrozen(r));
  assert.throws(() => { r.version = 2; }, TypeError);
  closed(f);
});
 test('02 ET_DYN and invalid UTF-8 source are hashed as bytes', () => {
  const f = fixture({ source: { bytes: Buffer.from([0xff, 0xfe, 0, 0xc0, 0x80]) }, binary: { bytes: elf(3) } });
  const r = attestBuildProvenance(f.input, f.io);
  assert.equal(r.sourceSha256, sha(f.source.bytes));
  assert.equal(r.sourceBytes, 5);
  assert.deepEqual(parseElf64Amd64Header(f.binary.bytes),
    { elfClass: 64, littleEndian: true, version: 1, type: 3, machine: 62 });
  assert.ok(Object.isFrozen(parseElf64Amd64Header(f.binary.bytes)));
  closed(f);
});
 test('03 expected hash is mandatory lowercase literal and input rejects unknowns', () => {
  for (const value of [undefined, null, '', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), 'a'.repeat(64) + '\n', 123]) {
    assert.throws(() => validateExpectedSourceSHA256(value));
    const f = fixture();
    rejected(f, { ...f.input, expectedSourceSHA256: value });
    assert.equal(f.log.opened.length, 0);
  }
  const missing = fixture();
  rejected(missing, { sourcePath: 'source', binaryPath: 'binary' });
  const unknown = fixture();
  rejected(unknown, { ...unknown.input, extra: true });
  for (const path of ['', null, 'source\0hidden']) {
    const f = fixture(); rejected(f, { ...f.input, sourcePath: path });
  }
});
 test('04 wrong source hash blocks binary open', () => {
  const f = fixture(); rejected(f, { ...f.input, expectedSourceSHA256: '0'.repeat(64) });
  assert.deepEqual(f.log.opened.map(x => x.name), ['source']);
});
 test('05 source cap is inclusive with cap plus one buffer', () => {
  const f = fixture({ source: { bytes: Buffer.alloc(SOURCE_CAP, 0x61) } });
  assert.equal(attestBuildProvenance(f.input, f.io).sourceBytes, 65536);
  assert.ok(f.log.allocations.filter(x => x.name === 'source').every(x => x.bytes === SOURCE_CAP + 1));
  closed(f);
});
 test('06 source cap overflow rejects before read', () => {
  const f = fixture({ source: { stat: { size: BigInt(SOURCE_CAP + 1) } } });
  rejected(f); assert.equal(f.log.reads.source, 0);
});
 test('07 binary cap is inclusive with cap plus one buffer', () => {
  const f = fixture({ binary: { bytes: elf(2, BINARY_CAP) } });
  assert.equal(attestBuildProvenance(f.input, f.io).binaryBytes, 4194304);
  assert.ok(f.log.allocations.filter(x => x.name === 'binary').every(x => x.bytes === BINARY_CAP + 1));
  closed(f);
});
 test('08 binary cap overflow rejects before binary read', () => {
  const f = fixture({ binary: { stat: { size: BigInt(BINARY_CAP + 1) } } });
  rejected(f); assert.equal(f.log.reads.binary, 0);
});
 test('09 exact source and binary permissions reject extra permission and special bits', () => {
  for (const name of ['source', 'binary']) for (const mode of [0o100600n, 0o100755n, 0o104644n, 0o102700n]) {
    rejected(fixture({ [name]: { stat: { mode } } }));
  }
});
 test('10 current owner required and unknown current UID blocks', () => {
  for (const name of ['source', 'binary']) rejected(fixture({ [name]: { stat: { uid: 1001n } } }));
  for (const uid of [null, -1, NaN, 1.5, 0x100000000]) {
    const f = fixture({ uid }); rejected(f); assert.equal(f.log.opened.length, 0);
  }
});
 test('11 exactly one link required for both files', () => {
  for (const name of ['source', 'binary']) for (const nlink of [0n, 2n, 99n]) {
    rejected(fixture({ [name]: { stat: { nlink } } }));
  }
});
 test('12 nonregular types including symlink directory FIFO and device reject', () => {
  for (const name of ['source', 'binary']) for (const type of [0o120000n, 0o040000n, 0o010000n, 0o020000n, 0o060000n, 0o140000n]) {
    rejected(fixture({ [name]: { stat: { mode: type | (name === 'source' ? 0o644n : 0o700n) } } }));
  }
});
 test('13 unknown negative and overflowing metadata fails closed', () => {
  for (const name of ['source', 'binary']) {
    for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs']) {
      for (const value of [undefined, null, 1, '1']) rejected(fixture({ [name]: { stat: { [key]: value } } }));
    }
    for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size']) {
      rejected(fixture({ [name]: { stat: { [key]: -1n } } }));
    }
    for (const key of ['mode', 'uid', 'gid']) rejected(fixture({ [name]: { stat: { [key]: 0x100000000n } } }));
    rejected(fixture({ [name]: { stat: { mode: name === 'source' ? 0o300644n : 0o300700n } } }));
  }
});
 test('14 every specified fstat identity field is stable across EOF', () => {
  const changes = { dev: 2n, ino: 999n, mode: 0o100600n, uid: 1001n, gid: 1001n, nlink: 2n,
    size: 65n, mtimeNs: 123456790n, ctimeNs: 234567891n };
  for (const name of ['source', 'binary']) for (const [key, value] of Object.entries(changes)) {
    rejected(fixture({ [name]: { after: { [key]: value } } }));
  }
});
 test('15 opens use required flags and missing unsupported flags block', () => {
  const f = fixture(); attestBuildProvenance(f.input, f.io); closed(f);
  assert.ok(f.log.opened.every(x => x.flags === (f.io.constants.O_NOFOLLOW | f.io.constants.O_NONBLOCK)));
  for (const constants of [{}, { O_RDONLY: 1, O_NOFOLLOW: 2, O_NONBLOCK: 4 },
    { O_RDONLY: 0, O_NOFOLLOW: 2, O_NONBLOCK: 2 },
    { O_RDONLY: 0, O_NOFOLLOW: 0, O_NONBLOCK: 4 },
    { O_RDONLY: 0, O_NOFOLLOW: 2 ** 40, O_NONBLOCK: 4 },
    { O_RDONLY: 0, O_NOFOLLOW: 3, O_NONBLOCK: 4 }]) {
    const bad = fixture(); bad.io.constants = constants; rejected(bad);
    assert.equal(bad.log.opened.length, 0);
  }
  const denied = fixture({ source: { openError: true } }); rejected(denied);
  const binaryDenied = fixture({ binary: { openError: true } }); rejected(binaryDenied);
});
 test('16 partial source reads accumulate exact bytes', () => {
  const f = fixture({ source: { chunk: 3 } });
  assert.equal(attestBuildProvenance(f.input, f.io).sourceSha256, sha(f.source.bytes));
  assert.ok(f.log.reads.source > 2); closed(f);
});
 test('17 partial binary reads accumulate exact bytes', () => {
  const f = fixture({ binary: { chunk: 4 } });
  assert.equal(attestBuildProvenance(f.input, f.io).binarySha256, sha(f.binary.bytes));
  assert.equal(f.log.reads.binary, 17); closed(f);
});
 test('18 EOF on the 32nd read is accepted', () => {
  const f = fixture({ source: { bytes: Buffer.alloc(31, 0x61), chunk: 1 } });
  attestBuildProvenance(f.input, f.io); assert.equal(f.log.reads.source, MAX_READ_CALLS); closed(f);
});
 test('19 no EOF within 32 reads rejects without a 33rd call', () => {
  for (const name of ['source', 'binary']) {
    const f = fixture({ [name]: { bytes: name === 'source' ? Buffer.alloc(32) : elf(), chunk: 1 } });
    rejected(f); assert.equal(f.log.reads[name], 32);
  }
});
 test('20 invalid read lengths fail closed', () => {
  for (const name of ['source', 'binary']) for (const result of [-1, NaN, Infinity, 0.5, undefined, null, '1', n => n + 1]) {
    rejected(fixture({ [name]: { readResult: result } }));
  }
});
 test('21 premature EOF rejects short contents', () => {
  for (const name of ['source', 'binary']) rejected(fixture({ [name]: { readResult: 0 } }));
});
 test('22 extra byte detects growth before hashing', () => {
  for (const name of ['source', 'binary']) {
    const f = fixture(); f[name].stat = { size: BigInt(f[name].bytes.length - 1) }; rejected(f);
  }
});
 test('23 descriptors close on stat read parser and close failures with suppressed diagnostics', () => {
  for (const name of ['source', 'binary']) for (const failure of [
    { fstatErrorAt: 1 }, { fstatErrorAt: 2 }, { readErrorAt: 1 }, { closeError: true }
  ]) rejected(fixture({ [name]: failure }));
  rejected(fixture({ binary: { bytes: Buffer.alloc(64) } }));
});
 test('24 invalid ELF magic rejects', () => {
  for (const offset of [0, 1, 2, 3]) {
    const bytes = elf(); bytes[offset] ^= 1;
    assert.throws(() => parseElf64Amd64Header(bytes)); rejected(fixture({ binary: { bytes } }));
  }
});
 test('25 ELF class must be 64 bit', () => {
  for (const value of [0, 1, 3, 255]) {
    const bytes = elf(); bytes[4] = value; rejected(fixture({ binary: { bytes } }));
  }
});
 test('26 ELF endian must be little endian', () => {
  for (const value of [0, 2, 255]) {
    const bytes = elf(); bytes[5] = value; rejected(fixture({ binary: { bytes } }));
  }
});
 test('27 both ELF version fields must be one', () => {
  for (const value of [0, 2, 255]) {
    const ident = elf(); ident[6] = value; rejected(fixture({ binary: { bytes: ident } }));
    const header = elf(); header.writeUInt32LE(value, 20); rejected(fixture({ binary: { bytes: header } }));
  }
});
 test('28 ELF type must be ET_EXEC or ET_DYN', () => {
  for (const type of [0, 1, 4, 0xffff]) rejected(fixture({ binary: { bytes: elf(type) } }));
});
 test('29 ELF machine must be amd64 62', () => {
  for (const machine of [0, 3, 40, 183, 0xffff]) {
    const bytes = elf(); bytes.writeUInt16LE(machine, 18); rejected(fixture({ binary: { bytes } }));
  }
});
 test('30 short ELF and nonbyte parser inputs reject; empty pinned source remains byte-valid', () => {
  for (const length of [0, 1, 16, 63]) {
    const bytes = elf().subarray(0, length);
    assert.throws(() => parseElf64Amd64Header(bytes)); rejected(fixture({ binary: { bytes } }));
  }
  for (const value of [undefined, null, {}, new Uint8Array(64), 'ELF']) {
    assert.throws(() => parseElf64Amd64Header(value));
  }
  const f = fixture({ source: { bytes: Buffer.alloc(0) } });
  assert.equal(attestBuildProvenance(f.input, f.io).sourceBytes, 0); closed(f);
});
