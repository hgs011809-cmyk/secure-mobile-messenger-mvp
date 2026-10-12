'use strict';

// Build-boundary evidence only: never authenticates or executes a helper.
// The trusted parent must check compiler success and supply a reviewed literal pin.
const fs = require('node:fs');
const crypto = require('node:crypto');
const SOURCE_CAP = 64 * 1024;
const BINARY_CAP = 4 * 1024 * 1024;
const MAX_READ_CALLS = 32; // Per file, including the mandatory EOF read.
const FIELDS = Object.freeze(['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs']);
const FAILURE = 'build_provenance=failed/raw_diagnostics_suppressed=true';

function fail() { throw new Error('build_provenance_failed'); }
function validateExpectedSourceSHA256(value) {
  if (typeof value !== 'string' || value.length !== 64 || !/^[0-9a-f]{64}$/.test(value)) fail();
  return value;
}
function parseElf64Amd64Header(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 64) fail();
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46 ||
      bytes[4] !== 2 || bytes[5] !== 1 || bytes[6] !== 1 ||
      ![2, 3].includes(bytes.readUInt16LE(16)) || bytes.readUInt16LE(18) !== 62 ||
      bytes.readUInt32LE(20) !== 1) fail();
  return Object.freeze({ elfClass: 64, littleEndian: true, version: 1,
    type: bytes.readUInt16LE(16), machine: 62 });
}
function copyStat(raw, uid, mode, cap) {
  if (!raw || typeof raw !== 'object') fail();
  const value = {};
  for (const key of FIELDS) {
    if (typeof raw[key] !== 'bigint') fail();
    value[key] = raw[key];
  }
  for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size']) {
    if (value[key] < 0n) fail();
  }
  if (value.mode > 0o177777n || value.uid > 0xffffffffn || value.gid > 0xffffffffn ||
      (value.mode & 0o170000n) !== 0o100000n ||
      (value.mode & 0o7777n) !== BigInt(mode) || value.uid !== BigInt(uid) ||
      value.nlink !== 1n || value.size > BigInt(cap)) fail();
  return Object.freeze(value);
}
function readOwnedStable(path, mode, cap, io, uid) {
  const c = io.constants;
  if (!c || !Number.isInteger(c.O_RDONLY) || c.O_RDONLY !== 0 ||
      !Number.isInteger(c.O_NOFOLLOW) || c.O_NOFOLLOW <= 0 || c.O_NOFOLLOW > 0x7fffffff ||
      (c.O_NOFOLLOW & (c.O_NOFOLLOW - 1)) !== 0 ||
      !Number.isInteger(c.O_NONBLOCK) || c.O_NONBLOCK <= 0 || c.O_NONBLOCK > 0x7fffffff ||
      (c.O_NONBLOCK & (c.O_NONBLOCK - 1)) !== 0 ||
      (c.O_NOFOLLOW & c.O_NONBLOCK) !== 0) fail();
  let fd;
  try {
    fd = io.openSync(path, c.O_RDONLY | c.O_NOFOLLOW | c.O_NONBLOCK);
    if (!Number.isInteger(fd) || fd < 0) fail();
    const before = copyStat(io.fstatSync(fd, { bigint: true }), uid, mode, cap);
    const size = Number(before.size);
    const buffer = Buffer.alloc(size + 1); // Extra byte detects growth; never cap+2.
    let used = 0;
    let eof = false;
    for (let calls = 0; calls < MAX_READ_CALLS; calls++) {
      const remaining = buffer.length - used;
      const count = io.readSync(fd, buffer, used, remaining, null);
      if (!Number.isInteger(count) || count < 0 || count > remaining) fail();
      if (count === 0) { eof = true; break; }
      used += count;
      if (used > size) fail();
    }
    if (!eof || used !== size) fail();
    const after = copyStat(io.fstatSync(fd, { bigint: true }), uid, mode, cap);
    if (FIELDS.some(key => before[key] !== after[key])) fail();
    return buffer.subarray(0, size);
  } finally {
    if (Number.isInteger(fd) && fd >= 0) io.closeSync(fd);
  }
}
function attestBuildProvenance(input, injectedFS) {
  try {
    if (!input || typeof input !== 'object' || Array.isArray(input) ||
        Object.keys(input).sort().join(',') !== 'binaryPath,expectedSourceSHA256,sourcePath') fail();
    const expected = validateExpectedSourceSHA256(input.expectedSourceSHA256);
    for (const p of [input.sourcePath, input.binaryPath]) {
      if (typeof p !== 'string' || p.length === 0 || p.includes('\0')) fail();
    }
    // Injection is only for synthetic tests; the production CLI never supplies it.
    const io = injectedFS === undefined ? fs : injectedFS;
    const uid = injectedFS === undefined ?
      (typeof process.getuid === 'function' ? process.getuid() : undefined) : io.getuid();
    if (!Number.isInteger(uid) || uid < 0 || uid > 0xffffffff) fail();
    const source = readOwnedStable(input.sourcePath, 0o644, SOURCE_CAP, io, uid);
    const sourceSha256 = crypto.createHash('sha256').update(source).digest('hex');
    if (sourceSha256 !== expected) fail();
    const binary = readOwnedStable(input.binaryPath, 0o700, BINARY_CAP, io, uid);
    parseElf64Amd64Header(binary);
    // Binary hashing happens only after bounded stable reading and header checks.
    const binarySha256 = crypto.createHash('sha256').update(binary).digest('hex');
    return Object.freeze({ version: 1, sourceSha256, binarySha256,
      sourceBytes: source.length, binaryBytes: binary.length, sourceVerified: true,
      nativeHelperExecuted: false, trustedBuildBoundaryOnly: true });
  } catch (_) { fail(); } // Suppress raw filesystem diagnostics and paths.
}

module.exports = Object.freeze({ parseElf64Amd64Header, attestBuildProvenance,
  validateExpectedSourceSHA256, SOURCE_CAP, BINARY_CAP, MAX_READ_CALLS });

if (require.main === module) {
  try {
    if (process.argv.length !== 5) fail();
    const record = attestBuildProvenance({ sourcePath: process.argv[2],
      binaryPath: process.argv[3], expectedSourceSHA256: process.argv[4] });
    process.stdout.write(JSON.stringify(record) + '\n');
  } catch (_) {
    process.stderr.write(FAILURE + '\n');
    process.exitCode = 1;
  }
}
