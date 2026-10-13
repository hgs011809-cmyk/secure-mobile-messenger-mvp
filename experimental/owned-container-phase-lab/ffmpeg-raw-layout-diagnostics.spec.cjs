'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {inspectRawZIPMetadata} = require('./ffmpeg-raw-zip-metadata.cjs');
const p = require('./ffmpeg-raw-layout-diagnostics.cjs');
let passed = 0;
function test(name, fn) { fn(); passed++; console.log('ok ' + name); }
// Manufactured stored ZIP headers only, deliberately bogus CRC observations.
// No actual vendor file, filesystem sink, network, child or decompression.
function fixture(names) {
  const locals = [], central = []; let off = 0;
  for (const name of names) {
    const directory = name.endsWith('/'), raw = Buffer.from(name), data = directory ? Buffer.alloc(0) : Buffer.from('x');
    const l = Buffer.alloc(30), c = Buffer.alloc(46), crc = directory ? 0 : 7;
    l.writeUInt32LE(0x04034b50); l.writeUInt16LE(20, 4); l.writeUInt32LE(crc, 14);
    l.writeUInt32LE(data.length, 18); l.writeUInt32LE(data.length, 22); l.writeUInt16LE(raw.length, 26);
    c.writeUInt32LE(0x02014b50); c.writeUInt16LE(0x0314, 4); c.writeUInt16LE(20, 6);
    c.writeUInt32LE(crc, 16); c.writeUInt32LE(data.length, 20); c.writeUInt32LE(data.length, 24);
    c.writeUInt16LE(raw.length, 28); c.writeUInt32LE((((directory ? 0x41ed : 0x81a4) * 65536) + (directory ? 16 : 0)) >>> 0, 38);
    c.writeUInt32LE(off, 42); locals.push(l, raw, data); central.push(c, raw); off += 30 + raw.length + data.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(names.length, 8); end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}
const inspect = names => p.inspectRawPathLayout(fixture(names));
const reject = bytes => assert.throws(() => p.inspectRawPathLayout(bytes), e => e.constructor === Error && e.message === p.ERROR);
function expected(names, counts) { const r = inspect(names); assert.deepEqual(r.counts, {file_ancestor: 0, ancestor_spelling_collision: 0, implicit_parent: 0, ...counts}); return r; }

test('original raw observations do not check file ancestors', () => {
  const b = fixture(['a', 'a/b']); assert.equal(inspectRawZIPMetadata(b).entryCount, 2);
  assert.equal(p.inspectRawPathLayout(b).counts.file_ancestor, 1);
});
test('flat manufactured vendor-style names: still no trust/admission', () => {
  const r = expected(['ffmpeg-linux', 'COPYING.LGPLv2.1'], {});
  for (const key of ['archiveAdmitted', 'fullOldPolicyAcceptanceEstablished', 'contentInflated', 'entriesMaterialized', 'payloadExecuted', 'vendorAuthenticated', 'buildOrSDKAdmitted']) assert.equal(r[key], false);
  assert.equal(r.metadata.entryCRCCheckedAgainstContent, false); assert.equal(r.sourceCandidateOnly, true);
});
for (const names of [['a/', 'a/x'], ['a/x', 'a/'], ['a/', 'a/b/', 'a/b/x'], ['a/b/x', 'a/b/', 'a/']])
  test('declared parents in either archive order ' + names.join(','), () => expected(names, {}));
for (const names of [['a', 'a/b'], ['a/b', 'a'], ['A', 'A/b'], ['A/b', 'A']])
  test('file ancestor in either order ' + names.join(','), () => expected(names, {file_ancestor: 1}));
test('multiple file ancestors', () => expected(['a', 'a/b', 'a/b/c'], {file_ancestor: 3}));
for (const names of [['A/', 'a/x'], ['a/x', 'A/'], ['a/', 'A/x'], ['A/x', 'a/']])
  test('explicit parent spelling collision ' + names.join(','), () => expected(names, {ancestor_spelling_collision: 1}));
test('implicit directory is an observation, not a new gate', () => expected(['a/x'], {implicit_parent: 1}));
test('two implicit ancestors', () => expected(['a/b/x'], {implicit_parent: 2}));
test('implicit siblings collide in parent spelling', () => expected(['a/x', 'A/y'], {implicit_parent: 2, ancestor_spelling_collision: 1}));
test('file ancestor and spelling collision both recorded', () => expected(['a', 'A/x'], {file_ancestor: 1, ancestor_spelling_collision: 1}));
test('similar prefix is not an ancestor', () => expected(['a', 'ab/x'], {implicit_parent: 1}));
test('separate declared roots', () => expected(['a/', 'ab/', 'a/x', 'ab/x'], {}));
test('deep implicit parents bounded', () => expected([Array.from({length:16}, (_,i) => 'd'+i).join('/')], {implicit_parent:15}));
test('512 flat entries bounded with no diagnostic explosion', () => { const r = expected(Array.from({length:512}, (_,i) => 'f'+i), {}); assert.equal(r.checkedEntries, 512); });
test('512 deep entries stay within count/issue bounds', () => {
  const roots = Array.from({length:15}, (_,i) => 'd'+i).join('/');
  const r = inspect(Array.from({length:512}, (_,i) => roots+'/f'+i));
  assert.equal(r.counts.implicit_parent, 512*15); assert.equal(r.issues.length, 512*15); assert(r.issues.length < r.maxIssues);
});
test('indices point into the inspected metadata only', () => { const r = inspect(['a', 'a/x']); const issue = r.issues.find(x => x.code === 'file_ancestor'); assert.deepEqual(issue, {code:'file_ancestor', entryIndex:1, relatedEntryIndex:0, prefixDepth:1}); });
test('implicit parent has no invented owner index', () => { const r = inspect(['a/x']); assert.equal(r.issues[0].relatedEntryIndex, null); });
test('original observations unchanged', () => { const b = fixture(['A/', 'a/x']); assert.deepEqual(p.inspectRawPathLayout(b).metadata, inspectRawZIPMetadata(b)); });
test('full metadata and diagnostics immutable', () => { const r = inspect(['a', 'a/x']); for (const x of [r, r.counts, r.issues, ...r.issues, r.metadata, r.metadata.entries, ...r.metadata.entries]) assert(Object.isFrozen(x)); assert.throws(() => { r.issues[0].code = 'safe'; }, TypeError); });
test('caller byte mutation cannot alter retained observations', () => { const b = fixture(['a', 'a/x']), r = p.inspectRawPathLayout(b), h = r.metadata.observedArchiveSha256; b.fill(0); assert.equal(r.counts.file_ancestor, 1); assert.equal(r.metadata.observedArchiveSha256, h); assert.notEqual(crypto.createHash('sha256').update(b).digest('hex'), h); });
test('decorated Buffer length cannot hide bytes', () => { const b = fixture(['a', 'a/x']); Object.defineProperty(b, 'length', {value:0}); assert.equal(p.inspectRawPathLayout(b).counts.file_ancestor, 1); });
test('proxy rejected without traps', () => { let touched=0; reject(new Proxy(fixture(['a']), {get(){touched++; throw Error('TRAP');}})); assert.equal(touched, 0); });
test('arbitrary metadata object rejected without getter access', () => { let touched=0; reject({get entries(){touched++; throw Error('TRAP');}}); assert.equal(touched, 0); });
test('shared memory rejected', () => reject(Buffer.from(new SharedArrayBuffer(32))));
for (const names of [['A', 'a'], ['a/', 'a'], ['a/../x'], ['a//x'], ['a\\x'], ['a', 'a']])
  test('upstream rejection retained ' + names.join(','), () => reject(fixture(names)));
test('513 entries rejected upstream', () => reject(fixture(Array.from({length:513}, (_,i) => 'f'+i))));
test('all truncations rejected upstream', () => { const b = fixture(['a/', 'a/x']); for (let n=0; n<b.length; n++) reject(b.subarray(0,n)); });
test('public constants frozen', () => { assert(Object.isFrozen(p) && Object.isFrozen(p.LIMITS) && Object.isFrozen(p.ISSUE_CODES)); assert.equal(p.LIMITS.maxIssues, 16384); });
console.log(JSON.stringify({kind:'raw_zip_layout_diagnostics_pure_spec',passed,failed:0,actualArchives:0,networkRequests:0,realChildren:0,decompression:false,filesystemSinkWrites:0,archiveAdmission:false}));
