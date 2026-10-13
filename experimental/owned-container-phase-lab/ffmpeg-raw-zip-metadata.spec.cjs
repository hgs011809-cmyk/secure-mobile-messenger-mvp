'use strict';
// Tiny synthetic RAW headers only. No compression/decompression library,
// network, file sink, extraction, child or actual FFmpeg bytes.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const p=require('./ffmpeg-raw-zip-metadata.cjs');let passed=0;const start=Date.now();
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function test(n,fn){if(Date.now()-start>55000)throw Error('RAW_SPEC_DEADLINE');fn();passed++;console.log('ok '+n);}
function fixture(items=[{name:'file.bin',data:Buffer.from('abc'),us:3,method:0,flags:0,mode:0x81a4}],extra=Buffer.alloc(0),comment=Buffer.alloc(0)){
 const locals=[],central=[],meta=[];let off=0;
 for(const e of items){const name=Buffer.from(e.name),l=Buffer.alloc(30),c=Buffer.alloc(46);l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt16LE(e.flags,6);l.writeUInt16LE(e.method,8);l.writeUInt32LE(7,14);l.writeUInt32LE(e.data.length,18);l.writeUInt32LE(e.us,22);l.writeUInt16LE(name.length,26);l.writeUInt16LE(extra.length,28);
 c.writeUInt32LE(0x02014b50);c.writeUInt16LE(0x0314,4);c.writeUInt16LE(20,6);c.writeUInt16LE(e.flags,8);c.writeUInt16LE(e.method,10);c.writeUInt32LE(7,16);c.writeUInt32LE(e.data.length,20);c.writeUInt32LE(e.us,24);c.writeUInt16LE(name.length,28);c.writeUInt16LE(extra.length,30);c.writeUInt32LE((e.mode*65536)>>>0,38);c.writeUInt32LE(off,42);meta.push({local:off,central:0});locals.push(l,name,extra,e.data);central.push(c,name,extra);off+=30+name.length+extra.length+e.data.length;
 }
 let cp=off;for(let i=0;i<items.length;i++){meta[i].central=cp;cp+=46+Buffer.byteLength(items[i].name)+extra.length;}const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(items.length,8);end.writeUInt16LE(items.length,10);end.writeUInt32LE(cp-off,12);end.writeUInt32LE(off,16);end.writeUInt16LE(comment.length,20);
 return {bytes:Buffer.concat([...locals,...central,end,comment]),meta,end:cp};
}
function inspect(f){return p.inspectRawZIPMetadata(f.bytes);}
function reject(f){assert.throws(()=>inspect(f),e=>e.message===p.ERROR);}
function mutate(n,fn){test(n,()=>{const f=fixture();fn(f);reject(f);});}
test('raw declarations explicitly not entry-content integrity',()=>{const f=fixture(),r=inspect(f);assert.equal(r.entryCount,1);assert.equal(r.observedArchiveSha256,sha(f.bytes));assert.equal(r.entries[0].declaredCRC32,7);for(const k of ['contentInflated','contentIntegrityChecked','entryCRCCheckedAgainstContent','entriesMaterialized','vendorAuthenticated','buildOrSDKAdmitted','fullOldPolicyAcceptanceEstablished','oldFullValidatorInvoked'])assert.equal(r[k],false);assert(Object.isFrozen(r)&&Object.isFrozen(r.entries)&&Object.isFrozen(r.entries[0]));});
test('corrupt payload is still only raw header observation',()=>{const f=fixture();f.bytes[38]^=1;const r=inspect(f);assert.equal(r.entryCRCCheckedAgainstContent,false);assert.equal(r.contentIntegrityChecked,false);});
test('deflate bytes observed without decoding',()=>{const f=fixture([{name:'file.bin',data:Buffer.from('cb2f482c2c4d5528aecc2bc9482dc94c56284ecc2dc8490500','hex'),us:23,method:8,flags:0,mode:0x81ed}]);assert.equal(inspect(f).entries[0].method,8);assert.equal(inspect(f).contentInflated,false);});
test('extras recorded, old gate not relaxed',()=>{const r=inspect(fixture(undefined,Buffer.from([1,2,3,4])));assert.equal(r.entries[0].centralExtraBytes,4);assert(r.oldPolicyHeaderReasons.includes('old_policy_extra_fields'));assert.equal(r.fullOldPolicyAcceptanceEstablished,false);});
test('archive comment observed with old rejection reason',()=>{const r=inspect(fixture(undefined,undefined,Buffer.from('comment')));assert.equal(r.archiveCommentBytes,7);assert(r.oldPolicyHeaderReasons.includes('old_policy_archive_comment'));});
test('descriptor metadata not trusted payload',()=>{const f=fixture([{name:'file.bin',data:Buffer.from('abc'),us:3,method:0,flags:8,mode:0x81a4}]);for(const o of [14,18,22])f.bytes.writeUInt32LE(0,o);assert(inspect(f).oldPolicyHeaderReasons.includes('old_policy_data_descriptor'));});
test('symlink mode observation is not admission',()=>{const r=inspect(fixture([{name:'file.bin',data:Buffer.from('abc'),us:3,method:0,flags:0,mode:0xa1ff}]));assert(r.oldPolicyHeaderReasons.includes('old_policy_mode_or_type'));assert.equal(r.entriesMaterialized,false);});
test('unknown method is declared only',()=>{const r=inspect(fixture([{name:'file.bin',data:Buffer.from('abc'),us:3,method:99,flags:0,mode:0x81a4}]));assert(r.oldPolicyHeaderReasons.includes('old_policy_method'));});
mutate('EOCD signature',f=>f.bytes.writeUInt32LE(0,f.end));mutate('multidisk',f=>f.bytes.writeUInt16LE(1,f.end+4));mutate('count mismatch',f=>f.bytes.writeUInt16LE(2,f.end+8));mutate('count cap',f=>{f.bytes.writeUInt16LE(513,f.end+8);f.bytes.writeUInt16LE(513,f.end+10);});mutate('ZIP64 sentinel',f=>f.bytes.writeUInt32LE(0xffffffff,f.end+16));mutate('central boundary',f=>f.bytes.writeUInt32LE(1,f.end+12));mutate('central signature',f=>f.bytes.writeUInt32LE(0,f.meta[0].central));mutate('local signature',f=>f.bytes.writeUInt32LE(0,0));mutate('local flags mismatch',f=>f.bytes.writeUInt16LE(0x800,6));mutate('local length mismatch',f=>f.bytes.writeUInt32LE(1,18));mutate('local name mismatch',f=>f.bytes[30]^=1);mutate('local extra over boundary',f=>f.bytes.writeUInt16LE(65535,28));mutate('file declaration cap',f=>f.bytes.writeUInt32LE(8388609,f.meta[0].central+24));
for(const name of ['../a','/a','a\\b','C:/a','a//b','a/./b','a/../b','a.','a ','a\n','x/'.repeat(16)+'f'])test('unsafe path '+JSON.stringify(name),()=>reject(fixture([{name,data:Buffer.from('a'),us:1,method:0,flags:0,mode:0x81a4}])));
test('duplicate casefold names',()=>reject(fixture([{name:'A',data:Buffer.from('a'),us:1,method:0,flags:0,mode:0x81a4},{name:'a',data:Buffer.from('b'),us:1,method:0,flags:0,mode:0x81a4}])));
test('declared aggregate cap, no inflation',()=>reject(fixture(Array.from({length:5},(_,i)=>({name:'f'+i,data:Buffer.from('a'),us:8388608,method:8,flags:0,mode:0x81a4})))));
test('all truncations rejected',()=>{const f=fixture();for(let n=0;n<f.bytes.length;n++)reject({...f,bytes:f.bytes.subarray(0,n)});});
test('ambiguous EOCD in comment rejected',()=>{const f=fixture(),second=Buffer.from(f.bytes.subarray(f.end));f.bytes.writeUInt16LE(22,f.end+20);f.bytes=Buffer.concat([f.bytes,second]);reject(f);});
test('decorated Buffer slots cannot hide actual bytes',()=>{const f=fixture();Object.defineProperty(f.bytes,'length',{value:1});assert.equal(inspect(f).byteCount,117);});
test('proxy rejects without traps',()=>{let got=0;const f=fixture();f.bytes=new Proxy(f.bytes,{get(){got++;throw Error('TRAP');}});reject(f);assert.equal(got,0);});
test('shared backing rejects',()=>reject({bytes:Buffer.from(new SharedArrayBuffer(32))}));
test('immutable observation is not live byte view',()=>{const f=fixture(),r=inspect(f),h=r.observedArchiveSha256;f.bytes.fill(0);assert.equal(r.observedArchiveSha256,h);assert.notEqual(sha(f.bytes),h);});
console.log(JSON.stringify({kind:'ffmpeg_raw_zip_header_pure_spec',passed,failed:0,realArchives:0,decompression:false,networkRequests:0,filesystemSinkWrites:0,realChildren:0,entryContentOrVendorIntegrityEvidence:false}));
