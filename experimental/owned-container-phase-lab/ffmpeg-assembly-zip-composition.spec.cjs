'use strict';
// PURE composition on a manufactured stored ZIP of the same declared length.
// This is deliberately NOT real FFmpeg bytes/layout/compatibility or vendor
// authentication. No network, filesystem sinks, staging, extraction or child.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
for(const [name,pin] of [['ffmpeg-byte-assembly-candidate.cjs','33b171beb7a7f4eacd5c365f3305a29862c74cb689dd4c0626ac25a7d2a95b76'],['zip-byte-inventory.cjs','a1a829ae07b81737b08c45e656502ebcc9b304a0a49c6f274bfd2c63b8498eea']])assert.equal(sha(fs.readFileSync(path.join(__dirname,name))),pin);
const a=require('./ffmpeg-byte-assembly-candidate.cjs'),z=require('./zip-byte-inventory.cjs');
const table=new Uint32Array(256);for(let i=0;i<256;i++){let c=i;for(let j=0;j<8;j++)c=(c>>>1)^((c&1)?0xedb88320:0);table[i]=c>>>0;}
function crc(b){let c=0xffffffff;for(const n of b)c=(c>>>8)^table[(c^n)&255];return (c^0xffffffff)>>>0;}
const name=Buffer.from('synthetic.bin'),payload=Buffer.alloc(a.LIMITS.maxCaptureBytes-(30+46+22+name.length*2));for(let i=0;i<payload.length;i++)payload[i]=(i*11+7)&255;
const l=Buffer.alloc(30),c=Buffer.alloc(46),end=Buffer.alloc(22),checksum=crc(payload),cdOffset=30+name.length+payload.length;
l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt32LE(checksum,14);l.writeUInt32LE(payload.length,18);l.writeUInt32LE(payload.length,22);l.writeUInt16LE(name.length,26);
c.writeUInt32LE(0x02014b50);c.writeUInt16LE(0x0314,4);c.writeUInt16LE(20,6);c.writeUInt32LE(checksum,16);c.writeUInt32LE(payload.length,20);c.writeUInt32LE(payload.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE(0x81a40000,38);
end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(c.length+name.length,12);end.writeUInt32LE(cdOffset,16);
const fixture=Buffer.concat([l,name,payload,c,name,end]),manifest={roots:['synthetic.bin'],entries:[{path:'synthetic.bin',type:'file',mode:420,size:payload.length,sha256:sha(payload)}]};assert.equal(fixture.length,a.LIMITS.maxCaptureBytes);
function capture(){const asm=a.createFFmpegByteAssemblyCandidate(a.PRIOR_HEAD_CLAIM);for(let i=0;i<fixture.length;i+=65536)asm.push(fixture.subarray(i,Math.min(i+65536,fixture.length)));return asm.finish();}
function inspect(r,pin={length:r.byteCount,sha256:r.snapshotSha256},m=manifest){return z.inspectZipBytes(r.bytes,JSON.stringify(pin),JSON.stringify(z.HARD_CEILINGS),JSON.stringify(m));}
function reject(fn){assert.throws(fn,e=>e.message===z.ERROR);}
let passed=0;const start=Date.now();function test(n,fn){if(Date.now()-start>55000)throw Error('COMPOSITION_SPEC_DEADLINE');fn();passed++;console.log('ok '+n);}
test('exact assembly to synthetic byte-tree binding',()=>{const r=capture(),v=inspect(r);assert.equal(v.archiveSha256,r.snapshotSha256);assert.equal(v.length,r.byteCount);assert.equal(v.totalOutputBytes,payload.length);assert.equal(v.entries[0].sha256,manifest.entries[0].sha256);assert.equal(v.entries[0].mode,420);assert.equal(v.candidateOnly,true);assert.equal(v.stagingImplemented,false);assert.equal(r.wireResponseValidated,false);assert.equal(r.acquisitionAuthorityEstablished,false);assert.equal(r.vendorAuthenticated,false);assert.equal(r.zipCompatibilityEstablished,false);});
test('mutation before consumption rejected by original snapshot pin',()=>{const r=capture();r.bytes[30+name.length]^=1;reject(()=>inspect(r));assert.notEqual(sha(r.bytes),r.snapshotSha256);});
test('fresh pin and consistent forged CRC still fail original content claim',()=>{const r=capture();r.bytes[30+name.length]^=1;const alteredCRC=crc(r.bytes.subarray(30+name.length,cdOffset));r.bytes.writeUInt32LE(alteredCRC,14);r.bytes.writeUInt32LE(alteredCRC,cdOffset+16);reject(()=>inspect(r,{length:r.byteCount,sha256:sha(r.bytes)}));});
test('unchanged archive cannot satisfy altered mode claim',()=>{const r=capture(),m=JSON.parse(JSON.stringify(manifest));m.entries[0].mode=493;reject(()=>inspect(r,undefined,m));});
test('bound inventory not a live view of later mutable bytes',()=>{const r=capture(),v=inspect(r),hash=v.archiveSha256,entry=v.entries[0].sha256;r.bytes.fill(0);assert.equal(v.archiveSha256,hash);assert.equal(v.entries[0].sha256,entry);assert.notEqual(sha(r.bytes),hash);assert(Object.isFrozen(v)&&Object.isFrozen(v.entries)&&Object.isFrozen(v.entries[0]));});
console.log(JSON.stringify({kind:'ffmpeg_assembly_zip_composition_pure_spec',passed,failed:0,syntheticByteLength:fixture.length,realArchives:0,networkRequests:0,realChildren:0,filesystemSinkWrites:0,staging:false,extraction:false,realFFmpegLayoutOrCompatibility:false,vendorAuthentication:false,temporalOrCleanupEvidence:false}));
