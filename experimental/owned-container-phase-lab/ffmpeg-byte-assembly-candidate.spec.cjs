'use strict';
// Synthetic opaque byte arrays ONLY, not real archives, network or filesystem
// sinks. No subprocess, extraction, ZIP compatibility, auth or elapsed proof.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const p=require('./ffmpeg-byte-assembly-candidate.cjs');
const start=Date.now();let passed=0;
function test(name,fn){if(Date.now()-start>55000)throw Error('PURE_SPEC_DEADLINE');fn();passed++;console.log('ok '+name);}
function reject(fn){assert.throws(fn,e=>e.message===p.ERROR);}
function create(){return p.createFFmpegByteAssemblyCandidate(p.PRIOR_HEAD_CLAIM);}
const data=Buffer.alloc(p.LIMITS.maxCaptureBytes);for(let i=0;i<data.length;i++)data[i]=(i*17+3)&255;
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
function fill(a,b=data){for(let i=0;i<b.length;i+=65536)a.push(b.subarray(i,Math.min(i+65536,b.length)));}
test('exact synthetic bytes and snapshot digest',()=>{const a=create();fill(a);const r=a.finish();assert.equal(r.byteCount,data.length);assert(r.bytes.equals(data));assert.equal(r.snapshotSha256,digest(data));assert.equal(r.chunkCount,36);assert(Object.isFrozen(r));for(const k of ['wireResponseValidated','acquisitionAuthorityEstablished','archiveVerified','vendorAuthenticated','zipCompatibilityEstablished','temporalBoundEstablished','transportCancellationEstablished','physicalErasureEstablished'])assert.equal(r[k],false);});
test('chunk snapshot isolates later caller mutation',()=>{const b=Buffer.from(data),a=create();fill(a,b);b.fill(0);assert(a.finish().bytes.equals(data));});
test('mutable copy explicitly not future hash binding',()=>{const a=create();fill(a);const r=a.finish(),old=r.snapshotSha256;r.bytes[0]^=1;assert.notEqual(digest(r.bytes),old);assert.equal(r.mutableCopyReturned,true);});
test('view offset internal slots',()=>{const backing=Buffer.alloc(65536+4),view=new Uint8Array(backing.buffer,backing.byteOffset+2,65536);data.copy(backing,2,0,65536);const a=create();a.push(view);for(let i=65536;i<data.length;i+=65536)a.push(data.subarray(i,Math.min(i+65536,data.length)));assert(a.finish().bytes.equals(data));});
test('decorated length/valueOf/iterator never consulted',()=>{const a=create(),b=Buffer.from(data.subarray(0,65536));for(const k of ['length','buffer','valueOf'])Object.defineProperty(b,k,{get(){throw Error('DECORATED_ACCESS');}});Object.defineProperty(b,Symbol.iterator,{get(){throw Error('DECORATED_ITERATOR');}});a.push(b);for(let i=65536;i<data.length;i+=65536)a.push(data.subarray(i,Math.min(i+65536,data.length)));assert(a.finish().bytes.equals(data));});
test('decorated oversized chunk cannot hide size',()=>{const a=create(),b=Buffer.alloc(p.LIMITS.maxChunkBytes+1);Object.defineProperty(b,'length',{value:1});reject(()=>a.push(b));reject(()=>a.finish());});
test('shared backing rejected',()=>{const a=create();reject(()=>a.push(new Uint8Array(new SharedArrayBuffer(1))));reject(()=>a.finish());});
test('proxy rejected without get traps',()=>{let gets=0;const a=create(),v=new Proxy(Buffer.from('x'),{get(){gets++;throw Error('TRAP');}});reject(()=>a.push(v));assert.equal(gets,0);});
for(const v of [null,undefined,{},[],new Uint16Array(1),new Uint8ClampedArray(1),'x',1])test('non byte view '+typeof v,()=>{const a=create();reject(()=>a.push(v));reject(()=>a.finish());});
test('zero byte chunk blocks',()=>{const a=create();reject(()=>a.push(Buffer.alloc(0)));reject(()=>a.finish());});
test('maximum chunk accepted within total',()=>{const a=create();a.push(data.subarray(0,p.LIMITS.maxChunkBytes));for(let i=p.LIMITS.maxChunkBytes;i<data.length;i+=65536)a.push(data.subarray(i,Math.min(i+65536,data.length)));assert(a.finish().bytes.equals(data));});
test('total overflow blocks before accepting extra data',()=>{const a=create();fill(a);reject(()=>a.push(Buffer.from('x')));reject(()=>a.finish());});
test('final cumulative overflow blocks',()=>{const a=create();for(let i=0;i<data.length-1;i+=65536)a.push(data.subarray(i,Math.min(i+65536,data.length-1)));reject(()=>a.push(Buffer.from('xy')));reject(()=>a.finish());});
test('short capture cannot finish',()=>{const a=create();a.push(Buffer.from('x'));reject(()=>a.finish());reject(()=>a.push(Buffer.from('y')));});
test('no bytes cannot finish',()=>reject(()=>create().finish()));
test('finite chunk ceiling independent of byte cap',()=>{const a=create();for(let i=0;i<p.LIMITS.maxChunks;i++)a.push(Buffer.from('x'));reject(()=>a.push(Buffer.from('x')));reject(()=>a.finish());});
test('abandon blocks reuse',()=>{const a=create();a.push(Buffer.from('x'));a.abandon();reject(()=>a.push(Buffer.from('x')));reject(()=>a.finish());});
test('finished capture cannot be reused',()=>{const a=create();fill(a);const r=a.finish();reject(()=>a.finish());reject(()=>a.push(Buffer.from('x')));assert(r.bytes.equals(data));});
test('claim object/getter never read',()=>{let got=false;reject(()=>p.createFFmpegByteAssemblyCandidate({get url(){got=true;throw Error('GETTER');}}));assert.equal(got,false);});
for(const change of [s=>s+' ',s=>s.replace('2302701','2302702'),s=>s.replace('200','307'),s=>s.replace('https:','http:'),s=>s.replace('identityRepresentation":true','identityRepresentation":false'),s=>s.replace('redirect":null','redirect":"https://example.invalid"'),s=>s.replace('ffmpeg-linux.zip','chrome-linux64.zip')])test('exact metadata claim rejects mutation',()=>reject(()=>p.createFFmpegByteAssemblyCandidate(change(p.PRIOR_HEAD_CLAIM))));
test('canonical claim cannot append duplicate keys',()=>reject(()=>p.createFFmpegByteAssemblyCandidate(p.PRIOR_HEAD_CLAIM.slice(0,-1)+',"status":200}')));
test('frozen policy and API',()=>{assert(Object.isFrozen(p)&&Object.isFrozen(p.LIMITS)&&Object.isFrozen(create()));assert.equal(Object.hasOwn(p,'fetch'),false);});
console.log(JSON.stringify({kind:'ffmpeg_byte_assembly_pure_spec',passed,failed:0,realArchives:0,networkRequests:0,realChildren:0,filesystemSinkWrites:0,zipCompatibility:false,acquisitionAuthority:false,vendorAuthentication:false,temporalOrCleanupEvidence:false}));
