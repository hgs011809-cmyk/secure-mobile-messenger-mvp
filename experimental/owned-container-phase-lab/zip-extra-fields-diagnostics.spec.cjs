'use strict';
// Tiny synthetic TLV fixtures only. No archive import or payload processing.
const assert=require('node:assert/strict');
const p=require('./zip-extra-fields-diagnostics.cjs');
const {ERROR,LIMITS}=p;
const inspect=(bytes,context='local')=>p.inspectZipExtraFields(bytes,context);
let passed=0;const started=Date.now();
function test(name,fn){if(Date.now()-started>55000)throw Error('ZIP_EXTRA_SPEC_DEADLINE');fn();passed++;console.log('ok '+name);}
function field(id,data=[]){const b=Buffer.alloc(4+data.length);b.writeUInt16LE(id);b.writeUInt16LE(data.length,2);Buffer.from(data).copy(b,4);return b;}
function reject(value,context='local'){assert.throws(()=>inspect(value,context),e=>e.message===ERROR);}
test('empty input: nonadmission flags',()=>{const r=inspect(Buffer.alloc(0),'local');assert.equal(r.fieldCount,0);for(const k of ['archiveAdmitted','buildOrSDKAdmitted','fullOldPolicyAcceptanceEstablished','contentInflated','entriesMaterialized','vendorAuthenticated'])assert.equal(r[k],false);assert(Object.isFrozen(r)&&Object.isFrozen(r.fields)&&Object.isFrozen(r.diagnostics));});
test('timestamp basic format emits no timestamp value',()=>{const r=inspect(field(0x5455,[1,1,2,3,4]),'local');assert.equal(r.fields[0].kind,'extended_timestamp_diagnostic_only');assert.equal(r.diagnostics.length,0);assert(!JSON.stringify(r).includes('67305985'));});
test('central timestamp format differs from local',()=>{const x=field(0x5455,[7,1,2,3,4,5,6,7,8,9,10,11,12]);assert.equal(inspect(x,'local').diagnostics.length,0);assert.equal(inspect(x,'central').diagnostics[0].code,'malformed_timestamp');});
test('timestamp tiny body and invalid flags diagnosed',()=>{assert.equal(inspect(field(0x5455,[]),'local').diagnostics[0].code,'malformed_timestamp');assert.equal(inspect(field(0x5455,[128]),'local').diagnostics[0].code,'malformed_timestamp');});
test('UID/GID reports lengths, not values',()=>{const r=inspect(field(0x7875,[1,2,0x34,0x12,1,0x56]));assert.equal(r.fields[0].kind,'uid_gid_diagnostic_only');assert(!JSON.stringify(r).includes('4660'));});
test('UID/GID invalid version and lengths diagnosed',()=>{assert.equal(inspect(field(0x7875,[2,1,9,1,8])).diagnostics[0].code,'malformed_uid_gid');assert.equal(inspect(field(0x7875,[1,5,1,2,3,4,5])).diagnostics[0].code,'malformed_uid_gid');});
test('ZIP64 diagnostic is not acceptance',()=>{const r=inspect(field(1,Array(8).fill(0)));assert.equal(r.fields[0].kind,'zip64_diagnostic_only');assert.equal(r.archiveAdmitted,false);});
test('unknown ID structurally reported',()=>{const r=inspect(field(0xbeef,[1,2]));assert.deepEqual(r.fields[0],{id:0xbeef,length:2,kind:'unknown',format:'opaque'});});
test('duplicate ID diagnosed without trust',()=>{const r=inspect(Buffer.concat([field(9,[1]),field(9,[2])]));assert.equal(r.diagnostics[0].code,'duplicate_id');});
test('truncated header/body fail closed',()=>{reject(Buffer.from([1,2,3]));reject(Buffer.from([1,0,2,0,99]));});
test('declared maximum length with tiny body fails closed',()=>{reject(Buffer.from([1,0,255,255]));});
test('field count cap',()=>{reject(Buffer.concat(Array.from({length:LIMITS.maxFields+1},()=>field(99,[]))));});
test('strict primitive contexts',()=>{for(const c of ['LOCAL','central ',null,{},new String('local')])assert.throws(()=>inspect(Buffer.alloc(0),c),e=>e.message===ERROR);});
test('private copy unaffected by later input mutation',()=>{const b=field(99,[3]),r=inspect(b);b[0]=0;assert.equal(r.fields[0].id,99);});
test('decorated Buffer rejected without invoking getter',()=>{const b=Buffer.alloc(0);Object.defineProperty(b,'trap',{get(){throw Error('getter ran')}});reject(b);});
test('proxy and shared backing rejected',()=>{reject(new Proxy(Buffer.alloc(0),{}));if(typeof SharedArrayBuffer==='function')reject(Buffer.from(new SharedArrayBuffer(1)));});
test('deep immutability and deterministic diagnostic ordering',()=>{const r=inspect(Buffer.concat([field(0x5455,[128]),field(0x5455,[128])]));assert.deepEqual(r.diagnostics.map(x=>x.code),['malformed_timestamp','malformed_timestamp','duplicate_id']);assert(Object.isFrozen(r.fields[0])&&Object.isFrozen(r.diagnostics[0]));});
test('diagnostic output bounded at maximum field count',()=>{const r=inspect(Buffer.concat(Array.from({length:LIMITS.maxFields},()=>field(0x5455,[128]))));assert.equal(r.fieldCount,LIMITS.maxFields);assert.equal(r.diagnostics.length,LIMITS.maxFields*2-1);assert(r.diagnostics.length<=LIMITS.maxDiagnostics);});
test('public function requires explicit context',()=>assert.throws(()=>p.inspectZipExtraFields(Buffer.alloc(0)),e=>e.message===ERROR));
test('central flags may declare three times but retain mtime only',()=>assert.equal(inspect(field(0x5455,[7,1,2,3,4]),'central').diagnostics.length,0));
test('byte cap exact boundary and one beyond',()=>{assert.equal(inspect(field(99,Buffer.alloc(LIMITS.maxBytes-4))).byteLength,LIMITS.maxBytes);reject(Buffer.alloc(LIMITS.maxBytes+1));});
test('all truncated TLV headers and bodies rejected',()=>{const b=field(99,[1,2,3,4]);for(let n=1;n<b.length;n++)reject(b.subarray(0,n));});
test('decorated intrinsic slots cannot override real bounds',()=>{const b=field(99,[1]);Object.defineProperty(b,'length',{get(){throw Error('getter ran');}});reject(b);});
test('proxy rejection does not touch traps',()=>{let touched=0;reject(new Proxy(Buffer.alloc(0),{get(){touched++;throw Error('TRAP');},ownKeys(){touched++;throw Error('TRAP');},getPrototypeOf(){touched++;throw Error('TRAP');}}));assert.equal(touched,0);});
test('zero-length unknown fields make bounded progress',()=>{const r=inspect(Buffer.concat(Array.from({length:LIMITS.maxFields},(_,i)=>field(i+0x1000,[]))));assert.equal(r.fieldCount,LIMITS.maxFields);assert.equal(r.diagnostics.length,0);});
test('public constants frozen',()=>assert(Object.isFrozen(p)&&Object.isFrozen(p.LIMITS)&&Object.isFrozen(p.ISSUE_CODES)));
console.log(JSON.stringify({kind:'zip_extra_field_pure_spec',passed,failed:0,actualArchives:0,networkRequests:0,realChildren:0,decompression:false,archiveAdmission:false}));
