'use strict';
const assert=require('node:assert/strict');
const {inspectCombinedRawHeaders,ERROR,LIMITS}=require('./raw-header-diagnostics-composition.cjs');
let passed=0; function test(n,f){f();passed++;console.log('ok '+n);}
function fixture(items, comment=Buffer.alloc(0), prefixGap=0){
 const locals=prefixGap?[Buffer.alloc(prefixGap)]:[], central=[]; let off=prefixGap;
 for(const x of items){const name=Buffer.from(x.name), d=x.name.endsWith('/'), payload=d?Buffer.alloc(0):Buffer.from('x'), le=x.local||Buffer.alloc(0), ce=x.central||Buffer.alloc(0);
  const l=Buffer.alloc(30),c=Buffer.alloc(46),crc=d?0:7;
  l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt16LE(x.flags||0,6);l.writeUInt32LE(crc,14);l.writeUInt32LE(payload.length,18);l.writeUInt32LE(payload.length,22);l.writeUInt16LE(name.length,26);l.writeUInt16LE(le.length,28);
  c.writeUInt32LE(0x02014b50);c.writeUInt16LE(0x0314,4);c.writeUInt16LE(20,6);c.writeUInt16LE(x.flags||0,8);c.writeUInt32LE(crc,16);c.writeUInt32LE(payload.length,20);c.writeUInt32LE(payload.length,24);c.writeUInt16LE(name.length,28);c.writeUInt16LE(ce.length,30);c.writeUInt32LE((((d?0x41ed:0x81a4)*65536)+(d?16:0))>>>0,38);c.writeUInt32LE(off,42);
  locals.push(l,name,le,payload);central.push(c,name,ce);off+=30+name.length+le.length+payload.length;
 }
 const cd=Buffer.concat(central),e=Buffer.alloc(22+comment.length);e.writeUInt32LE(0x06054b50);e.writeUInt16LE(items.length,8);e.writeUInt16LE(items.length,10);e.writeUInt32LE(cd.length,12);e.writeUInt32LE(off,16);e.writeUInt16LE(comment.length,20);comment.copy(e,22);return Buffer.concat([...locals,cd,e]);
}
const field=(id,data=Buffer.alloc(0))=>{const h=Buffer.alloc(4);h.writeUInt16LE(id);h.writeUInt16LE(data.length,2);return Buffer.concat([h,data]);};
const inspect=b=>inspectCombinedRawHeaders(b), reject=b=>assert.throws(()=>inspect(b),e=>e.constructor===Error&&e.message===ERROR);
const base=()=>fixture([{name:'root/',local:field(0x9999),central:field(0x9999)},{name:'root/a',local:field(0x5455,Buffer.from([1,1,2,3,4])),central:field(0x5455,Buffer.from([1,1,2,3,4]))}]);
test('combined one-snapshot layout plus local and central observations',()=>{const r=inspect(base());assert.equal(r.extras.entries.length,2);assert.equal(r.extras.fieldCount,4);assert.equal(r.layout.counts.implicit_parent,0);assert.deepEqual(r.oldPolicyHeaderReasons,['old_policy_extra_fields']);});
test('local-central difference and unknown IDs remain diagnostics',()=>{const r=inspect(fixture([{name:'x',local:field(0x9999),central:Buffer.alloc(0)}]));assert.equal(r.extras.entries[0].local.fields[0].kind,'unknown');assert.equal(r.extras.entries[0].central.fieldCount,0);assert.equal(r.oldPolicyHeaderReasons.includes('old_policy_extra_fields'),true);});
test('malformed TLV uses fixed generic failure',()=>reject(fixture([{name:'x',local:Buffer.from([1,2,9,0,4])}])));
test('duplicate and unknown field identifiers are reported, not admitted',()=>{const x=Buffer.concat([field(0xbeef),field(0xbeef)]),r=inspect(fixture([{name:'x',local:x,central:x}]));assert.equal(r.extras.diagnosticCount,2);assert.equal(r.archiveAdmitted,false);});
test('noncontiguous-local and descriptor reasons are preserved',()=>{const r=inspect(fixture([{name:'x',flags:8}],Buffer.alloc(0),1));assert.deepEqual(r.oldPolicyHeaderReasons,['old_policy_data_descriptor','old_policy_flags','old_policy_noncontiguous_local_layout']);});
test('path layout reports implicit and file ancestor without changing reasons',()=>{const r=inspect(fixture([{name:'a'},{name:'a/b'}]));assert.equal(r.layout.counts.file_ancestor,1);assert.deepEqual(r.oldPolicyHeaderReasons,[]);});
test('archive comment old reason preserved exactly',()=>assert.deepEqual(inspect(fixture([{name:'x'}],Buffer.from('c'))).oldPolicyHeaderReasons,['old_policy_archive_comment']));
test('caller mutation cannot change private result',()=>{const b=base(),r=inspect(b);b.fill(0);assert.equal(r.extras.fieldCount,4);});
test('proxy rejected before traps',()=>{let touched=0;reject(new Proxy(base(),{get(){touched++;throw Error('trap')}}));assert.equal(touched,0);});
test('shared, subclass and decorated buffers rejected',()=>{reject(Buffer.from(new SharedArrayBuffer(32)));class B extends Buffer{};const sub=Buffer.from(base());Object.setPrototypeOf(sub,B.prototype);reject(sub);const b=base();Object.defineProperty(b,'x',{get(){throw Error('getter')}});reject(b);});
test('aggregate output deeply frozen and has no admission flags set true',()=>{const r=inspect(base());assert(Object.isFrozen(r)&&Object.isFrozen(r.extras.entries[0].local.fields));for(const k of ['archiveAdmitted','fullOldPolicyAcceptanceEstablished','contentInflated','contentIntegrityChecked','entriesMaterialized','vendorAuthenticated','buildOrSDKAdmitted'])assert.equal(r[k],false);});
test('malformed central TLV fails with fixed generic error',()=>reject(fixture([{name:'x',central:Buffer.from([1,2,8,0,4])}])));
test('aggregate extra-byte cap rejects before accumulating large diagnostics',()=>{const x=Buffer.alloc(60000);x.writeUInt16LE(0xbeef,0);x.writeUInt16LE(59996,2);reject(fixture([{name:'a',local:x,central:x},{name:'b',local:x,central:x},{name:'c',local:x,central:x}]));});
test('empty extras remain bounded diagnostics',()=>{const r=inspect(fixture([{name:'x'}]));assert.equal(r.extras.totalExtraBytes,0);});
test('exact aggregate 4096-field boundary succeeds without admission',()=>{const x=Buffer.concat(Array.from({length:1024},()=>field(0xbeef)));const r=inspect(fixture([{name:'a',local:x,central:x},{name:'b',local:x,central:x}]));assert.equal(r.extras.fieldCount,LIMITS.maxFields);assert.equal(r.extras.diagnosticCount,4092);assert.equal(r.archiveAdmitted,false);});
test('one beyond aggregate field limit fails closed',()=>{const x=Buffer.concat(Array.from({length:1024},()=>field(0xbeef)));reject(fixture([{name:'a',local:x,central:x},{name:'b',local:x,central:x},{name:'c',local:field(0xbeef)}]));});
test('worst diagnostic count at field cap is 8188 not 8192',()=>{const x=Buffer.concat(Array.from({length:1024},()=>field(0x5455,Buffer.from([128]))));const r=inspect(fixture([{name:'a',local:x,central:x},{name:'b',local:x,central:x}]));assert.equal(r.extras.fieldCount,4096);assert.equal(r.extras.diagnosticCount,8188);assert(r.extras.diagnosticCount<=LIMITS.maxDiagnostics);});
test('exact aggregate extra-byte boundary succeeds',()=>{const x=field(0xbeef,Buffer.alloc(65531));const r=inspect(fixture([{name:'a',local:x,central:x},{name:'b',local:x,central:x},{name:'c',local:field(0xbeef)}]));assert.equal(r.extras.totalExtraBytes,LIMITS.maxExtraBytes);assert.equal(r.extras.fieldCount,5);});
test('one beyond aggregate extra-byte boundary rejected',()=>{const x=field(0xbeef,Buffer.alloc(65531));reject(fixture([{name:'a',local:x,central:x},{name:'b',local:x,central:x},{name:'c',local:field(0xbeef,Buffer.from([0]))}]));});
test('local three-times and central one-time timestamp profiles correlate',()=>{const r=inspect(fixture([{name:'x',local:field(0x5455,Buffer.from([7,...Array(12).fill(0)])),central:field(0x5455,Buffer.from([7,...Array(4).fill(0)]))}]));assert.equal(r.extras.diagnosticCount,0);assert.deepEqual(r.oldPolicyHeaderReasons,['old_policy_extra_fields']);assert.equal(r.fullOldPolicyAcceptanceEstablished,false);});
test('ancestor spelling collision remains independent observation',()=>{const r=inspect(fixture([{name:'Root/a'},{name:'root/b'}]));assert.equal(r.layout.counts.ancestor_spelling_collision,1);assert.deepEqual(r.oldPolicyHeaderReasons,[]);assert.equal(r.archiveAdmitted,false);});
test('throwing intrinsic slot decorations never invoked',()=>{for(const slot of ['length','buffer','byteLength']){let hits=0,b=base();Object.defineProperty(b,slot,{get(){hits++;throw Error('TRAP');}});reject(b);assert.equal(hits,0);}});
console.log(JSON.stringify({kind:'combined_raw_header_diagnostics_source_spec',passed,failed:0,manufacturedHeaderFixtures:true,actualArchives:0,networkRequests:0,decompression:false,admission:false}));
