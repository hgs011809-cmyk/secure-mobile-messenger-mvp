'use strict';
// Finite deterministic single-bit mutation properties on TWO tiny synthetic
// fixtures ONLY. Re-pin each mutated archive to reach structural/content checks.
// Accepted equivalent encodings must retain exact original manifest semantics.
// No archive acquisition, extraction, child processes, network or staging.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),zlib=require('node:zlib'),fs=require('node:fs'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'zip-byte-inventory.cjs'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
assert.equal(sha(source),'a1a829ae07b81737b08c45e656502ebcc9b304a0a49c6f274bfd2c63b8498eea');
const p=require('./zip-byte-inventory.cjs');
function crc(b){let x=0xffffffff;for(const v of b){x^=v;for(let i=0;i<8;i++)x=(x>>>1)^((x&1)?0xedb88320:0);}return (x^0xffffffff)>>>0;}
function fixture(method){
 const items=[{path:'root',dir:true,data:Buffer.alloc(0),method:0},{path:'root/a',dir:false,data:Buffer.from('opaque synthetic sample'),method}];
 const local=[],central=[],entries=[];let offset=0,compressedTotal=0;
 for(const e of items){const name=Buffer.from(e.path+(e.dir?'/':'')),compressed=e.method===8?zlib.deflateRawSync(e.data):e.data,l=Buffer.alloc(30),c=Buffer.alloc(46),mode=e.dir?493:420;
 l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt16LE(e.method,8);l.writeUInt32LE(crc(e.data),14);l.writeUInt32LE(compressed.length,18);l.writeUInt32LE(e.data.length,22);l.writeUInt16LE(name.length,26);
 c.writeUInt32LE(0x02014b50);c.writeUInt16LE(0x0314,4);c.writeUInt16LE(20,6);c.writeUInt16LE(e.method,10);c.writeUInt32LE(crc(e.data),16);c.writeUInt32LE(compressed.length,20);c.writeUInt32LE(e.data.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE((((e.dir?0x4000:0x8000)|mode)*65536+(e.dir?16:0))>>>0,38);c.writeUInt32LE(offset,42);
 local.push(l,name,compressed);central.push(c,name);offset+=30+name.length+compressed.length;compressedTotal+=compressed.length;entries.push({path:e.path,type:e.dir?'directory':'file',mode,size:e.data.length,sha256:sha(e.data)});
 }
 const cd=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(items.length,8);end.writeUInt16LE(items.length,10);end.writeUInt32LE(cd.length,12);end.writeUInt32LE(offset,16);
 return {bytes:Buffer.concat([...local,cd,end]),manifest:{roots:['root'],entries},compressedTotal,outputTotal:items.reduce((n,e)=>n+e.data.length,0)};
}
function inspect(bytes,f){return p.inspectZipBytes(bytes,JSON.stringify({length:bytes.length,sha256:sha(bytes)}),JSON.stringify(p.HARD_CEILINGS),JSON.stringify(f.manifest));}
function semantics(r,f,b){assert.equal(r.archiveSha256,sha(b));assert.equal(r.length,b.length);assert.equal(r.candidateOnly,true);assert.equal(r.stagingImplemented,false);assert.deepEqual(Array.from(r.roots),f.manifest.roots);assert.deepEqual(r.entries.map(({path,type,mode,size,sha256})=>({path,type,mode,size,sha256})),f.manifest.entries);assert.equal(r.totalCompressedBytes,f.compressedTotal);assert.equal(r.totalOutputBytes,f.outputTotal);assert(Object.isFrozen(r)&&Object.isFrozen(r.entries)&&r.entries.every(Object.isFrozen));}
const started=Date.now(),families=[];let mutations=0,rejected=0,acceptedEquivalent=0;
for(const method of [0,8]){
 const f=fixture(method);assert(f.bytes.length<4096);semantics(inspect(f.bytes,f),f,f.bytes);let familyRejected=0,familyAccepted=0;
 for(let offset=0;offset<f.bytes.length;offset++)for(let bit=0;bit<8;bit++){
  if(Date.now()-started>55000)throw Error('MUTATION_SPEC_DEADLINE');
  const b=Buffer.from(f.bytes);b[offset]^=1<<bit;let r;
  try{r=inspect(b,f);}catch(e){assert.equal(e.message,p.ERROR);rejected++;familyRejected++;}
  if(r){semantics(r,f,b);acceptedEquivalent++;familyAccepted++;}
  mutations++;
 }
 // Stored tiny fixture has no deflate padding/equivalent compression bits.
 if(method===0)assert.equal(familyAccepted,0);
 assert.equal(familyRejected+familyAccepted,f.bytes.length*8);families.push({method,bytes:f.bytes.length,mutations:f.bytes.length*8,rejected:familyRejected,acceptedEquivalent:familyAccepted});
}
assert.equal(mutations,rejected+acceptedEquivalent);
console.log(JSON.stringify({kind:'zip_byte_single_bit_mutation_pure_spec',fixtures:2,mutations,rejected,acceptedEquivalent,families,realArchives:0,networkRequests:0,realChildren:0,filesystemSinkWrites:0,extraction:false,vendorAuthentication:false,generalZIPCompatibility:false,exploitSafety:false}));
