'use strict';
// Direct require synthetic tests. No subprocess, extraction, network, container
// or filesystem staging. Finite deterministic loops; external deadline <=60s.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),zlib=require('node:zlib');
const {inspectZipBytes,HARD_CEILINGS,ERROR}=require('./zip-byte-inventory.cjs');
const start=Date.now();let count=0;
function test(name,fn){if(Date.now()-start>55000)throw Error('TEST_DEADLINE');fn();count++;console.log('ok '+count+' '+name);}
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function crc(b){let x=0xffffffff;for(const v of b){x^=v;for(let i=0;i<8;i++)x=(x>>>1)^((x&1)?0xedb88320:0);}return (x^0xffffffff)>>>0;}
function fixture(items=[{name:'root/',data:'',dir:true},{name:'root/a',data:'bounded real bytes',method:0}]){
 const locals=[],centrals=[],meta=[];let offset=0;
 for(const e of items){const data=Buffer.from(e.data),name=Buffer.from(e.name),method=e.method||0,compressed=e.compressed|| (method===8?zlib.deflateRawSync(data):data),l=Buffer.alloc(30),c=Buffer.alloc(46),mode=e.dir?0x41ed:0x81a4;
 l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt16LE(method,8);l.writeUInt32LE(crc(data),14);l.writeUInt32LE(compressed.length,18);l.writeUInt32LE(data.length,22);l.writeUInt16LE(name.length,26);
 c.writeUInt32LE(0x02014b50);c.writeUInt16LE(0x0314,4);c.writeUInt16LE(20,6);c.writeUInt16LE(method,10);c.writeUInt32LE(crc(data),16);c.writeUInt32LE(compressed.length,20);c.writeUInt32LE(data.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE((mode*65536+(e.dir?16:0))>>>0,38);c.writeUInt32LE(offset,42);
 locals.push(l,name,compressed);centrals.push(c,name);meta.push({local:offset,central:0,data:offset+30+name.length});offset+=30+name.length+compressed.length;
 }
 let cp=offset;for(let i=0;i<items.length;i++){meta[i].central=cp;cp+=46+Buffer.byteLength(items[i].name);}
 const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(items.length,8);end.writeUInt16LE(items.length,10);end.writeUInt32LE(cp-offset,12);end.writeUInt32LE(offset,16);
 const bytes=Buffer.concat([...locals,...centrals,end]);
 const manifest={roots:['root'],entries:items.map(e=>({path:e.dir?e.name.slice(0,-1):e.name,type:e.dir?'directory':'file',mode:e.dir?493:420,size:Buffer.byteLength(e.data),sha256:sha(Buffer.from(e.data))}))};return {bytes,manifest,meta,end:cp};
}
const caps={...HARD_CEILINGS};
function inspect(f,c=caps,p={length:f.bytes.length,sha256:sha(f.bytes)},m=f.manifest){return inspectZipBytes(f.bytes,JSON.stringify(p),JSON.stringify(c),JSON.stringify(m));}
function reject(f,c,p,m){assert.throws(()=>inspect(f,c,p,m),e=>e.message===ERROR);}
function mutate(name,fn){test(name,()=>{const f=fixture();fn(f);reject(f);});}
test('valid stored exact tree binding immutable',()=>{const f=fixture(),r=inspect(f);assert.equal(r.entries.length,2);assert.equal(r.archiveSha256,sha(f.bytes));assert.equal(r.stagingImplemented,false);assert.equal(r.candidateOnly,true);assert.equal(r.bindingSha256,inspect(f).bindingSha256);assert(Object.isFrozen(r)&&Object.isFrozen(r.entries)&&Object.isFrozen(r.entries[0])&&Object.isFrozen(r.roots));});
test('valid deflate and zero-length files',()=>{const f=fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'deflated actual content',method:8},{name:'root/empty',data:'',method:8}]);assert.equal(inspect(f).entries[1].method,8);});
test('stored empty file',()=>inspect(fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:''}])));
mutate('EOCD signature',f=>f.bytes.writeUInt32LE(0,f.end));
mutate('multidisk EOCD',f=>f.bytes.writeUInt16LE(1,f.end+4));
mutate('disk entry mismatch',f=>f.bytes.writeUInt16LE(1,f.end+8));
mutate('ZIP64 EOCD sentinel',f=>f.bytes.writeUInt32LE(0xffffffff,f.end+16));
mutate('ZIP64 count sentinel',f=>f.bytes.writeUInt16LE(65535,f.end+10));
mutate('EOCD comment',f=>f.bytes.writeUInt16LE(1,f.end+20));
mutate('central boundary',f=>f.bytes.writeUInt32LE(1,f.end+12));
mutate('central signature',f=>f.bytes.writeUInt32LE(0,f.meta[0].central));
mutate('unsupported made-by host',f=>f.bytes.writeUInt16LE(20,f.meta[0].central+4));
mutate('version needed mismatch',f=>f.bytes.writeUInt16LE(45,f.meta[0].central+6));
mutate('encrypted flag',f=>f.bytes.writeUInt16LE(1,f.meta[1].central+8));
mutate('data descriptor flag',f=>f.bytes.writeUInt16LE(8,f.meta[1].central+8));
mutate('unsupported method',f=>f.bytes.writeUInt16LE(9,f.meta[1].central+10));
mutate('central extra ZIP64 metadata',f=>f.bytes.writeUInt16LE(20,f.meta[1].central+30));
mutate('central comment',f=>f.bytes.writeUInt16LE(1,f.meta[1].central+32));
mutate('entry disk',f=>f.bytes.writeUInt16LE(1,f.meta[1].central+34));
mutate('internal attrs',f=>f.bytes.writeUInt16LE(1,f.meta[1].central+36));
mutate('symlink type',f=>f.bytes.writeUInt32LE(0xa1ff0000,f.meta[1].central+38));
mutate('special device type',f=>f.bytes.writeUInt32LE(0x21a40000,f.meta[1].central+38));
mutate('unsafe privilege modes',f=>f.bytes.writeUInt32LE(0x89a40000,f.meta[1].central+38));
mutate('unknown low attrs',f=>f.bytes.writeUInt32LE(0x81a40020,f.meta[1].central+38));
mutate('local offset overlap',f=>f.bytes.writeUInt32LE(0,f.meta[1].central+42));
mutate('local gap',f=>f.bytes.writeUInt32LE(f.meta[1].local+1,f.meta[1].central+42));
mutate('local signature',f=>f.bytes.writeUInt32LE(0,f.meta[1].local));
mutate('local flag mismatch',f=>f.bytes.writeUInt16LE(0x800,f.meta[1].local+6));
mutate('local method mismatch',f=>f.bytes.writeUInt16LE(8,f.meta[1].local+8));
mutate('local timestamp mismatch',f=>f.bytes.writeUInt16LE(1,f.meta[1].local+10));
mutate('local CRC mismatch',f=>f.bytes.writeUInt32LE(1,f.meta[1].local+14));
mutate('local compressed length mismatch',f=>f.bytes.writeUInt32LE(1,f.meta[1].local+18));
mutate('local output length mismatch',f=>f.bytes.writeUInt32LE(1,f.meta[1].local+22));
mutate('local extra metadata',f=>f.bytes.writeUInt16LE(1,f.meta[1].local+28));
mutate('local name mismatch',f=>f.bytes[f.meta[1].local+30]=120);
mutate('CRC validated actual data',f=>f.bytes[f.meta[1].data]^=1);
mutate('shared forged CRC fails',f=>{f.bytes.writeUInt32LE(0,f.meta[1].local+14);f.bytes.writeUInt32LE(0,f.meta[1].central+16);});
mutate('ZIP64 entry sentinel',f=>f.bytes.writeUInt32LE(0xffffffff,f.meta[1].central+20));
test('deflate trailing bytes',()=>reject(fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'test',method:8,compressed:Buffer.concat([zlib.deflateRawSync(Buffer.from('test')),Buffer.from([0])])}])));
test('deflate output over declared bound',()=>{const f=fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'x',method:8,compressed:zlib.deflateRawSync(Buffer.alloc(1024,65))}]);reject(f);});
test('corrupt deflate',()=>reject(fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'x',method:8,compressed:Buffer.from([255,255])}])));
test('truncation every byte',()=>{const f=fixture();for(let i=0;i<f.bytes.length;i++)reject({...f,bytes:f.bytes.subarray(0,i)});});
test('trailing data',()=>{const f=fixture();f.bytes=Buffer.concat([f.bytes,Buffer.from([0])]);reject(f);});
test('prefix data',()=>{const f=fixture();f.bytes=Buffer.concat([Buffer.from([0]),f.bytes]);reject(f);});
for(const name of ['root/../a','/a','root\\a','C:/a','root/./a','root//a','root/a\0','root/a\n','root/a.','root/a '])test('reject path '+JSON.stringify(name),()=>reject(fixture([{name:'root/',data:'',dir:true},{name,data:'x'}])));
test('duplicate paths',()=>reject(fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'x'},{name:'root/a',data:'x'}])));
test('case collision',()=>reject(fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'x'},{name:'root/A',data:'x'}])));
test('ancestor file conflict',()=>reject(fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'x'},{name:'root/a/b',data:'x'}])));
test('missing explicit parent',()=>reject(fixture([{name:'root/',data:'',dir:true},{name:'root/a/b',data:'x'}])));
test('directory data forbidden',()=>reject(fixture([{name:'root/',data:'x',dir:true}])));
test('layout root mismatch',()=>{const f=fixture();f.manifest.roots=['other'];reject(f);});
test('incomplete expected tree',()=>{const f=fixture();f.manifest.entries.pop();reject(f);});
test('unexpected expected entry',()=>{const f=fixture();f.manifest.entries.push({...f.manifest.entries[1],path:'root/b'});reject(f);});
test('expected hash mismatch',()=>{const f=fixture();f.manifest.entries[1].sha256='0'.repeat(64);reject(f);});
test('expected mode mismatch',()=>{const f=fixture();f.manifest.entries[1].mode=493;reject(f);});
test('expected length mismatch',()=>{const f=fixture();f.manifest.entries[1].size++;reject(f);});
test('separate archive SHA pin',()=>{const f=fixture();reject(f,undefined,{length:f.bytes.length,sha256:'0'.repeat(64)});});
test('separate archive length pin',()=>{const f=fixture();reject(f,undefined,{length:f.bytes.length+1,sha256:sha(f.bytes)});});
for(const [k,v] of Object.entries({maxArchiveBytes:1,maxEntries:1,maxCompressedBytes:1,maxOutputBytes:1,maxFileBytes:1,maxPathBytes:1,maxDepth:1,maxJsonBytes:1}))test('caller cap '+k,()=>reject(fixture(),{...caps,[k]:v}));
test('compression ratio bound',()=>reject(fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'x'.repeat(500),method:8}]),{...caps,maxRatio:1}));
for(const k of Object.keys(caps))test('hard ceiling '+k,()=>reject(fixture(),{...caps,[k]:caps[k]+1}));
test('caps required',()=>assert.throws(()=>inspectZipBytes(fixture().bytes,'{}',undefined,'{}'),e=>e.message===ERROR));
test('getters not invoked',()=>{let invoked=false;const f=fixture(),o={get roots(){invoked=true;throw Error('getter');}};assert.throws(()=>inspectZipBytes(f.bytes,JSON.stringify({length:f.bytes.length,sha256:sha(f.bytes)}),JSON.stringify(caps),o),e=>e.message===ERROR);assert.equal(invoked,false);});
test('proxy config not inspected',()=>{const f=fixture(),p=new Proxy({}, {get(){throw Error('proxy');}});assert.throws(()=>inspectZipBytes(f.bytes,p,p,p),e=>e.message===ERROR);});
test('proxy buffer rejected',()=>assert.throws(()=>inspectZipBytes(new Proxy(Buffer.alloc(22),{}),'{}','{}','{}'),e=>e.message===ERROR));
test('duplicate decoded JSON keys',()=>{const f=fixture();const pin='{"length":'+f.bytes.length+',"leng\\u0074h":'+f.bytes.length+',"sha256":"'+sha(f.bytes)+'"}';assert.throws(()=>inspectZipBytes(f.bytes,pin,JSON.stringify(caps),JSON.stringify(f.manifest)),e=>e.message===ERROR);});
test('JSON depth bound',()=>assert.throws(()=>inspectZipBytes(fixture().bytes,'[]', '['.repeat(12)+'0'+']'.repeat(12),'{}'),e=>e.message===ERROR));
test('no accidental defaults',()=>reject(fixture(),{}));
test('duplicate byte names against distinct expected tree',()=>{const f=fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'x'},{name:'root/b',data:'x'}]);f.bytes.write('root/a',f.meta[2].local+30,'ascii');f.bytes.write('root/a',f.meta[2].central+46,'ascii');reject(f);});
test('actual SHA checked after consistent CRC substitution',()=>{const f=fixture();f.bytes[f.meta[1].data]^=1;const data=f.bytes.subarray(f.meta[1].data,f.meta[0].central);const value=crc(data);f.bytes.writeUInt32LE(value,f.meta[1].local+14);f.bytes.writeUInt32LE(value,f.meta[1].central+16);reject(f);});
test('ASCII UTF8 flag accepted consistently',()=>{const f=fixture();for(const e of f.meta){f.bytes.writeUInt16LE(0x800,e.local+6);f.bytes.writeUInt16LE(0x800,e.central+8);}inspect(f);});
test('explicit executable mode binding',()=>{const f=fixture();f.manifest.entries[1].mode=493;f.bytes.writeUInt32LE(0x81ed0000,f.meta[1].central+38);assert.equal(inspect(f).entries[1].mode,493);});
test('multiple exact layout roots including top-level file',()=>{const f=fixture([{name:'root/',data:'',dir:true},{name:'root/a',data:'x'},{name:'ffmpeg-linux',data:'opaque bytes'}]);f.manifest.roots.push('ffmpeg-linux');assert.equal(inspect(f).roots.length,2);});
test('ancestor spelling mismatch',()=>reject(fixture([{name:'root/',data:'',dir:true},{name:'root/A/',data:'',dir:true},{name:'root/a/b',data:'x'}])));
test('central entry order must match local contiguous order',()=>{const f=fixture();const first=f.bytes.subarray(f.meta[0].central,f.meta[1].central),second=f.bytes.subarray(f.meta[1].central,f.end);f.bytes=Buffer.concat([f.bytes.subarray(0,f.meta[0].central),second,first,f.bytes.subarray(f.end)]);reject(f);});
test('decorated Buffer properties never read',()=>{const f=fixture(),pin=JSON.stringify({length:f.bytes.length,sha256:sha(f.bytes)});let touches=0;for(const key of ['length','byteLength','byteOffset','buffer','copy','valueOf','constructor','subarray'])Object.defineProperty(f.bytes,key,{get(){touches++;throw Error('decorated');}});assert.equal(inspectZipBytes(f.bytes,pin,JSON.stringify(caps),JSON.stringify(f.manifest)).entries.length,2);assert.equal(touches,0);});
test('decorated length cannot bypass archive cap',()=>{const f=fixture(),pin=JSON.stringify({length:f.bytes.length,sha256:sha(f.bytes)});let touches=0;Object.defineProperty(f.bytes,'length',{get(){touches++;return 22;}});assert.throws(()=>inspectZipBytes(f.bytes,pin,JSON.stringify({...caps,maxArchiveBytes:22}),JSON.stringify(f.manifest)),e=>e.message===ERROR);assert.equal(touches,0);});
test('shared backing rejected',()=>{const f=fixture(),b=Buffer.from(new SharedArrayBuffer(f.bytes.length));b.set(f.bytes);assert.throws(()=>inspectZipBytes(b,JSON.stringify({length:f.bytes.length,sha256:sha(f.bytes)}),JSON.stringify(caps),JSON.stringify(f.manifest)),e=>e.message===ERROR);});
for(const literal of ['214.00000000000000000001','1e0','-0','9007199254740993'])test('source exact numeric reject '+literal,()=>{const f=fixture();assert.throws(()=>inspectZipBytes(f.bytes,'{"length":'+literal+',"sha256":"'+sha(f.bytes)+'"}',JSON.stringify(caps),JSON.stringify(f.manifest)),e=>e.message===ERROR);});
test('fractional cap cannot round into hard ceiling',()=>{const f=fixture(),p=JSON.stringify({length:f.bytes.length,sha256:sha(f.bytes)}),c=JSON.stringify(caps).replace('16777216','16777216.0000000001');assert.throws(()=>inspectZipBytes(f.bytes,p,c,JSON.stringify(f.manifest)),e=>e.message===ERROR);});
test('fractional manifest mode cannot round into mode',()=>{const f=fixture(),p=JSON.stringify({length:f.bytes.length,sha256:sha(f.bytes)}),m=JSON.stringify(f.manifest).replace('420','420.00000000000000001');assert.throws(()=>inspectZipBytes(f.bytes,p,JSON.stringify(caps),m),e=>e.message===ERROR);});
console.log('PASS '+count+' direct synthetic tests; elapsedMs='+ (Date.now()-start)+'; candidate only; no staging runtime');
