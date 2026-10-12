'use strict';
// Direct synthetic spec. No subprocess, network, install, CI, container, shell
// payload or executable extracted content. Invoke directly with external <=60s
// deadline. Linux runtime tests NEVER count as skipped passes on Windows.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os');
const path=require('node:path'),crypto=require('node:crypto'),zlib=require('node:zlib');
const {stageZipBytes,validateStagingInput,ERROR}=require('./zip-safe-staging.cjs');
const {HARD_CEILINGS}=require('./zip-byte-inventory.cjs');
const {performance}=require('node:perf_hooks');
const start=performance.now();let pure=0,runtime=0;
function deadline(){if(performance.now()-start>55000)throw Error('SPEC_DEADLINE');}
function test(name,fn,linux=false){deadline();fn();deadline();if(linux)runtime++;else pure++;console.log('ok '+(linux?'linux':'pure')+' '+name);}
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function crc(b){let x=0xffffffff;for(const v of b){x^=v;for(let i=0;i<8;i++)x=(x>>>1)^((x&1)?0xedb88320:0);}return (x^0xffffffff)>>>0;}
function fixture(method=0){
 const items=[{name:'root/',data:'',dir:true},{name:'root/sub/',data:'',dir:true},{name:'root/sub/data',data:'synthetic bounded bytes',method},{name:'root/empty',data:''},{name:'root/executable-name',data:'opaque non-program synthetic bytes',mode:493,method}];
 const locals=[],centrals=[],entries=[];let offset=0;
 for(const e of items){const data=Buffer.from(e.data),name=Buffer.from(e.name),m=e.method||0,compressed=m===8?zlib.deflateRawSync(data):data,l=Buffer.alloc(30),c=Buffer.alloc(46),mode=e.mode||(e.dir?493:420);
  l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt16LE(m,8);l.writeUInt32LE(crc(data),14);l.writeUInt32LE(compressed.length,18);l.writeUInt32LE(data.length,22);l.writeUInt16LE(name.length,26);
  c.writeUInt32LE(0x02014b50);c.writeUInt16LE(0x0314,4);c.writeUInt16LE(20,6);c.writeUInt16LE(m,10);c.writeUInt32LE(crc(data),16);c.writeUInt32LE(compressed.length,20);c.writeUInt32LE(data.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE((((e.dir?0x4000:0x8000)|mode)*65536+(e.dir?16:0))>>>0,38);c.writeUInt32LE(offset,42);
  locals.push(l,name,compressed);centrals.push(c,name);offset+=30+name.length+compressed.length;
  entries.push({path:e.dir?e.name.slice(0,-1):e.name,type:e.dir?'directory':'file',mode,size:data.length,sha256:sha(data)});
 }
 const cd=Buffer.concat(centrals),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(items.length,8);end.writeUInt16LE(items.length,10);end.writeUInt32LE(cd.length,12);end.writeUInt32LE(offset,16);
 const bytes=Buffer.concat([...locals,cd,end]),manifest={roots:['root'],entries};return {bytes,pin:JSON.stringify({length:bytes.length,sha256:sha(bytes)}),caps:JSON.stringify(HARD_CEILINGS),manifest:JSON.stringify(manifest),items};
}
function validate(f){return validateStagingInput(f.bytes,f.pin,f.caps,f.manifest);}
function stage(f,parent){return stageZipBytes(f.bytes,f.pin,f.caps,f.manifest,parent);}
const rejected=fn=>assert.throws(fn,e=>e.message===ERROR);
for(const method of [0,8])test('full archive and manifest binding method '+method,()=>{const f=fixture(method),r=validate(f);assert.equal(r.entries.length,5);assert.equal(r.archiveSha256,sha(f.bytes));assert(Object.isFrozen(r.entries));});
test('detached inventory cannot substitute archive',()=>{const f=fixture();f.bytes=validate(f);rejected(()=>validate(f));});
test('decorated internal typed-array slots snapshot',()=>{const f=fixture();let calls=0;for(const k of ['length','buffer','byteOffset','byteLength','copy','subarray','valueOf','constructor'])Object.defineProperty(f.bytes,k,{get(){calls++;throw Error('getter');}});assert.equal(validate(f).entries.length,5);assert.equal(calls,0);});
test('object JSON getters untouched',()=>{const f=fixture();let calls=0;f.manifest={get roots(){calls++;throw Error('getter');}};rejected(()=>validate(f));assert.equal(calls,0);});
test('shared input rejected',()=>{const f=fixture(),b=Buffer.from(new SharedArrayBuffer(f.bytes.length));b.set(f.bytes);f.bytes=b;rejected(()=>validate(f));});
test('proxy Buffer rejected',()=>{const f=fixture();f.bytes=new Proxy(f.bytes,{});rejected(()=>validate(f));});
test('mismatched archive pin rejected',()=>{const f=fixture();f.bytes[30]^=1;rejected(()=>validate(f));});
test('full manifest hash binding',()=>{const f=fixture(),m=JSON.parse(f.manifest);m.entries[2].sha256='0'.repeat(64);f.manifest=JSON.stringify(m);rejected(()=>validate(f));});
test('manifest extras rejected',()=>{const f=fixture(),m=JSON.parse(f.manifest);m.entries.push({...m.entries[2],path:'root/extra'});f.manifest=JSON.stringify(m);rejected(()=>validate(f));});
test('path traversal rejected',()=>{const f=fixture(),m=JSON.parse(f.manifest);m.entries[2].path='root/../escape';f.manifest=JSON.stringify(m);rejected(()=>validate(f));});
for(const k of Object.keys(HARD_CEILINGS))test('hard ceiling '+k,()=>{const f=fixture();f.caps=JSON.stringify({...HARD_CEILINGS,[k]:HARD_CEILINGS[k]+1});rejected(()=>validate(f));});
test('caller archive cap enforced',()=>{const f=fixture();f.caps=JSON.stringify({...HARD_CEILINGS,maxArchiveBytes:22});rejected(()=>validate(f));});
test('archive symlink or hardlink-like Unix type rejected',()=>{for(const attr of [0xa1ff0000,0x21a40000]){const f=fixture();const cd=f.bytes.readUInt32LE(f.bytes.length-6);f.bytes.writeUInt32LE(attr,cd+38);f.pin=JSON.stringify({length:f.bytes.length,sha256:sha(f.bytes)});rejected(()=>validate(f));}});
// Explicit list includes injected single-owner synthetic faults, not proof of
// hostile races or general filesystem safety. No production mutation hooks.
const linuxTests=[
 ['stored and deflated complete tree modes/digests',parent=>{for(const m of [0,8]){const f=fixture(m),r=stage(f,parent);assert.equal(r.archiveSha256,sha(f.bytes));assert.equal(r.bindingSha256,validate(f).bindingSha256);assert.equal(fs.statSync(r.root).mode&0o7777,0o700);const expected=JSON.parse(f.manifest).entries,seen=[];function walk(p,prefix=''){for(const name of fs.readdirSync(p)){const key=prefix?prefix+'/'+name:name,s=fs.lstatSync(path.join(p,name));seen.push(key);const e=expected.find(e=>e.path===key);assert(e);assert.equal(s.uid,process.getuid());assert.equal(s.mode&0o7777,e.mode);if(s.isDirectory())walk(path.join(p,name),key);else{assert(s.isFile());assert.equal(s.nlink,1);assert.equal(s.size,e.size);assert.equal(sha(fs.readFileSync(path.join(p,name))),e.sha256);}}}walk(r.root);assert.deepEqual(seen.sort(),expected.map(e=>e.path).sort());assert(Object.isFrozen(r));}}],
 ['second-pass directory mutation after readdir rejected',parent=>{const original=fs.readdirSync;let rootReads=0,changed=false;fs.readdirSync=(p,...args)=>{const names=original(p,...args);if(path.basename(p).startsWith('zip-stage-')&&++rootReads===2){fs.writeFileSync(path.join(p,'late-extra'),'synthetic',{mode:0o600});changed=true;}return names;};try{rejected(()=>stage(fixture(),parent));assert(changed);}finally{fs.readdirSync=original;}}],
 ['wrong parent permissions',parent=>{fs.chmodSync(parent,0o755);try{rejected(()=>stage(fixture(),parent));}finally{fs.chmodSync(parent,0o700);}}],
 ['parent symlink rejected',parent=>{const link=path.join(parent,'alias');fs.symlinkSync(parent,link);rejected(()=>stage(fixture(),link));}],
 ['missing, relative, file and parent getter rejected',parent=>{const file=path.join(parent,'plain');fs.writeFileSync(file,'synthetic',{mode:0o600});for(const p of ['relative',path.join(parent,'missing'),file])rejected(()=>stage(fixture(),p));let n=0;rejected(()=>stage(fixture(),{get path(){n++;}}));assert.equal(n,0);}],
 ['existing roots not reused',parent=>{const f=fixture(),a=stage(f,parent),b=stage(f,parent);assert.notEqual(a.root,b.root);assert.equal(sha(fs.readFileSync(path.join(a.root,'root/sub/data'))),JSON.parse(f.manifest).entries[2].sha256);}],
 ['mkdtemp existing-stage fault fails closed',parent=>{const existing=path.join(parent,'existing');fs.mkdirSync(existing,{mode:0o700});fs.writeFileSync(path.join(existing,'preserved'),'unchanged',{mode:0o600});const original=fs.mkdtempSync;fs.mkdtempSync=()=>existing;try{rejected(()=>stage(fixture(),parent));assert.equal(fs.readFileSync(path.join(existing,'preserved'),'utf8'),'unchanged');assert(!fs.existsSync(path.join(existing,'root')));}finally{fs.mkdtempSync=original;}}],
 ['injected extra file detected; failed root preserved',parent=>{const original=fs.mkdtempSync;let failed;fs.mkdtempSync=(...args)=>{failed=original(...args);fs.writeFileSync(path.join(failed,'extra'),'synthetic',{mode:0o600});return failed;};try{rejected(()=>stage(fixture(),parent));assert.equal(fs.statSync(failed).mode&0o7777,0o700);assert(fs.existsSync(path.join(failed,'extra')));}finally{fs.mkdtempSync=original;}}],
 ['injected hardlink detected',parent=>{const original=fs.fchmodSync;let linked=false;fs.fchmodSync=(fd,mode)=>{original(fd,mode);const p=fs.readlinkSync('/proc/self/fd/'+fd);if(!linked&&fs.fstatSync(fd).isFile()){linked=true;fs.linkSync(p,path.join(path.dirname(p),'hardlink'));}};try{rejected(()=>stage(fixture(),parent));assert(linked);}finally{fs.fchmodSync=original;}}],
 ['injected symlink replacement detected',parent=>{const original=fs.fchmodSync;let changed=false;fs.fchmodSync=(fd,mode)=>{original(fd,mode);const p=fs.readlinkSync('/proc/self/fd/'+fd);if(!changed&&fs.fstatSync(fd).isFile()){changed=true;fs.unlinkSync(p);fs.symlinkSync('/nonexistent-synthetic-target',p);}};try{rejected(()=>stage(fixture(),parent));assert(changed);}finally{fs.fchmodSync=original;}}],
 ['same-size retained-FD mutation detected',parent=>{const original=fs.readSync;let changed=false;fs.readSync=(fd,buffer,offset,length,position)=>{if(!changed&&length){changed=true;fs.writeSync(fd,Buffer.from('X'),0,1,0);}return original(fd,buffer,offset,length,position);};try{rejected(()=>stage(fixture(),parent));assert(changed);}finally{fs.readSync=original;}}],
 ['wrong UID check fault rejected',parent=>{const original=fs.fstatSync;fs.fstatSync=(...args)=>{const s=original(...args);s.uid=process.getuid()+1;return s;};try{rejected(()=>stage(fixture(),parent));}finally{fs.fstatSync=original;}}],
 ['exclusive file creation collision fails',parent=>{const original=fs.openSync;let collided=false;fs.openSync=(p,flags,mode)=>{if(!collided&&(flags&fs.constants.O_CREAT)){collided=true;fs.writeFileSync(p,'preexisting synthetic',{mode:0o600});}return original(p,flags,mode);};try{rejected(()=>stage(fixture(),parent));assert(collided);}finally{fs.openSync=original;}}]
];
if(process.platform!=='linux'){
 test('unsupported platform fixed failure no getters',()=>{let touched=0;const p=new Proxy({}, {get(){touched++;throw Error('getter');}});rejected(()=>stageZipBytes(p,p,p,p,p));assert.equal(touched,0);});
 console.log('NOT EXECUTED: '+linuxTests.length+' Linux runtime tests on '+process.platform+'; not counted as passes.');
}else{
 // Only Linux direct spec creates an auto-owned private temporary parent.
 // Roots are intentionally retained as synthetic evidence, no cleanup claim.
 const parent=fs.mkdtempSync(path.join(os.tmpdir(),'zip-safe-spec-'));assert.equal(fs.lstatSync(parent).uid,process.getuid());assert.equal(fs.lstatSync(parent).mode&0o7777,0o700);
 console.log('Synthetic evidence parent retained: '+parent);
 for(const [name,fn] of linuxTests)test(name,()=>fn(parent),true);
}
deadline();
console.log('RESULT purePassed='+pure+' linuxRuntimePassed='+runtime+' linuxRuntimeNotExecuted='+(process.platform==='linux'?0:linuxTests.length)+' elapsedMs='+Math.round(performance.now()-start)+'; no payload executed; candidate only');
