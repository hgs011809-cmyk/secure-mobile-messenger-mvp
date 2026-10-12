'use strict';
// CANDIDATE ONLY: synthetic, local Linux, trusted single-owner parent scope.
// No hostile-host/atomic containment/openat promise, provenance, build acceptance,
// payload execution or physical erasure claim. Failures preserve new private
// roots as evidence; no failure returns a stage path. Owner can enumerate them.
// 55s cooperative deadline between bounded synchronous local operations does
// not cancel a stalled kernel syscall. No detached inventory is accepted.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const zlib=require('node:zlib'),util=require('node:util');
const {inspectZipBytes,HARD_CEILINGS}=require('./zip-byte-inventory.cjs');
const {performance}=require('node:perf_hooks');
const ERROR='INVALID_ZIP_SAFE_STAGING';
function bad(){throw Error(ERROR);}
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function bound(bytes,pin,caps,manifest){
 if(util.types.isProxy(bytes)||!Buffer.isBuffer(bytes))bad();
 const t=Object.getPrototypeOf(Uint8Array.prototype);
 const length=Object.getOwnPropertyDescriptor(t,'length').get.call(bytes);
 const backing=Object.getOwnPropertyDescriptor(t,'buffer').get.call(bytes);
 if(util.types.isSharedArrayBuffer(backing)||length<22||length>HARD_CEILINGS.maxArchiveBytes)bad();
 const b=Buffer.alloc(length);Uint8Array.prototype.set.call(b,bytes);
 const inventory=inspectZipBytes(b,pin,caps,manifest);
 return {b,inventory};
}
function validateStagingInput(bytes,pin,caps,manifest){try{return bound(bytes,pin,caps,manifest).inventory;}catch(_){bad();}}
function stageZipBytes(bytes,pin,caps,manifest,parent){
 const fds=[];const start=performance.now();
 function tick(){if(performance.now()-start>55000)bad();}
 try {
  if(process.platform!=='linux'||typeof process.getuid!=='function')bad();
  const C=fs.constants,uid=process.getuid();
  for(const k of ['O_NOFOLLOW','O_NONBLOCK','O_DIRECTORY','O_EXCL','O_CREAT'])if(!Number.isSafeInteger(C[k])||C[k]===0)bad();
  if(typeof parent!=='string'||parent.length>4096||parent.includes('\0')||!path.isAbsolute(parent)||path.normalize(parent)!==parent||parent==='/')bad();
  const {b,inventory}=bound(bytes,pin,caps,manifest);tick();
  // Equality rejects ancestor aliases, not atomic path resolution races.
  if(fs.realpathSync(parent)!==parent)bad();
  function own(s,kind,mode){if(s.uid!==uid||(s.mode&0o7777)!==mode||s.isSymbolicLink()||!(kind==='directory'?s.isDirectory():s.isFile()))bad();if(kind==='file'&&s.nlink!==1)bad();if(kind==='directory'&&(!Number.isSafeInteger(s.nlink)||s.nlink<2||s.nlink>HARD_CEILINGS.maxEntries+2))bad();}
  function identity(a,b){if(a.dev!==b.dev||a.ino!==b.ino||a.uid!==b.uid||a.gid!==b.gid||a.mode!==b.mode||a.nlink!==b.nlink)bad();}
  function openDir(p,mode){tick();const before=fs.lstatSync(p);own(before,'directory',mode);const fd=fs.openSync(p,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW|C.O_NONBLOCK);fds.push(fd);const after=fs.fstatSync(fd);own(after,'directory',mode);identity(before,after);identity(after,fs.lstatSync(p));return {p,fd,kind:'directory',mode};}
  const parentNode=openDir(parent,0o700),parentBefore=fs.fstatSync(parentNode.fd);
  const root=fs.mkdtempSync(path.join(parent,'zip-stage-'));
  const rootNode=openDir(root,0o700),nodes=new Map();
  const parentAfter=fs.fstatSync(parentNode.fd);own(parentAfter,'directory',0o700);
  if(parentAfter.dev!==parentBefore.dev||parentAfter.ino!==parentBefore.ino||parentAfter.gid!==parentBefore.gid||parentAfter.nlink!==parentBefore.nlink+1)bad();
  identity(parentAfter,fs.lstatSync(parent));
  const entries=[...inventory.entries].sort((a,b)=>a.path.split('/').length-b.path.split('/').length||a.path.localeCompare(b.path));
  // Re-derive only inspector-validated contiguous local slices on private copy.
  const decoded=new Map();let offset=0,total=0;
  for(const e of inventory.entries){tick();const nl=b.readUInt16LE(offset+26),pos=offset+30+nl;
   const raw=b.subarray(pos,pos+e.compressedBytes);
   const out=e.method===0?Buffer.from(raw):zlib.inflateRawSync(raw,{maxOutputLength:Math.max(1,e.size)});
   if(out.length!==e.size||sha(out)!==e.sha256)bad();total+=out.length;if(total>HARD_CEILINGS.maxOutputBytes)bad();decoded.set(e.path,out);offset=pos+e.compressedBytes;
  }
  function anchored(){tick();own(fs.fstatSync(parentNode.fd),'directory',0o700);identity(parentAfter,fs.fstatSync(parentNode.fd));identity(parentAfter,fs.lstatSync(parent));own(fs.fstatSync(rootNode.fd),'directory',0o700);identity(fs.fstatSync(rootNode.fd),fs.lstatSync(root));}
  for(const e of entries){anchored();const p=path.join(root,e.path),parentPath=path.dirname(e.path);if(parentPath!=='.'){const n=nodes.get(parentPath);if(!n||n.kind!=='directory')bad();identity(fs.fstatSync(n.fd),fs.lstatSync(n.p));}
   if(e.type==='directory'){fs.mkdirSync(p,{mode:0o700});nodes.set(e.path,openDir(p,0o700));}
   else {const fd=fs.openSync(p,C.O_RDWR|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW|C.O_NONBLOCK,0o600);fds.push(fd);const n={p,fd,kind:'file',mode:0o600};own(fs.fstatSync(fd),'file',0o600);identity(fs.fstatSync(fd),fs.lstatSync(p));const data=decoded.get(e.path);let done=0;while(done<data.length){tick();const wrote=fs.writeSync(fd,data,done,data.length-done,done);if(wrote<=0)bad();done+=wrote;}fs.fsyncSync(fd);nodes.set(e.path,n);}
  }
  for(const e of entries){tick();const n=nodes.get(e.path);own(fs.fstatSync(n.fd),n.kind,n.mode);identity(fs.fstatSync(n.fd),fs.lstatSync(n.p));fs.fchmodSync(n.fd,e.mode);n.mode=e.mode;}
  const expected=new Map(entries.map(e=>[e.path,e]));
  function checkTree(){anchored();let visited=0;const baselines=new Map();
   function check(n,key){tick();const e=key?expected.get(key):null,s=fs.fstatSync(n.fd);own(s,n.kind,n.mode);identity(s,fs.lstatSync(n.p));
    if(n.kind==='file'){if(s.size!==e.size)bad();const data=Buffer.alloc(e.size);let done=0;while(done<data.length){tick();const got=fs.readSync(n.fd,data,done,data.length-done,done);if(got<=0)bad();done+=got;}if(sha(data)!==e.sha256)bad();const after=fs.fstatSync(n.fd);identity(s,after);if(s.size!==after.size||s.mtimeMs!==after.mtimeMs||s.ctimeMs!==after.ctimeMs)bad();}
    else {const names=fs.readdirSync(n.p);if(names.length>HARD_CEILINGS.maxEntries)bad();let dirs=0;for(const name of names){const child=key?key+'/'+name:name;const ce=expected.get(child),cn=nodes.get(child);if(!ce||!cn)bad();if(++visited>expected.size)bad();if(ce.type==='directory')dirs++;check(cn,child);}if(s.nlink!==2+dirs)bad();}
    const fresh=fs.fstatSync(n.fd);identity(s,fresh);if(s.size!==fresh.size||s.mtimeMs!==fresh.mtimeMs||s.ctimeMs!==fresh.ctimeMs)bad();identity(fresh,fs.lstatSync(n.p));baselines.set(key,fresh);
   }
   check(rootNode,'');if(visited!==expected.size)bad();return baselines;
  }
  const before=checkTree(),after=checkTree();
  for(const [key,s] of before){const a=after.get(key);identity(s,a);if(s.size!==a.size||s.mtimeMs!==a.mtimeMs||s.ctimeMs!==a.ctimeMs)bad();}
  anchored();tick();while(fds.length){fs.closeSync(fds[fds.length-1]);fds.pop();}tick();
  return Object.freeze({candidateOnly:true,stagingImplemented:true,root,archiveSha256:inventory.archiveSha256,bindingSha256:inventory.bindingSha256,entries:inventory.entries});
 }catch(_){for(const fd of fds){try{fs.closeSync(fd);}catch(_){}}bad();}
}
module.exports=Object.freeze({stageZipBytes,validateStagingInput,ERROR});
