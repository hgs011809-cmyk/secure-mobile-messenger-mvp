'use strict';
// CANDIDATE ONLY. Narrow ZIP32 data parser, not vendor authentication, general
// ZIP compatibility, exploit-safe parsing or hostile-host containment. No I/O
// staging: this API returns an immutable byte/tree binding only. Unix regular
// files/directories only; archives containing legitimate symlinks are rejected.
const crypto=require('node:crypto'),zlib=require('node:zlib'),util=require('node:util');
const ERROR='INVALID_ZIP_BYTE_INVENTORY';
const HARD_CEILINGS=Object.freeze({maxArchiveBytes:16777216,maxEntries:512,maxCompressedBytes:16777216,maxOutputBytes:33554432,maxFileBytes:8388608,maxPathBytes:512,maxDepth:16,maxRatio:100,maxJsonBytes:262144});
function bad(){throw Error(ERROR);}
function hash(b){return crypto.createHash('sha256').update(b).digest('hex');}
function shape(o,keys){if(!o||typeof o!=='object'||Array.isArray(o)||Object.keys(o).length!==keys.length||keys.some(k=>!Object.hasOwn(o,k)))bad();}
function int(n){if(!Number.isSafeInteger(n)||n<0||Object.is(n,-0))bad();}
// Primitive JSON text prevents caller getters/proxies. Reject duplicate keys.
function json(t){
 if(typeof t!=='string'||t.length>HARD_CEILINGS.maxJsonBytes||Buffer.byteLength(t)>HARD_CEILINGS.maxJsonBytes)bad();
 const re=/\s*("(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|[{}\[\],:])/y;
 let pos=0,tokens=0;
 function next(){if(++tokens>40000)bad();re.lastIndex=pos;const m=re.exec(t);if(!m)bad();pos=re.lastIndex;return m[1];}
 function val(k,depth){if(depth>8)bad();if(k==='{'||k==='['){const obj=k==='{',end=obj?'}':']',seen=new Set();k=next();if(k===end)return;for(;;){if(obj){if(k[0]!=='"')bad();const name=JSON.parse(k);if(seen.has(name))bad();seen.add(name);if(next()!==':')bad();k=next();}val(k,depth+1);k=next();if(k===end)return;if(k!==',')bad();k=next();}}else {if(!/^(?:"|-?[0-9]|true$|false$|null$)/.test(k))bad();if(/^-?[0-9]/.test(k)&&(k.length>16||!/^(?:0|[1-9][0-9]*)$/.test(k)||BigInt(k)>BigInt(Number.MAX_SAFE_INTEGER)))bad();}}
 val(next(),0);if(t.substring(pos).trim())bad();return JSON.parse(t);
}
function pathCheck(p,c){if(typeof p!=='string'||!p||p.length>c.maxPathBytes||/[^\x21-\x7e]/.test(p)||/[\\:]/.test(p))bad();const a=p.split('/');if(a.length>c.maxDepth||a.some(x=>!x||x==='.'||x==='..'||x.length>255||/[. ]$/.test(x)))bad();return a;}
function inspectZipBytes(bytes,pinText,capsText,manifestText){try{
 if(util.types.isProxy(bytes)||!Buffer.isBuffer(bytes))bad();
 const c=json(capsText);shape(c,Object.keys(HARD_CEILINGS));for(const k of Object.keys(c)){int(c[k]);if(!c[k]||c[k]>HARD_CEILINGS[k])bad();}
 // Read internal typed-array slots, never decorated Buffer length/valueOf/copy.
 const typed=Object.getPrototypeOf(Uint8Array.prototype);
 const length=Object.getOwnPropertyDescriptor(typed,'length').get.call(bytes);
 const backing=Object.getOwnPropertyDescriptor(typed,'buffer').get.call(bytes);
 if(util.types.isSharedArrayBuffer(backing)||length>c.maxArchiveBytes||length<22)bad();
 const pin=json(pinText);shape(pin,['length','sha256']);int(pin.length);if(typeof pin.sha256!=='string'||! /^[a-f0-9]{64}$/.test(pin.sha256)||pin.length!==length)bad();
 const b=Buffer.alloc(length);Uint8Array.prototype.set.call(b,bytes);const archiveSha256=hash(b);if(archiveSha256!==pin.sha256)bad();
 const m=json(manifestText);if(Buffer.byteLength(manifestText)>c.maxJsonBytes||Buffer.byteLength(pinText)>c.maxJsonBytes||Buffer.byteLength(capsText)>c.maxJsonBytes)bad();shape(m,['roots','entries']);
 if(!Array.isArray(m.roots)||!m.roots.length||m.roots.length>c.maxEntries||!Array.isArray(m.entries)||!m.entries.length||m.entries.length>c.maxEntries)bad();
 const expected=new Map(),folded=new Set(),roots=new Set();
 for(const r of m.roots){if(pathCheck(r,c).length!==1||roots.has(r.toLowerCase()))bad();roots.add(r.toLowerCase());}
 for(const e of m.entries){shape(e,['path','type','mode','size','sha256']);const parts=pathCheck(e.path,c);if(folded.has(e.path.toLowerCase()))bad();folded.add(e.path.toLowerCase());if(!m.roots.includes(parts[0]))bad();int(e.size);int(e.mode);if(e.type!=='file'&&e.type!=='directory')bad();if(e.size>c.maxFileBytes||typeof e.sha256!=='string'||! /^[a-f0-9]{64}$/.test(e.sha256))bad();if(e.type==='directory'&&(e.size!==0||e.mode!==493||e.sha256!==hash(Buffer.alloc(0))))bad();if(e.type==='file'&&e.mode!==420&&e.mode!==493)bad();expected.set(e.path,e);}
 for(const e of m.entries){const a=e.path.split('/');for(let i=1;i<a.length;i++){const parent=expected.get(a.slice(0,i).join('/'));if(!parent||parent.type!=='directory')bad();}}
 for(const r of m.roots)if(!expected.has(r))bad();
 const end=b.length-22;const u16=o=>{if(o<0||o+2>b.length)bad();return b.readUInt16LE(o);},u32=o=>{if(o<0||o+4>b.length)bad();return b.readUInt32LE(o);};
 if(u32(end)!==0x06054b50||u16(end+4)||u16(end+6)||u16(end+20))bad();const n=u16(end+10),cdSize=u32(end+12),cdOff=u32(end+16);
 if(!n||n===65535||n>c.maxEntries||n!==u16(end+8)||n!==m.entries.length||cdSize===0xffffffff||cdOff===0xffffffff||cdOff+cdSize!==end)bad();
 let p=cdOff,localEnd=0,totalC=0,totalU=0;const seen=new Set(),entries=[];
 for(let i=0;i<n;i++){
  if(p+46>end||u32(p)!==0x02014b50||u16(p+4)!==0x0314||u16(p+6)!==20)bad();
  const flags=u16(p+8),method=u16(p+10),crc=u32(p+16),cs=u32(p+20),us=u32(p+24),nl=u16(p+28),extra=u16(p+30),comment=u16(p+32),attr=u32(p+38),off=u32(p+42);
  if((flags!==0&&flags!==0x800)||(method!==0&&method!==8)||extra||comment||u16(p+34)||u16(p+36)||!nl||nl>c.maxPathBytes+1||p+46+nl>end||cs===0xffffffff||us===0xffffffff||off===0xffffffff)bad();
  const raw=b.subarray(p+46,p+46+nl);if([...raw].some(x=>x<33||x>126))bad();const name=raw.toString('ascii'),isDir=name.endsWith('/'),namePath=isDir?name.substring(0,name.length-1):name;pathCheck(namePath,c);
  if(seen.has(namePath.toLowerCase()))bad();seen.add(namePath.toLowerCase());const e=expected.get(namePath);if(!e||e.type!==(isDir?'directory':'file'))bad();
  const mode=attr>>>16,type=mode&0xf000;if(type!==(isDir?0x4000:0x8000)||(mode&0x0fff)!==e.mode||(attr&0xffff)!==(isDir?0x10:0))bad();
  if(off!==localEnd||off+30>cdOff||u32(off)!==0x04034b50||u16(off+4)!==20||u16(off+6)!==flags||u16(off+8)!==method||u16(off+10)!==u16(p+12)||u16(off+12)!==u16(p+14)||u32(off+14)!==crc||u32(off+18)!==cs||u32(off+22)!==us||u16(off+26)!==nl||u16(off+28))bad();
  const start=off+30+nl;localEnd=start+cs;if(localEnd>cdOff||!b.subarray(off+30,start).equals(raw)||cs>c.maxFileBytes||us>c.maxFileBytes||us!==e.size||us>cs*c.maxRatio)bad();
  totalC+=cs;totalU+=us;if(totalC>c.maxCompressedBytes||totalU>c.maxOutputBytes)bad();
  if(isDir&&(method!==0||cs!==0||us!==0||crc!==0))bad();
  const compressed=b.subarray(start,localEnd);let out;
  if(method===0){if(cs!==us)bad();out=compressed;}else{const result=zlib.inflateRawSync(compressed,{maxOutputLength:Math.max(1,us),info:true});if(result.engine.bytesWritten!==cs)bad();out=result.buffer;}
  if(out.length!==us||crc32(out)!==crc||hash(out)!==e.sha256)bad();
  entries.push(Object.freeze({path:namePath,type:e.type,mode:e.mode,size:us,sha256:e.sha256,method,compressedBytes:cs}));p+=46+nl;
 }
 if(p!==end||localEnd!==cdOff||seen.size!==expected.size)bad();
 const bindingSha256=hash(Buffer.from(JSON.stringify({archiveSha256,length:b.length,roots:m.roots,entries})));
 return Object.freeze({candidateOnly:true,stagingImplemented:false,archiveSha256,length:b.length,bindingSha256,roots:Object.freeze([...m.roots]),entries:Object.freeze(entries),totalCompressedBytes:totalC,totalOutputBytes:totalU});
 }catch(_){throw Error(ERROR);}}
const table=new Uint32Array(256);for(let i=0;i<256;i++){let x=i;for(let j=0;j<8;j++)x=(x>>>1)^((x&1)?0xedb88320:0);table[i]=x>>>0;}
function crc32(b){let x=0xffffffff;for(const v of b)x=(x>>>8)^table[(x^v)&255];return (x^0xffffffff)>>>0;}
module.exports=Object.freeze({inspectZipBytes,HARD_CEILINGS,ERROR});
