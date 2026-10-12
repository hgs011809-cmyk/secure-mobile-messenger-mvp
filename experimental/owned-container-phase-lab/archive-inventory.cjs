'use strict';
// Experimental JSON claims only. No ZIP parser, extractor, byte binding or gate pass.
// Accept primitive JSON text only; caller getters/proxies are never inspected.
// Synthetic defaults are NOT independently reviewed acquisition caps.
const DEFAULT_CAPS=Object.freeze({maxEntries:10000,maxTotalCompressedBytes:268435456,maxTotalUncompressedBytes:1073741824,maxFileBytes:134217728,maxCompressionRatio:100});
const SCHEMA=Object.freeze({manifest:Object.freeze(['entries']),entry:Object.freeze(['path','type','compressedBytes','uncompressedBytes']),caps:Object.freeze(Object.keys(DEFAULT_CAPS))});
const ERROR='INVALID_ARCHIVE_INVENTORY';
// Reject duplicate decoded member names before JSON.parse can discard them.
function parse(t){
 if(typeof t!=='string'||t.length>16777216)throw Error(ERROR);
 const token=/\s*("(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|[{}\[\],:])/y;
 let pos=0,n=0;function next(){if(++n>200000)throw Error(ERROR);token.lastIndex=pos;const m=token.exec(t);if(!m)throw Error(ERROR);pos=token.lastIndex;return m[1];}
 function value(first,depth){if(depth>8)throw Error(ERROR);if(first==='{'||first==='['){const object=first==='{',end=object?'}':']',seen=new Set();let k=next();if(k===end)return;for(;;){if(object){if(k[0]!=='"')throw Error(ERROR);const name=JSON.parse(k);if(seen.has(name))throw Error(ERROR);seen.add(name);if(next()!==':')throw Error(ERROR);k=next();}value(k,depth+1);k=next();if(k===end)return;if(k!==',')throw Error(ERROR);k=next();}}else {if(!/^(?:"|-?[0-9]|true$|false$|null$)/.test(first))throw Error(ERROR);if(/^-?[0-9]/.test(first)&&(first.length>16||!/^(?:0|[1-9][0-9]*)$/.test(first)||BigInt(first)>BigInt(Number.MAX_SAFE_INTEGER)))throw Error(ERROR);}}
 value(next(),0);if(t.substring(pos).trim()!=='')throw Error(ERROR);return JSON.parse(t);
}
function shape(o,k){if(!o||typeof o!=='object'||Array.isArray(o)||Object.keys(o).length!==k.length||k.some(x=>!Object.hasOwn(o,x)))throw Error(ERROR);}
function integer(n){if(!Number.isSafeInteger(n)||n<0||Object.is(n,-0))throw Error(ERROR);}
function validateInventory(text,capsText){try{
 const m=parse(text),c=capsText===undefined?DEFAULT_CAPS:parse(capsText);
 shape(m,SCHEMA.manifest);shape(c,SCHEMA.caps);
 for(const k of SCHEMA.caps){integer(c[k]);if(!c[k])throw Error(ERROR);}
 if(!Array.isArray(m.entries)||!m.entries.length||m.entries.length>c.maxEntries||m.entries.length>10000)throw Error(ERROR);
 const paths=new Map(),spellings=new Map();let totalC=0n,totalU=0n;
 for(const e of m.entries){
  shape(e,SCHEMA.entry);
  if(typeof e.path!=='string'||!e.path||e.path.length>1024||/[^\x20-\x7e]/.test(e.path)||/[\\:]/.test(e.path))throw Error(ERROR);
  const parts=e.path.split('/');if(parts.length>32||parts.some(p=>!p||p.length>255||p==='.'||p==='..'))throw Error(ERROR);
  if(e.type!=='file'&&e.type!=='directory')throw Error(ERROR);
  integer(e.compressedBytes);integer(e.uncompressedBytes);
  if(e.type==='directory'&&(e.compressedBytes||e.uncompressedBytes))throw Error(ERROR);
  if(e.compressedBytes>c.maxFileBytes||e.uncompressedBytes>c.maxFileBytes)throw Error(ERROR);
  const cb=BigInt(e.compressedBytes),ub=BigInt(e.uncompressedBytes);
  if(ub>cb*BigInt(c.maxCompressionRatio))throw Error(ERROR);
  totalC+=cb;totalU+=ub;
  if(totalC>BigInt(c.maxTotalCompressedBytes)||totalU>BigInt(c.maxTotalUncompressedBytes))throw Error(ERROR);
  const key=e.path.toLowerCase();if(paths.has(key))throw Error(ERROR);paths.set(key,e.type);
  for(let i=1;i<=parts.length;i++){
   const literal=parts.slice(0,i).join('/'),fold=literal.toLowerCase();
   if(spellings.has(fold)&&spellings.get(fold)!==literal)throw Error(ERROR);spellings.set(fold,literal);
  }
 }
 for(const e of m.entries){const parts=e.path.toLowerCase().split('/');for(let i=1;i<parts.length;i++)if(paths.get(parts.slice(0,i).join('/'))==='file')throw Error(ERROR);}
 return true;
}catch(_){throw Error(ERROR);}}
module.exports=Object.freeze({validateInventory,DEFAULT_CAPS,SCHEMA,ERROR});