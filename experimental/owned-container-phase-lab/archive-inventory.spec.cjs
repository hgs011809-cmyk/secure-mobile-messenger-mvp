'use strict';
const assert=require('node:assert/strict');
const {validateInventory:v,DEFAULT_CAPS,SCHEMA,ERROR}=require('./archive-inventory.cjs');
let count=0;
const caps={maxEntries:3,maxTotalCompressedBytes:10,maxTotalUncompressedBytes:20,maxFileBytes:10,maxCompressionRatio:2};
const f=(path='a',compressedBytes=1,uncompressedBytes=1)=>({path,type:'file',compressedBytes,uncompressedBytes});
const d=path=>({path,type:'directory',compressedBytes:0,uncompressedBytes:0});
const j=e=>JSON.stringify({entries:e});
function ok(e,c=caps){count++;assert.equal(v(j(e),JSON.stringify(c)),true);}
function badRaw(m,c=JSON.stringify(caps)){count++;assert.throws(()=>v(m,c),e=>e.constructor===Error&&e.message===ERROR);}
function bad(e,c=caps){badRaw(j(e),JSON.stringify(c));}
bad([]);ok([f()]);ok([d('a'),f('a/b')]);ok([f('a/b'),d('a')]);ok([f('a',10,20)],{...caps,maxFileBytes:20});ok([f('a',0,0)]);ok([d('a'),d('b'),d('c')]);
bad([f('a',11,1)]);bad([f('a',1,11)]);bad([f('a',1,3)]);bad([f('a',0,1)]);bad([f('a',6,6),f('b',5,5)]);bad([f('a',5,10),f('b',5,10)],{...caps,maxTotalUncompressedBytes:19});bad([d('a'),d('b'),d('c'),d('d')]);
for(const p of ['', '.', '..','/a','a/','a//b','./a','a/../b','a/./b','C:/a','C:a','a\\b','\\server\\x','a\u0000b','a\nb','a\tb','a\x7fb','é','a:stream'])bad([f(p)]);
for(const type of ['symlink','hardlink','fifo','socket','device','regular','dir',null,1])bad([{...f(),type}]);
for(const n of [-1,0.5,Number.MAX_SAFE_INTEGER+1,'1',null,true])for(const k of ['compressedBytes','uncompressedBytes'])bad([{...f(),[k]:n}]);
badRaw('{"entries":[{"path":"a","type":"file","compressedBytes":1e400,"uncompressedBytes":1}]}');
for(const e of [[f('a'),f('a')],[f('A'),f('a')],[d('a'),f('a')],[f('a'),f('a/b')],[f('a/b'),f('a')],[f('A'),f('a/b')],[f('A/x'),f('a/y')],[d('A'),f('a/x')],[f('a/x'),d('A')]])bad(e);
bad([{...d('a'),compressedBytes:1}]);bad([{...d('a'),uncompressedBytes:1}]);bad([{...f(),extra:1}]);bad([{path:'a',type:'file',compressedBytes:1}]);bad([null]);bad([[]]);
for(const m of ['null','[]','{}','{"entries":{}}','{"entries":[],"extra":1}','bad','{"__proto__":{},"entries":[]}'])badRaw(m);
for(const k of Object.keys(caps)){const c={...caps};delete c[k];badRaw(j([f()]),JSON.stringify(c));for(const n of [0,-1,0.5,'1',null,Number.MAX_SAFE_INTEGER+1])badRaw(j([f()]),JSON.stringify({...caps,[k]:n}));}
badRaw(j([f()]),JSON.stringify({...caps,extra:1}));badRaw(j([f()]),'null');badRaw(j([f()]),'bad');
let touches=0;const hostile=new Proxy({},{get(){touches++;throw Error('get');},ownKeys(){touches++;throw Error('keys');},getPrototypeOf(){touches++;throw Error('proto');}});
badRaw(hostile);badRaw(j([]),hostile);badRaw({get entries(){touches++;throw Error('getter');}});count++;assert.equal(touches,0);
const original=Object.freeze({entries:Object.freeze([Object.freeze(f())])});const text=JSON.stringify(original),ct=JSON.stringify(caps);count++;assert.equal(v(text,ct),true);count++;assert.equal(JSON.stringify(original),text);count++;assert.equal(JSON.stringify(caps),ct);
count++;assert.equal(v(j([f()])),true);count++;assert.ok(Object.isFrozen(DEFAULT_CAPS)&&Object.isFrozen(SCHEMA)&&Object.values(SCHEMA).every(Object.isFrozen));
const large={maxEntries:3,maxTotalCompressedBytes:Number.MAX_SAFE_INTEGER,maxTotalUncompressedBytes:Number.MAX_SAFE_INTEGER,maxFileBytes:Number.MAX_SAFE_INTEGER,maxCompressionRatio:Number.MAX_SAFE_INTEGER};
ok([f('a',Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER)],large);bad([f('a',Number.MAX_SAFE_INTEGER,0),f('b',1,0)],large);ok([f('a',1,Number.MAX_SAFE_INTEGER)],large);
badRaw(' '.repeat(16777217));
for(const raw of ['{"entries":[],"entries":[{"path":"a","type":"file","compressedBytes":1,"uncompressedBytes":1}]}','{"entries":[{"path":"a","p\\u0061th":"b","type":"file","compressedBytes":1,"uncompressedBytes":1}]}'])badRaw(raw);
badRaw(j([f()]),'{"maxEntries":3,"maxEntries":4,"maxTotalCompressedBytes":10,"maxTotalUncompressedBytes":20,"maxFileBytes":10,"maxCompressionRatio":2}');
bad([f('a'.repeat(256))]);bad([f(Array(33).fill('a').join('/'))]);bad([f(Array(5).fill('a'.repeat(255)).join('/'))]);
badRaw('['.repeat(10)+'0'+']'.repeat(10));
count++;assert.equal(v(' { "entries" : [ { "path" : "a", "type":"file", "compressedBytes":1,"uncompressedBytes":1 } ] } ',JSON.stringify(caps)),true);
for(const numeric of ['0.99999999999999999','1.0000000000000001','1e0','1.0','-0','9007199254740993'])badRaw('{"entries":[{"path":"a","type":"file","compressedBytes":'+numeric+',"uncompressedBytes":1}]}');
ok([f('a'.repeat(255))]);ok([f(Array(32).fill('a').join('/'))]);ok([f('a'.repeat(255)+'/'+ 'b'.repeat(255)+'/'+ 'c'.repeat(255)+'/'+ 'd'.repeat(254)+'/e')]);
console.log('PASS '+count+' synthetic checks; JSON claims only, no ZIP bytes/extraction/gate acceptance.');