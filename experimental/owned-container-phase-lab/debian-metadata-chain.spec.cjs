'use strict';
// Synthetic parser tests. No real signature verification, trust or archive claim.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const fs=require('node:fs');
const {verifyChain:v,LIMITS,ERROR}=require('./debian-metadata-chain.cjs');
const H=b=>createHash('sha256').update(b).digest('hex');
const primary='A'.repeat(40),signing='B'.repeat(40),now=Date.UTC(2026,9,13,12)/1000;
const p={allowedPrimaryFingerprints:[primary],allowedSigningFingerprints:[signing],suite:'stable',codename:'trixie',component:'main',architecture:'amd64',indexFilename:'main/binary-amd64/Packages',packageName:'example',packageVersion:'1.0-1',packageArchitecture:'amd64',now,maxAgeSeconds:86400,maxFutureSkewSeconds:0,requireValidUntil:true,maxValidUntilSeconds:604800,signatureClass:'00'};
const provenance=JSON.stringify({statusOrigin:'caller-captured-gpgv-status-fd',releaseOrigin:'caller-supplied-exact-signed-bytes',verificationBoundary:'external-trusted-caller-required'});
const status=`[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED ${primary} 0\n[GNUPG:] SIG_ID abc123 2026-10-13 ${now-3600}\n[GNUPG:] GOODSIG ${signing.slice(-16)} Synthetic Test\n[GNUPG:] VALIDSIG ${signing} 2026-10-13 ${now-3600} 0 4 0 1 8 00 ${primary}\n`;
const deb=Buffer.from('synthetic-deb-not-an-archive\0');
const makePackages=(extra='')=>`Package: example\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/e/example/example_1.0-1_amd64.deb\nSize: ${deb.length}\nSHA256: ${H(deb)}\n${extra}`;
const pk=makePackages();
const makeRelease=pack=>`Suite: stable\nCodename: trixie\nComponents: main\nArchitectures: amd64\nDate: Tue, 13 Oct 2026 11:00:00 GMT\nValid-Until: Wed, 14 Oct 2026 11:00:00 +0000\nSHA256:\n ${H(pack)} ${Buffer.byteLength(pack)} main/binary-amd64/Packages\n`;
const rel=makeRelease(pk);
const base=[status,0,rel,pk,deb,JSON.stringify(p),provenance];
let count=0,accepted=0,rejected=0;
function ok(args=base){count++;accepted++;const r=v(...args);assert.equal(r.authenticityAttested,false);assert.equal(r.kind,'literal-signed-metadata-correspondence');assert.equal(Object.isFrozen(r),true);return r;}
function bad(args){count++;rejected++;assert.throws(()=>v(...args),e=>e.constructor===Error&&e.message===ERROR);}
function change(i,x){const a=base.slice();a[i]=x;return a;}
function bp(over){bad(change(5,JSON.stringify({...p,...over})));}
function packBad(s){const a=base.slice();a[2]=makeRelease(s);a[3]=s;bad(a);}
const result=ok();count++;assert.equal(result.debSHA256,H(deb));
ok(base.map((x,i)=>[0,2,3].includes(i)?Buffer.from(x):x));
ok(base.map((x,i)=>[0,2,3,4].includes(i)?new Uint8Array(Buffer.from(x)):x));
for(const code of ['BADSIG','ERRSIG','NO_PUBKEY','EXPKEYSIG','EXPSIG','REVKEYSIG','FAILURE','ERROR','NODATA','BADARMOR','TRUST_NEVER','UNKNOWN','DECRYPTION_OKAY'])bad(change(0,status+`[GNUPG:] ${code} ignored\n`));
for(const s of ['',status.trimEnd(),status.replace('[GNUPG:]','stderr:'),status.replace('GOODSIG','BADSIG'),status.replace('VALIDSIG','ERRSIG'),status.replace(primary,'C'.repeat(40)).replaceAll(primary,'C'.repeat(40)),status.replaceAll(signing,'C'.repeat(40)),status+status,status.replace(' 8 00 ',' 2 00 '),status.replace(' 00 ',' 01 '),status.replace(' 4 0 ',' 4 1 '),status.replace(` ${now-3600} 0 4`,` ${now-3600} ${now} 4`),status.replace(` ${now-3600} 0 4`,` ${now+1} 0 4`),status.replace('2026-10-13','2026-10-12').replaceAll('2026-10-13','2026-10-12'),status.replace('GOODSIG '+signing.slice(-16),'GOODSIG '+primary.slice(-16)),status.replace(' 0 4 ',' 0.0 4 '),status+'[GNUPG:] NEWSIG\n',status+'\n',status+'[GNUPG:] TRUST_FULLY 1\n'])bad(change(0,s));
for(const n of [1,-1,0.1,-0,'0',null,NaN,Infinity,{},new Number(0)])bad(change(1,n));
for(const over of [{allowedPrimaryFingerprints:['C'.repeat(40)]},{allowedSigningFingerprints:['C'.repeat(40)]},{allowedPrimaryFingerprints:[]},{allowedSigningFingerprints:[signing,signing]},{allowedPrimaryFingerprints:[primary.toLowerCase()]},{suite:'testing'},{codename:'bookworm'},{component:'contrib'},{architecture:'arm64'},{indexFilename:'main/binary-amd64/Packages.gz'},{packageName:'other'},{packageVersion:'1.0-2'},{packageArchitecture:'all'},{now:now+200000},{now:now-3601},{maxAgeSeconds:3599},{maxAgeSeconds:0},{maxAgeSeconds:1.5},{maxFutureSkewSeconds:3601},{maxValidUntilSeconds:3600},{requireValidUntil:1},{extra:true}])bp(over);
for(const k of Object.keys(p)){const q={...p};delete q[k];bad(change(5,JSON.stringify(q)));}
for(const raw of ['null','[]','{}','bad','{"now":1,"now":2}',JSON.stringify(p).replace('"now":'+now,'"now":'+now+'.0000000001'),JSON.stringify(p).replace('"now":'+now,'"now":1e0'),JSON.stringify(p).replace('"now":'+now,'"now":-0'),JSON.stringify(p).replace('"now":'+now,'"now":9007199254740993'),JSON.stringify(p).replace('"now":'+now,'"now":'+now+',"n\\u006fw":'+now),' '.repeat(LIMITS.policyBytes+1),'['.repeat(6)+'0'+']'.repeat(6)])bad(change(5,raw));
for(const raw of ['{}','null',provenance.replace('external-trusted-caller-required','authenticated'),provenance.replace('caller-captured-gpgv-status-fd','source-derived-pin'),provenance.slice(0,-1)+',"statusOrigin":"caller-captured-gpgv-status-fd"}',' '.repeat(LIMITS.provenanceBytes+1)])bad(change(6,raw));
for(const r of [rel+'Suite: stable\n',rel.replace('Suite: stable','Suite: testing'),rel.replace('Codename: trixie','Codename: bookworm'),rel.replace('Components: main','Components: contrib'),rel.replace('Architectures: amd64','Architectures: arm64'),rel.replace('GMT',''),rel.replace('GMT','+0100'),rel.replace('Tue,','Mon,'),rel.replace('13 Oct','32 Oct'),rel.replace('11:00:00 GMT','11:00:60 GMT'),rel.replace('2026 11:00:00 +0000','2026 11:00:00 GMT').replace('14 Oct','13 Oct'),rel.replace(/^Valid-Until:.*\n/m,''),rel.replace('main/binary-amd64/Packages','../main/binary-amd64/Packages'),rel.replace('main/binary-amd64/Packages','main//binary-amd64/Packages'),rel.replace('main/binary-amd64/Packages','main/binary-arm64/Packages'),rel+rel.split('\n').at(-2)+'\n',rel.replace(H(pk),'0'.repeat(64)),rel.replace(' '+Buffer.byteLength(pk)+' ',' '+(Buffer.byteLength(pk)+1)+' '),rel.replace(' '+Buffer.byteLength(pk)+' ',' 1.0 '),rel.replace('SHA256:\n','SHA256: ambiguous\n'),rel.replace('SHA256:\n','SHA256:\nSHA256:\n'),rel.replace('Suite: stable','Suite: stable\n continuation'),rel.replace('Components: main','Components: main main'),rel.trimEnd(),rel+'\n'])bad(change(2,r));
for(const s of [pk+'Package: example\n',pk+'\n'+pk,pk.replace('Version: 1.0-1','Version: other'),pk.replace('Architecture: amd64','Architecture: all'),pk.replace('Filename: pool','Filename: ../pool'),pk.replace('Filename: pool','Filename: /pool'),pk.replace('Filename: pool','Filename: pool\\x'),pk.replace('Size: '+deb.length,'Size: '+(deb.length+1)),pk.replace('Size: '+deb.length,'Size: 1.0'),pk.replace('Size: '+deb.length,'Size: 9007199254740993'),pk.replace(H(deb),'0'.repeat(64)),pk.replace('SHA256:','SHA256:\n '),pk+' Description continuation\n',pk.replace('Package: example','Package: example '),pk.replace('Package: example','Package:\texample'),pk.replace('Filename:', 'filename:'),pk.replace('Size: '+deb.length+'\n',''),pk.trimEnd(),pk.replace('example','éxample')])packBad(s);
bad(change(3,pk+'\n'));bad(change(4,Buffer.from('wrong')));bad(change(4,Buffer.concat([deb,Buffer.from('x')])));
// Optional Valid-Until is only accepted when upstream policy explicitly permits it.
const noUntil=rel.replace(/^Valid-Until:.*\n/m,'');const optional=base.slice();optional[2]=noUntil;optional[5]=JSON.stringify({...p,requireValidUntil:false});ok(optional);
const skew=base.slice();skew[5]=JSON.stringify({...p,now:now-3601,maxFutureSkewSeconds:1});ok(skew);
// Rehash exact CRLF bytes, not normalized text.
const crpk=pk.replaceAll('\n','\r\n');const cr=base.slice();cr[0]=status.replaceAll('\n','\r\n');cr[2]=makeRelease(crpk).replaceAll('\n','\r\n');cr[3]=crpk;ok(cr);
for(const [i,cap] of [[0,LIMITS.statusBytes],[2,LIMITS.releaseBytes],[3,LIMITS.packagesBytes],[4,LIMITS.debBytes]])bad(change(i,new Uint8Array(cap+1)));
bad(change(0,'[GNUPG:] NEWSIG '+ 'x'.repeat(LIMITS.lineBytes)+'\n'));
bad(change(0,('[GNUPG:] KEY_CONSIDERED '+primary+' 0\n').repeat(65)));
bad(change(2,rel+'X: '+'x'.repeat(LIMITS.lineBytes)+'\n'));
let touches=0;const hostile=new Proxy({},{get(){touches++;throw Error('get');},ownKeys(){touches++;throw Error('keys');},getPrototypeOf(){touches++;throw Error('proto');}});
for(const i of [0,1,2,3,4,5,6])bad(change(i,hostile));
for(const i of [0,2,3,4,5,6])for(const x of [null,{},[],new String('text'),new DataView(new ArrayBuffer(2)),new Uint16Array(2),new ArrayBuffer(2)])bad(change(i,x));
for(const i of [0,2,3,4]){const x=new Uint8Array(Buffer.from(base[i]));for(const k of ['buffer','byteLength','length',Symbol.toStringTag,Symbol.iterator])Object.defineProperty(x,k,{get(){touches++;throw Error('getter');}});ok(change(i,x));bad(change(i,new Uint8Array(new SharedArrayBuffer(32))));}
const getter={get status(){touches++;throw Error('getter');}};bad(change(0,getter));count++;assert.equal(touches,0);
if(Object.getOwnPropertyDescriptor(ArrayBuffer.prototype,'resizable'))bad(change(4,new Uint8Array(new ArrayBuffer(32,{maxByteLength:64}))));
count++;assert.equal(Object.isFrozen(LIMITS),true);
ok(change(2,rel.replace('GMT','UTC')));
bad(change(2,rel+'suite: stable\n'));
packBad(pk+'package: example\n');
packBad(pk+'\n'+pk.replace('example','other')+'\n'+pk.replace('example','other'));
bad(change(0,status.replace('abc123 2026-10-13 '+(now-3600),'abc123 2026-10-13 '+(now-3601))));
bad(change(0,status.replace(' 0 4 0',' 9007199254740991 4 0')));
bad(change(0,status+'[GNUPG:] KEY_CONSIDERED '+ 'C'.repeat(40)+' 0\n'));
// Exercise each independent count cap with correctly hashed surrounding bytes.
const extraFields=Array.from({length:LIMITS.fields},(_,i)=>'X'+i+': value\n').join('');
bad(change(2,rel+extraFields));packBad(pk+extraFields);
const tooManyEntries=Array.from({length:LIMITS.releaseEntries},(_,i)=>' '+H(pk)+' 1 main/x'+i+'\n').join('');
bad(change(2,rel+tooManyEntries));
const tooManyStanzas=Array.from({length:LIMITS.packageStanzas},(_,i)=>pk.replace('Package: example','Package: x'+i)+'\n').join('');
packBad(pk+'\n'+tooManyStanzas);
// Cross-realm safe intrinsics ignore overridden typed-array accessors and methods.
const overridden=Buffer.from(deb);Object.defineProperty(overridden,'set',{get(){touches++;throw Error('get set');}});ok(change(4,overridden));
count++;assert.equal(touches,0);
const detachedBuffer=new ArrayBuffer(8),detachedView=new Uint8Array(detachedBuffer);structuredClone(detachedBuffer,{transfer:[detachedBuffer]});bad(change(4,detachedView));
bad(change(0,status+'[GNUPG:] SIG_ID abc123 2026-10-13 '+(now-3600)+'\n'));
const optionalExpired=optional.slice();optionalExpired[2]=rel.replace('Wed, 14 Oct 2026 11:00:00 +0000','Tue, 13 Oct 2026 12:00:00 GMT');bad(optionalExpired);
bad(change(2,rel+'MD5Sum:\n '+ '0'.repeat(32)+' 1 main/x\n '+ '0'.repeat(32)+' 1 main/x\n'));
for(const k of ['now','maxAgeSeconds','maxFutureSkewSeconds','maxValidUntilSeconds'])for(const spelling of ['0.99999999999999999','1.0000000000000001','1.0','1e0','-0'])bad(change(5,JSON.stringify(p).replace('"'+k+'":'+p[k],'"'+k+'":'+spelling)));
ok(change(2,rel+'X: '+'x'.repeat(LIMITS.lineBytes-3)+'\n'));
const inclusiveAge=base.slice();inclusiveAge[5]=JSON.stringify({...p,maxAgeSeconds:3600});ok(inclusiveAge);
const other=pk.replace('Package: example','Package: unrelated');const withOther=base.slice();withOther[3]=other+'\n'+pk;withOther[2]=makeRelease(withOther[3]);ok(withOther);
// Ordinary Debian control advisory continuation and UTF-8, entirely synthetic.
function packOK(s,over={}){const a=base.slice();a[2]=makeRelease(s);a[3]=s;a[5]=JSON.stringify({...p,...over});return ok(a);}
packOK(pk+'Description: first\n second\n');
const advisory=`Section: utils\nPriority: optional\nMaintainer: Synthetic Maintainer <nobody@example.invalid>\nInstalled-Size: 100\nDepends: libc6 (>= 2.36),\n libexample1 | libexample2\nDescription: UTF-8 café 한국어 日本語\n More ordinary prose: résumé and Ελληνικά.\n .\n\tTabbed advisory continuation only.\n`;
const unrelatedComplete=pk.replace('Package: example','Package: unrelated').replace('Version: 1.0-1','Version: 2.0-1')+advisory;
const keyringStanza=pk.replace('Package: example','Package: debian-archive-keyring').replace('Version: 1.0-1','Version: 2025.1').replace('Architecture: amd64','Architecture: all').replace('pool/main/e/example/example_1.0-1_amd64.deb','pool/main/d/debian-archive-keyring/debian-archive-keyring_2025.1_all.deb')+'Section: misc\nPriority: important\nMaintainer: Synthetic Keyring Maintainer <keyring@example.invalid>\nDescription: Synthetic keyring fixture, not real keys\n Contains no installed or authenticated keys.\n';
const completePackages=unrelatedComplete+'\n'+keyringStanza;
const completeResult=packOK(completePackages,{packageName:'debian-archive-keyring',packageVersion:'2025.1',packageArchitecture:'all'});
const completeCRLF=completePackages.replaceAll('\n','\r\n');packOK(Buffer.from(completeCRLF),{packageName:'debian-archive-keyring',packageVersion:'2025.1',packageArchitecture:'all'});
count++;assert.equal(completeResult.packagesSHA256,H(completePackages));
// Exact raw-byte hash must precede all normalization/UTF-8 parsing.
const normalizedMismatch=base.slice();normalizedMismatch[2]=makeRelease(completePackages);normalizedMismatch[3]=Buffer.from(completeCRLF);normalizedMismatch[5]=JSON.stringify({...p,packageName:'debian-archive-keyring',packageVersion:'2025.1',packageArchitecture:'all'});bad(normalizedMismatch);
for(const k of ['Package','Version','Architecture','Filename','Size','SHA256']){
 packBad(pk.replace(new RegExp('^'+k+': (.*)$','m'),k+': $1\n injected'));
 packBad(pk.replace(new RegExp('^'+k+': (.*)$','m'),k+': $1\n\tinjected'));
 packBad(pk.replace(new RegExp('^'+k+': (.*)$','m'),k+': $1é'));
}
packBad(' orphan advisory continuation\n'+pk);packBad(pk+'\n orphan continuation\n');
packBad(pk+'Description: first\n \n');packBad(pk+'Description: first\n\t\n');
packBad(pk+'Description: first\nDescription: second\n');
packBad(pk+'Description: first\ndescription: second\n');
packBad(completePackages+'\n'+unrelatedComplete);
for(const control of ['\x00','\x01','\x0b','\x0c','\x1b','\x7f','\u0085','\u009f','\u202e','\ufeff','\u2028','\u2029'])packBad(pk+'Description: text'+control+'bad\n');
for(const seq of [[0xc0,0xaf],[0xe2,0x82],[0xed,0xa0,0x80],[0xf4,0x90,0x80,0x80],[0x80]])packBad(Buffer.concat([Buffer.from(pk+'Description: '),Buffer.from(seq),Buffer.from('\n')]));
packBad(pk+'Description: lone surrogate \ud800\n');
packBad(pk+'Description: '+ 'é'.repeat(4090)+'\n');
packOK(pk+'Description: '+ 'é'.repeat(4089)+'x\n');
packBad(pk+'Description: first\rbare\n');
packOK(pk+'Description: text\n Package: this remains opaque advisory text\n');
// Every continuation bound has independent inclusive/overflow checks.
packOK(pk+'Description: text\n'+' x\n'.repeat(LIMITS.continuationsPerField));
packBad(pk+'Description: text\n'+' x\n'.repeat(LIMITS.continuationsPerField+1));
const stanzaContinuations=Array.from({length:4},(_,i)=>'X'+i+': text\n'+' x\n'.repeat(256)).join('');
packOK(pk+stanzaContinuations);packBad(pk+stanzaContinuations+'X4: extra\n x\n');
const fieldByteBoundary='Description:\n'+(' '+'x'.repeat(8190)+'\n').repeat(8);
packOK(pk+fieldByteBoundary);packBad(pk+fieldByteBoundary+' x\n');
const totalBoundary=Array.from({length:256},(_,i)=>pk.replace('Package: example','Package: bulk'+i)+'Description: text\n'+' x\n'.repeat(256)+'\n').join('');
packOK(totalBoundary+pk);packBad(totalBoundary+pk+'Description: text\n x\n');
// Explicit signature-class policy. No opportunistic multisig fallback or crypto.
const class01=base.slice();class01[0]=status.replace(' 8 00 ',' 8 01 ');class01[5]=JSON.stringify({...p,signatureClass:'01'});const classResult=ok(class01);count++;assert.equal(classResult.signatureClass,'01');
bad(change(5,JSON.stringify({...p,signatureClass:'01'})));
for(const c of ['02','10','ff','0',0,null,true]){bp({signatureClass:c});bad(change(0,status.replace(' 8 00 ',' 8 '+c+' ')));}
bp({packageArchitecture:'arm64'});bp({architecture:'arm64',indexFilename:'main/binary-arm64/Packages',packageArchitecture:'amd64'});
console.log(JSON.stringify({result:'PASS',checks:count,accepted,rejected,fixtureHashes:{release:H(rel),packages:H(pk),deb:H(deb),completeSyntheticPackages:H(completePackages),completeSyntheticRelease:H(makeRelease(completePackages))},sourceHashes:{module:H(fs.readFileSync(__dirname+'/debian-metadata-chain.cjs')),spec:H(fs.readFileSync(__filename))},limits:LIMITS,claim:'synthetic literal correspondence only; no gpg execution/authentication/extraction/runtime/CI'},null,2));
