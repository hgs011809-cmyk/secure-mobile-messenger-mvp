'use strict';
/* Preparatory literal signed-metadata correspondence ONLY. No gpg execution, keys,
 * network, extraction or dependency solver. A trusted caller MUST run real gpgv
 * with an independently provisioned keyring, capture status-fd separately from
 * stdout/stderr and supply its actual exit code. The Release input MUST be the
 * verified plaintext corresponding to EXACTLY the signed bytes passed to gpgv:
 * detached signatures verify these exact bytes; clearsigned Release plaintext
 * must be extracted by the trusted external verification process, not an
 * unauthenticated parser or stdout from an unrelated command. This module neither
 * extracts clearsigned content nor validates that external process boundary.
 * Caller-supplied status, zero exit, source-derived pins and provenance labels
 * CANNOT establish authenticity. This function cannot attest that boundary.
 * All accepted inputs are primitive JSON/text or copied non-shared Uint8Array.
 * Text is encoded as UTF-8; pass Uint8Array/Buffer for exact binary payloads.
 * API: verifyChain(status, actualExitCode, Release, Packages, deb, policyJSON,
 * provenanceJSON). Policy values are independently configured by the caller,
 * never learned as trusted pins from source metadata. Only uncompressed Packages
 * indexes are supported. Advisory fields allow bounded UTF-8 Debian-control
 * continuations; advisory Depends is NOT solved or interpreted. Security fields
 * remain exact one-line ASCII. UTC/GMT/+0000 dates only. packageArchitecture must
 * equal index architecture or explicitly configured 'all'. signatureClass is an
 * explicit trusted policy enum '00'/'01', never auto-selected from status output.
 * One signature only, no multisig fallback. Real transcripts/index compatibility
 * remain an external gate; 16 MiB/10000 stanzas are SYNTHETIC candidate limits.
 */
const {createHash}=require('node:crypto');
const {TextDecoder}=require('node:util');
const ERROR='DEBIAN_METADATA_CHAIN_REJECTED';
const LIMITS=Object.freeze({policyBytes:8192,provenanceBytes:1024,statusBytes:16384,statusLines:64,releaseBytes:1048576,packagesBytes:16777216,debBytes:67108864,lineBytes:8192,releaseEntries:8192,packageStanzas:10000,fields:128,continuationsPerField:256,continuationsPerStanza:1024,totalContinuations:65536,advisoryFieldBytes:65536});
const tp=Object.getPrototypeOf(Uint8Array.prototype), tg=Object.getOwnPropertyDescriptor(tp,Symbol.toStringTag).get;
const bl=Object.getOwnPropertyDescriptor(tp,'byteLength').get,bf=Object.getOwnPropertyDescriptor(tp,'buffer').get;
const ab=Object.getOwnPropertyDescriptor(ArrayBuffer.prototype,'byteLength').get;
const rz=Object.getOwnPropertyDescriptor(ArrayBuffer.prototype,'resizable')?.get;
const copy=Uint8Array.prototype.set;
function fail(){throw new Error(ERROR);}
function bytes(x,cap){
 if(typeof x==='string'){if(x.length>cap||/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(x))fail();const b=Buffer.from(x,'utf8');if(b.length>cap)fail();return b;}
 let n,b;try{if(tg.call(x)!=='Uint8Array')fail();n=bl.call(x);b=bf.call(x);ab.call(b);if(rz&&rz.call(b))fail();}catch{fail();}
 if(n>cap)fail();const out=Buffer.alloc(n);try{copy.call(out,x);}catch{fail();}return out;
}
function text(b){for(const c of b)if(c!==10&&c!==13&&(c<32||c>126))fail();const s=b.toString('ascii');if(!s.endsWith('\n')||/\r(?!\n)/.test(s))fail();const lines=s.replace(/\r\n/g,'\n').split('\n');lines.pop();if(lines.some(l=>l.length>LIMITS.lineBytes))fail();return lines;}
// Exact raw Packages bytes are hashed BEFORE decoding. Fatal UTF-8, byte-based
// line limits and control rejection prevent replacement/normalization ambiguity.
function packageText(b){let s;try{s=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(b);}catch{fail();}
 if(!s.endsWith('\n')||/\r(?!\n)/.test(s)||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\p{Cf}\u2028\u2029]/u.test(s))fail();
 const lines=s.replace(/\r\n/g,'\n').split('\n');lines.pop();if(lines.some(l=>Buffer.byteLength(l,'utf8')>LIMITS.lineBytes))fail();return lines;
}
// Bounded JSON parser rejects duplicate/escaped-equivalent keys and numeric
// spellings that could round fractional values to integers before validation.
function json(raw,cap){if(typeof raw!=='string'||raw.length>cap||Buffer.byteLength(raw)>cap)fail();let i=0,tokens=0;
 const ws=()=>{while(/[ \t\r\n]/.test(raw[i]||'!'))i++;};
 function val(depth){if(depth>4||++tokens>256)fail();ws();const c=raw[i];
 if(c==='"'){const start=i++;while(i<raw.length){const q=raw[i++];if(q==='"'){try{return JSON.parse(raw.substring(start,i));}catch{fail();}}if(q==='\\')i++;}fail();}
 if(c==='{'||c==='['){i++;const obj=c==='{'?Object.create(null):[];const end=c==='{'?'}':']';ws();if(raw[i]===end){i++;return obj;}while(true){if(c==='{'){const k=val(depth+1);if(typeof k!=='string'||Object.hasOwn(obj,k))fail();ws();if(raw[i++]!==':')fail();obj[k]=val(depth+1);}else obj.push(val(depth+1));ws();const ch=raw[i++];if(ch===end)return obj;if(ch!==',')fail();}}
 for(const [s,v] of [['true',true],['false',false],['null',null]])if(raw.startsWith(s,i)){i+=s.length;return v;}
 const m=/^(?:0|[1-9][0-9]*)/.exec(raw.substring(i));if(!m)fail();i+=m[0].length;const n=Number(m[0]);if(!Number.isSafeInteger(n))fail();return n;
 }
 const out=val(0);ws();if(i!==raw.length)fail();return out;
}
function shape(o,keys){if(!o||Array.isArray(o)||typeof o!=='object'||Object.keys(o).length!==keys.length||keys.some(k=>!Object.hasOwn(o,k)))fail();}
function int(n,lo,hi=Number.MAX_SAFE_INTEGER){if(!Number.isSafeInteger(n)||n<lo||n>hi)fail();return n;}
function uint(s){if(!/^(0|[1-9][0-9]*)$/.test(s))fail();return int(Number(s),0);}
function pathOK(s){if(typeof s!=='string'||s.length>1024||!s||s.split('/').some(p=>!p||p==='.'||p==='..')||!/^[-A-Za-z0-9_+.\/]+$/.test(s)||s.startsWith('/'))fail();return s;}
const fp=/^(?:[A-F0-9]{40}|[A-F0-9]{64})$/;
function policy(raw){const p=json(raw,LIMITS.policyBytes);shape(p,['allowedPrimaryFingerprints','allowedSigningFingerprints','suite','codename','component','architecture','indexFilename','packageName','packageVersion','packageArchitecture','now','maxAgeSeconds','maxFutureSkewSeconds','requireValidUntil','maxValidUntilSeconds','signatureClass']);
 for(const k of ['allowedPrimaryFingerprints','allowedSigningFingerprints'])if(!Array.isArray(p[k])||!p[k].length||p[k].length>16||p[k].some(f=>typeof f!=='string'||!fp.test(f))||new Set(p[k]).size!==p[k].length)fail();
 for(const k of ['suite','codename','component','architecture','packageArchitecture'])if(typeof p[k]!=='string'||!/^[-a-z0-9]+$/.test(p[k])||p[k].length>64)fail();
 if(typeof p.packageName!=='string'||!/^[-a-z0-9+.]{1,128}$/.test(p.packageName)||!/[a-z0-9]/.test(p.packageName))fail();
 if(typeof p.packageVersion!=='string'||! /^[A-Za-z0-9][A-Za-z0-9.+:~\-]{0,255}$/.test(p.packageVersion))fail();
 if(p.packageArchitecture!==p.architecture&&p.packageArchitecture!=='all')fail();
 if(p.signatureClass!=='00'&&p.signatureClass!=='01')fail();
 pathOK(p.indexFilename);if(p.indexFilename!==p.component+'/binary-'+p.architecture+'/Packages')fail();
 int(p.now,0,253402300799);int(p.maxAgeSeconds,1,31536000);int(p.maxFutureSkewSeconds,0,3600);int(p.maxValidUntilSeconds,1,31536000);if(typeof p.requireValidUntil!=='boolean')fail();return p;
}
function provenance(raw){const p=json(raw,LIMITS.provenanceBytes);shape(p,['statusOrigin','releaseOrigin','verificationBoundary']);if(p.statusOrigin!=='caller-captured-gpgv-status-fd'||p.releaseOrigin!=='caller-supplied-exact-signed-bytes'||p.verificationBoundary!=='external-trusted-caller-required')fail();}
function signature(b,exit,p){if(typeof exit!=='number'||!Number.isSafeInteger(exit)||Object.is(exit,-0)||exit!==0)fail();const lines=text(b);if(!lines.length||lines.length>LIMITS.statusLines)fail();let good=null,valid=null,news=0,keys=0,ids=0,trusts=0,sigID=null;
 for(const line of lines){const m=/^\[GNUPG:\] ([A-Z_]+)(?: (.*))?$/.exec(line);if(!m)fail();const code=m[1],arg=m[2]||'',a=arg.split(' ');
 if(code==='NEWSIG'){if(++news>1||good||valid)fail();}
 else if(code==='KEY_CONSIDERED'){if(++keys>8||a.length!==2||!fp.test(a[0])||(!p.allowedPrimaryFingerprints.includes(a[0])&&!p.allowedSigningFingerprints.includes(a[0]))||! /^(0|1|2|3)$/.test(a[1]))fail();}
 else if(code==='SIG_ID'){if(good||valid||++ids>1||a.length!==3||! /^[A-Za-z0-9+/=]{1,128}$/.test(a[0])||!/^\d{4}-\d{2}-\d{2}$/.test(a[1]))fail();uint(a[2]);sigID={date:a[1],timestamp:a[2]};}
 else if(code==='GOODSIG'){if(good||valid||!/^([A-F0-9]{16}) (.+)$/.test(arg))fail();good=a[0];}
 else if(code==='VALIDSIG'){if(!good||valid||a.length!==10||!fp.test(a[0])||!fp.test(a[9])||!p.allowedSigningFingerprints.includes(a[0])||!p.allowedPrimaryFingerprints.includes(a[9])||!a[0].endsWith(good))fail();
 const ts=uint(a[2]),ex=uint(a[3]);if((sigID&&(sigID.date!==a[1]||sigID.timestamp!==a[2]))||ex>253402300799||ts>p.now+p.maxFutureSkewSeconds||ts>253402300799||new Date(ts*1000).toISOString().substring(0,10)!==a[1]||(ex!==0&&(ex<=p.now||ex<=ts))||!['4','5','6'].includes(a[4])||a[5]!=='0'||!['1','19','22','27','28'].includes(a[6])||!['8','9','10','11'].includes(a[7])||a[8]!==p.signatureClass)fail();valid={signingFingerprint:a[0],primaryFingerprint:a[9],signatureClass:a[8]};}
 else if(['TRUST_UNDEFINED','TRUST_MARGINAL','TRUST_FULLY','TRUST_ULTIMATE'].includes(code)){if(++trusts>1||!valid||!/^0(?: pgp)?$/.test(arg))fail();}
 else fail(); // Every negative signature state, FAILURE, ERROR and unknown state.
 }
 if(!good||!valid)fail();return valid;
}
function date(s){const m=/^(Sun|Mon|Tue|Wed|Thu|Fri|Sat), ([0-9]{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) (GMT|UTC|\+0000)$/.exec(s);if(!m)fail();const mo=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(m[3]),y=Number(m[4]),d=Number(m[2]),h=Number(m[5]),mi=Number(m[6]),se=Number(m[7]);if(y<1970||h>23||mi>59||se>59)fail();const t=Date.UTC(y,mo,d,h,mi,se),v=new Date(t);if(v.getUTCFullYear()!==y||v.getUTCMonth()!==mo||v.getUTCDate()!==d||['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][v.getUTCDay()]!==m[1])fail();return t/1000;}
function release(b,p){const lines=text(b),fields=Object.create(null),entries=new Map(),fieldNames=new Set(),checksumPaths=new Set();let current=null,total=0;
 for(const l of lines){if(l.startsWith(' ')){if(!['SHA256','SHA512','SHA1','MD5Sum'].includes(current))fail();const bits=l.match(/^ ([a-f0-9]+) +(0|[1-9][0-9]*) (\S+)$/);if(!bits)fail();const lengths={SHA256:64,SHA512:128,SHA1:40,MD5Sum:32};if(bits[1].length!==lengths[current]||++total>LIMITS.releaseEntries)fail();const name=pathOK(bits[3]),size=uint(bits[2]);const checksumPath=current+':'+name;if(checksumPaths.has(checksumPath))fail();checksumPaths.add(checksumPath);if(current==='SHA256'){if(entries.has(name))fail();entries.set(name,{sha256:bits[1],size,filename:name});}}
 else{const m=/^([A-Za-z][A-Za-z0-9-]*):(?: (.*))?$/.exec(l);if(!m||fieldNames.has(m[1].toLowerCase())||fieldNames.size>=LIMITS.fields)fail();fieldNames.add(m[1].toLowerCase());current=m[1];fields[current]=m[2]??'';if(['SHA256','SHA512','SHA1','MD5Sum'].includes(current)&&fields[current]!=='')fail();}}
 for(const [k,want] of [['Suite',p.suite],['Codename',p.codename]])if(fields[k]!==want)fail();
 for(const [k,want] of [['Components',p.component],['Architectures',p.architecture]]){const v=fields[k];if(typeof v!=='string'||!/^[-a-z0-9]+(?: [-a-z0-9]+)*$/.test(v)||new Set(v.split(' ')).size!==v.split(' ').length||!v.split(' ').includes(want))fail();}
 const dt=date(fields.Date);if(dt>p.now+p.maxFutureSkewSeconds||p.now-dt>p.maxAgeSeconds)fail();let until=null;
 if(Object.hasOwn(fields,'Valid-Until')){until=date(fields['Valid-Until']);if(until<=p.now||until<=dt||until-dt>p.maxValidUntilSeconds)fail();}else if(p.requireValidUntil)fail();
 const entry=entries.get(p.indexFilename);if(!entry)fail();return {entry,date:dt,validUntil:until};
}
function hash(b){return createHash('sha256').update(b).digest('hex');}
function matches(b,e){if(b.length!==e.size||hash(b)!==e.sha256)fail();}
function packages(b,p){const lines=packageText(b);let stanza=Object.create(null),stanzas=0,found=null,fields=0;const identities=new Set();let fieldNames=new Set();
 const security=new Set(['package','version','architecture','filename','size','sha256']);
 let current=null,fieldContinuations=0,stanzaContinuations=0,totalContinuations=0,advisoryBytes=0;
 function flush(){if(!fields)return;if(++stanzas>LIMITS.packageStanzas)fail();for(const k of ['Package','Version','Architecture','Filename','Size','SHA256'])if(!Object.hasOwn(stanza,k))fail();pathOK(stanza.Filename);const size=uint(stanza.Size);if(!/^[a-f0-9]{64}$/.test(stanza.SHA256)||!/^[-a-z0-9+.]+$/.test(stanza.Package)||! /^[A-Za-z0-9][A-Za-z0-9.+:~\-]*$/.test(stanza.Version)||!/^[-a-z0-9]+$/.test(stanza.Architecture))fail();
 const identity=JSON.stringify([stanza.Package,stanza.Version,stanza.Architecture]);if(identities.has(identity))fail();identities.add(identity);
 if(stanza.Package===p.packageName&&stanza.Version===p.packageVersion&&stanza.Architecture===p.packageArchitecture){if(found)fail();found={filename:stanza.Filename,size,sha256:stanza.SHA256};}stanza=Object.create(null);fields=0;fieldNames=new Set();current=null;fieldContinuations=0;stanzaContinuations=0;advisoryBytes=0;}
 for(const l of lines){if(!l){flush();continue;}
 if(/^[ \t]/.test(l)){
  if(!current||security.has(current)||!l.trim()||++fieldContinuations>LIMITS.continuationsPerField||++stanzaContinuations>LIMITS.continuationsPerStanza||++totalContinuations>LIMITS.totalContinuations)fail();
  advisoryBytes+=Buffer.byteLength(l,'utf8')+1;if(advisoryBytes>LIMITS.advisoryFieldBytes)fail();
  continue; // Advisory continuation is opaque, never reinterpreted as a field.
 }
 const m=/^([A-Za-z][A-Za-z0-9-]*):(?:[ \t](.*))?$/.exec(l);
 if(!m||fieldNames.has(m[1].toLowerCase())||++fields>LIMITS.fields)fail();
 current=m[1].toLowerCase();fieldNames.add(current);fieldContinuations=0;
 if(security.has(current)){
  if(!/^([A-Za-z][A-Za-z0-9-]*): [!-~][ -~]*$/.test(l)||l.endsWith(' '))fail();
  stanza[m[1]]=m[2];advisoryBytes=0;
 }else{advisoryBytes=Buffer.byteLength(m[2]??'','utf8');if(advisoryBytes>LIMITS.advisoryFieldBytes)fail();}
 }flush();if(!found)fail();return found;
}
function verifyChain(statusInput,gpgvExitCode,releaseInput,packagesInput,debInput,policyJSON,provenanceJSON){try{const p=policy(policyJSON);provenance(provenanceJSON);const status=bytes(statusInput,LIMITS.statusBytes),sig=signature(status,gpgvExitCode,p),rb=bytes(releaseInput,LIMITS.releaseBytes),r=release(rb,p),pb=bytes(packagesInput,LIMITS.packagesBytes);matches(pb,r.entry);const pkg=packages(pb,p),db=bytes(debInput,LIMITS.debBytes);matches(db,pkg);
 return Object.freeze({kind:'literal-signed-metadata-correspondence',authenticityAttested:false,trustedCallerBoundary:'real external gpgv verification required',...sig,releaseSHA256:hash(rb),packagesSHA256:hash(pb),debSHA256:hash(db),indexFilename:r.entry.filename,packageFilename:pkg.filename,packageSize:pkg.size,releaseDate:r.date,validUntil:r.validUntil});}catch{fail();}}
module.exports=Object.freeze({verifyChain,LIMITS,ERROR});
