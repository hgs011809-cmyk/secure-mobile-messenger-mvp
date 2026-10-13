'use strict';
/* SOURCE-ONLY CANDIDATE: independent review before separately authorized CI.
 * Trusted provisioned Linux runner, Node runtime, root package database, local
 * filesystems, toolchain and existing Ubuntu keyring are the trust boundary.
 * No hostile concurrent inode/mount mutation, ptrace or privileged adversary.
 * Package identity is a local database assertion, not independent attestation.
 * No install, container, key download/import, signing or synthetic status.
 * Child timers are best-effort event-loop deadlines, not hard wall-clock bounds:
 * blocked synchronous local I/O can delay callbacks. A separately reviewed
 * external owned-process monitor is required before runtime for a hard budget.
 * Runtime verification is only an archive signature prerequisite: no freshness,
 * current-signer allowlist, full Debian chain, build or full-chain acceptance.
 */
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const URL='https://archive.ubuntu.com/ubuntu/dists/noble/InRelease';
const KEY='/usr/share/keyrings/ubuntu-archive-keyring.gpg';
const CAP=1048576, DEADLINE=20000;
const failures=new Set(['profile','filesystem','identity','child_spawn','child_cap','child_deadline','child_unclosed','child_exit','fetch','fetch_redirect','fetch_cap','fetch_deadline','status_profile','signature','release_scope','fd_cleanup']);
function bad(code){const e=new Error('PREFLIGHT_BLOCKED');e.fixed=failures.has(code)?code:'profile';throw e;}
function sha(b){return crypto.createHash('sha256').update(b).digest('hex');}
function same(a,b){return a.dev===b.dev&&a.ino===b.ino&&a.uid===b.uid&&a.gid===b.gid&&a.mode===b.mode&&a.nlink===b.nlink&&a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs;}
function ancestors(p,trusted){
 if(!path.isAbsolute(p)||path.normalize(p)!==p||/[\x00-\x1f\x7f]/.test(p))bad('filesystem');
 let current='/';
 const top=fs.lstatSync('/');if(!top.isDirectory()||top.uid!==0||(top.mode&0o022))bad('filesystem');
 for(const part of p.split('/').filter(Boolean)){current=path.join(current,part);const s=fs.lstatSync(current);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o022)||(trusted?s.uid!==0:![0,process.getuid()].includes(s.uid)))bad('filesystem');}
}
function directory(p,resources){
 const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);resources.push({fd});
 const s=fs.fstatSync(fd);if(!s.isDirectory()||s.uid!==process.getuid()||(s.mode&0o7777)!==0o700)bad('filesystem');return {fd,p,s};
}
function checkDir(d){const a=fs.fstatSync(d.fd),b=fs.lstatSync(d.p);if(!a.isDirectory()||b.isSymbolicLink()||a.dev!==d.s.dev||a.ino!==d.s.ino||b.dev!==a.dev||b.ino!==a.ino||a.uid!==process.getuid()||(a.mode&0o7777)!==0o700||b.mode!==a.mode)bad('filesystem');}
function readFD(fd,cap,owner,mode){
 const a=fs.fstatSync(fd);if(!a.isFile()||a.nlink!==1||a.uid!==owner||(a.mode&0o022)||(mode!==null&&(a.mode&0o7777)!==mode)||a.size<1||a.size>cap)bad('filesystem');
 const b=Buffer.alloc(a.size);let n=0;while(n<b.length){const k=fs.readSync(fd,b,n,b.length-n,n);if(!k)bad('filesystem');n+=k;}
 const extra=Buffer.alloc(1);if(fs.readSync(fd,extra,0,1,n)!==0||!same(a,fs.fstatSync(fd)))bad('filesystem');return {bytes:b,sha256:sha(b),size:n,stat:a};
}
function retained(p,cap,owner,mode,resources,executable=false){
 ancestors(path.dirname(p),owner===0);const l=fs.lstatSync(p);if(l.isSymbolicLink())bad('filesystem');
 const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);resources.push({fd});
 const r=readFD(fd,cap,owner,mode);if(!same(l,r.stat)||(executable&&(!(r.stat.mode&0o111)||(r.stat.mode&0o6000))))bad('filesystem');return {fd,p,cap,owner,mode,...r};
}
function recheck(r){const n=readFD(r.fd,r.cap,r.owner,r.mode),l=fs.lstatSync(r.p);if(l.isSymbolicLink()||!same(r.stat,n.stat)||!same(l,n.stat)||n.sha256!==r.sha256)bad('filesystem');}
function reserve(p,resources){
 const fd=fs.openSync(p,fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);resources.push({fd});
 const s=fs.fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o7777)!==0o600||s.size!==0)bad('filesystem');return {fd,p,cap:CAP,owner:process.getuid(),mode:0o600};
}
function save(p,b,resources){
 const r=reserve(p,resources);fs.writeFileSync(r.fd,b);fs.fsyncSync(r.fd);Object.assign(r,readFD(r.fd,CAP,process.getuid(),0o600));if(r.sha256!==sha(b))bad('filesystem');return r;
}
function cleanupProjection(record,attempted,succeeded){
 if(!Number.isSafeInteger(attempted)||!Number.isSafeInteger(succeeded)||attempted<0||succeeded<0||succeeded>attempted)bad('profile');
 const projected={...record,fdCleanup:{attempted,succeeded,failed:attempted-succeeded,allClosed:attempted===succeeded}};
 if(attempted!==succeeded){projected.status='blocked';projected.failureClass='fd_cleanup';if(record.failureClass)projected.priorFailureClass=failures.has(record.failureClass)?record.failureClass:'profile';}
 return projected;
}
/* Only this function spawns. fd 3 is bounded public status, fd 4 retained
 * keyring, fd 5 hashed executable, fd 6 exact input. No PID signaling or shell.
 * Gpgv plaintext uses --output -: ONLY the parent writes its exclusively opened
 * 0600 file, at most CAP bytes. This is a file-byte boundary even for a buggy
 * tool emitting excessive stdout, not an exploit-safe/tool sandbox claim.
 * Overflow drains/discards and fails closed. A best-effort timer targets 20s
 * for signaling only the owned handle; blocked synchronous writes can delay
 * that callback. Missing close after the further best-effort 2s grace is
 * unknown/fail-block with no later child. No hard wall-clock claim.
 */
async function child(tool,args,key,home,outCap,input=null,sink=null){
 recheck(tool);recheck(key);if(input)recheck(input);
 return await new Promise((resolve,reject)=>{
  let c,timer,grace,settled=false,spawned=false,exited=false,code=null,signal=null,spawnError=false,capped=false,timed=false,writeError=false;
  const out=[],err=[],status=[];let outBytes=0,errBytes=0,statusBytes=0;
  function done(closeCode,closeSignal,closed){
   if(settled)return;settled=true;clearTimeout(timer);clearTimeout(grace);
   const observation={spawned,exitObserved:exited,closed,exitCode:Number.isInteger(code)?code:null,signalPresent:signal!==null};
   const problem=!closed?'child_unclosed':timed?'child_deadline':capped?'child_cap':writeError?'filesystem':spawnError||!spawned?'child_spawn':!exited||closeCode!==code||closeSignal!==signal?'child_exit':null;
   if(problem){const e=new Error('PREFLIGHT_BLOCKED');e.fixed=problem;e.observed=observation;reject(e);}else resolve({...observation,stdout:Buffer.concat(out),stdoutBytes:outBytes,status:Buffer.concat(status),stderrSha256:sha(Buffer.concat(err)),stderrBytes:errBytes});
  }
  function detach(){if(c.stdout)c.stdout.destroy();if(c.stderr)c.stderr.destroy();if(c.stdio[3])c.stdio[3].destroy();c.unref();done(null,null,false);}
  function deadline(){timed=true;try{c.kill('SIGKILL');}catch{}grace=setTimeout(detach,2000);}
  try{
   c=spawn('/proc/self/fd/5',args,{cwd:home,env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',HOME:home,GNUPGHOME:home},shell:false,detached:false,stdio:input?['ignore','pipe','pipe','pipe',key.fd,tool.fd,input.fd]:['ignore','pipe','pipe','pipe',key.fd,tool.fd]});
   c.once('spawn',()=>{spawned=true;});c.once('error',()=>{spawnError=true;});
   c.once('exit',(v,s)=>{exited=true;code=v;signal=s;});c.once('close',(v,s)=>done(v,s,true));
   for(const stream of [c.stdout,c.stderr,c.stdio[3]])stream.on('error',()=>{spawnError=true;});
   c.stdout.on('data',b=>{
    if(settled)return;if(outBytes+b.length>outCap){capped=true;return;}if(capped||writeError)return;
    if(sink){try{let n=0;while(n<b.length){const k=fs.writeSync(sink.fd,b,n,b.length-n,outBytes+n);if(k<1)throw Error('WRITE');n+=k;}}catch{writeError=true;return;}}
    else out.push(b);outBytes+=b.length;
   });
   c.stderr.on('data',b=>{if(settled)return;if(errBytes+b.length>32768){capped=true;return;}if(!capped){err.push(b);errBytes+=b.length;}});
   c.stdio[3].on('data',b=>{if(settled)return;if(statusBytes+b.length>65536){capped=true;return;}if(!capped){status.push(b);statusBytes+=b.length;}});
   timer=setTimeout(deadline,DEADLINE);
  }catch{spawnError=true;if(!c)done(null,null,true);else timer=setTimeout(deadline,DEADLINE);}
 });
}
function text(b){try{return new TextDecoder('utf-8',{fatal:true}).decode(b);}catch{bad('profile');}}
async function acquire(){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),DEADLINE);let reader;
 try{
  const r=await fetch(URL,{method:'GET',redirect:'manual',credentials:'omit',signal:controller.signal,headers:{Accept:'text/plain','Accept-Encoding':'identity'}});
  if(r.status>=300&&r.status<400)bad('fetch_redirect');if(r.status!==200||r.url!==URL||r.redirected||!r.body)bad('fetch');
  const length=r.headers.get('content-length');if(length!==null&&(!/^[0-9]{1,8}$/.test(length)||Number(length)>CAP))bad('fetch_cap');
  const encoding=r.headers.get('content-encoding');if(encoding!==null&&encoding!=='identity')bad('fetch');
  reader=r.body.getReader();const chunks=[];let used=0;
  while(true){const x=await reader.read();if(x.done)break;used+=x.value.byteLength;if(used>CAP)bad('fetch_cap');chunks.push(Buffer.from(x.value));}
  if(!used||(length!==null&&Number(length)!==used))bad('fetch');return Buffer.concat(chunks,used);
 }catch(e){if(e.fixed)throw e;bad(controller.signal.aborted?'fetch_deadline':'fetch');}
 finally{clearTimeout(timer);controller.abort();if(reader){void reader.cancel().catch(()=>{});try{reader.releaseLock();}catch{}}}
}
/* Structural profiles only, never cryptographic verification. */
function crc24(bytes){let crc=0xb704ce;for(const b of bytes){crc^=b<<16;for(let i=0;i<8;i++){crc<<=1;if(crc&0x1000000)crc^=0x1864cfb;}crc&=0xffffff;}return crc;}
function packetFraming(bytes){
 if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>131072)bad('profile');
 let at=0,count=0,totalBody=0;
 function octet(){if(at>=bytes.length)bad('profile');return bytes[at++];}
 function uint(n){let v=0;for(let i=0;i<n;i++)v=v*256+octet();return v;}
 while(at<bytes.length){
  if(++count>8)bad('profile');const h=octet();if(!(h&0x80))bad('profile');let length;
  if(h&0x40){
   if((h&0x3f)!==2)bad('profile');const x=octet();
   if(x<192)length=x;
   else if(x<=223)length=(x-192)*256+octet()+192;
   else if(x===255){length=uint(4);if(length<8384)bad('profile');}
   else bad('profile'); // partial lengths are never supported
  }else{
   if(((h>>2)&15)!==2)bad('profile');const kind=h&3;
   if(kind===0)length=octet();
   else if(kind===1){length=uint(2);if(length<256)bad('profile');}
   else if(kind===2){length=uint(4);if(length<65536)bad('profile');}
   else bad('profile'); // old indeterminate length
  }
  if(length<1||length>16384||length>bytes.length-at)bad('profile');
  totalBody+=length;at+=length;
 }
 return {signaturePacketCount:count,signaturePacketBytes:bytes.length,signatureBodyBytes:totalBody,structuralOnly:true};
}
function decodeSignatureArmor(armor){
 if(typeof armor!=='string'||armor.length>180000)bad('profile');
 const lines=armor.split('\n');if(lines.pop()!=='')bad('profile');let i=0;const seen=new Set();
 while(i<lines.length&&lines[i]!==''){
  const m=/^(Version|Comment): ([\x20-\x7e]{0,256})$/.exec(lines[i++]);if(!m||seen.has(m[1]))bad('profile');seen.add(m[1]);
 }
 if(lines[i++]!==''||i>=lines.length)bad('profile');
 let checksum=null;
 if(lines[lines.length-1].startsWith('=')){checksum=lines.pop();if(!/^=[A-Za-z0-9+/]{4}$/.test(checksum))bad('profile');}
 const data=lines.slice(i);if(!data.length||data.length>2732)bad('profile');
 for(let n=0;n<data.length;n++){
  if(!/^[A-Za-z0-9+/]+={0,2}$/.test(data[n])||data[n].length>76||data[n].length%4!==0||(n<data.length-1&&data[n].includes('=')))bad('profile');
 }
 const encoded=data.join('');if(encoded.length>174764)bad('profile');
 const decoded=Buffer.from(encoded,'base64');if(decoded.toString('base64')!==encoded)bad('profile');
 if(checksum!==null){const b=Buffer.from(checksum.slice(1),'base64');if(b.length!==3||b.toString('base64')!==checksum.slice(1)||b.readUIntBE(0,3)!==crc24(decoded))bad('profile');}
 return {...packetFraming(decoded),crc24Present:checksum!==null};
}
function clearSignedProfile(bytes){
 if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>CAP||bytes.some(b=>b>126||(b<32&&![9,10,13].includes(b))))bad('profile');
 const s=bytes.toString('ascii').replace(/\r\n/g,'\n');
 const header=/^-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA(?:256|384|512)(?:, SHA(?:256|384|512))*\n\n/.exec(s);
 if(s.includes('\r')||!header)bad('profile');
 const marker='\n-----BEGIN PGP SIGNATURE-----\n',at=s.indexOf(marker,header[0].length);
 if(at<0||s.indexOf(marker,at+marker.length)!==-1||!s.endsWith('-----END PGP SIGNATURE-----\n'))bad('profile');
 const body=s.slice(header[0].length,at+1);if(!body.length)bad('profile');
 // Every leading dash in the signed body must be RFC cleartext dash-escaped.
 for(const line of body.split('\n'))if(line.startsWith('-')&&!line.startsWith('- '))bad('profile');
 const exactBody=Buffer.from(body.replace(/^- /gm,''),'ascii');
 // CRLF output can be no larger than the exact acquired byte cap: use a
 // conservative 2-byte newline model, and independently cap the parent file.
 const conservativeOutputBytes=exactBody.length+(body.match(/\n/g)||[]).length;
 if(conservativeOutputBytes>CAP)bad('profile');
 const armor=s.slice(at+marker.length,-'-----END PGP SIGNATURE-----\n'.length);
 return {...decodeSignatureArmor(armor),cleartextBodyBytes:exactBody.length,conservativeOutputBytes,plaintextFileByteCap:CAP,outputBound:'parent_exclusive_file_capped_stdout',cryptographicVerification:false,exploitSafe:false};
}
function parseReleaseDate(value){
 if(typeof value!=='string')bad('release_scope');
 const m=/^(Sun|Mon|Tue|Wed|Thu|Fri|Sat), ([0-9]{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) (UTC|GMT)$/.exec(value);
 if(!m)bad('release_scope');
 const month=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(m[3]),year=Number(m[4]),day=Number(m[2]),hour=Number(m[5]),minute=Number(m[6]),second=Number(m[7]);
 if(year<1900||year>9999||day<1||hour>23||minute>59||second>59)bad('release_scope');
 const ms=Date.UTC(year,month,day,hour,minute,second),d=new Date(ms);
 if(d.getUTCFullYear()!==year||d.getUTCMonth()!==month||d.getUTCDate()!==day||['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d.getUTCDay()]!==m[1])bad('release_scope');
 return {releaseDate:value,releaseDateTimestamp:ms/1000,releaseDateInformationalOnly:true,freshnessChecked:false};
}
function statusProjection(bytes){
 const counts={NEWSIG:0,GOODSIG:0,VALIDSIG:0,KEY_CONSIDERED:0,SIG_ID:0};
 const names=['BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','NODATA','BADARMOR','ERROR','FAILURE','UNEXPECTED'];
 const failureClasses=Object.fromEntries(names.map(k=>[k,0]));
 const trust=['TRUST_UNDEFINED','TRUST_NEVER','TRUST_MARGINAL','TRUST_FULLY','TRUST_ULTIMATE'];
 const signatureClasses={binaryDocument:0,canonicalText:0};let pending=false,good=false,lines=0;
 const s=text(bytes);if(!s.endsWith('\n'))bad('status_profile');
 for(const line of s.split('\n')){
  if(!line)continue;if(++lines>256||line.length>8192)bad('status_profile');
  const m=/^\[GNUPG:\] ([A-Z_]+)(?: (.*))?$/.exec(line);if(!m)bad('status_profile');const tag=m[1],value=m[2]||'';
  if(names.includes(tag)){failureClasses[tag]++;pending=false;good=false;continue;}if(trust.includes(tag))continue;
  if(!Object.hasOwn(counts,tag))bad('status_profile');counts[tag]++;
  if(tag==='NEWSIG'){if(pending)bad('status_profile');pending=true;good=false;}
  if(tag==='GOODSIG'){if(!pending||good||!/^[A-Fa-f0-9]{16,64} .+$/.test(value))bad('status_profile');good=true;}
  if(tag==='VALIDSIG'){
   if(!pending||!good)bad('status_profile');const p=value.split(' ');
   if(![9,10].includes(p.length)||!/^(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$/.test(p[0])||!/^\d{4}-\d{2}-\d{2}$/.test(p[1])||!/^\d{1,12}$/.test(p[2])||!/^\d{1,12}$/.test(p[3])||!['4','5','6'].includes(p[4])||p[5]!=='0'||!['1','17','19','22'].includes(p[6])||!['8','9','10','11'].includes(p[7])||!['00','01'].includes(p[8])||(p.length===10&&!/^(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$/.test(p[9])))bad('status_profile');
   signatureClasses[p[8]==='01'?'canonicalText':'binaryDocument']++;pending=false;good=false;
  }
 }
 const verified=!pending&&counts.NEWSIG>=1&&counts.NEWSIG<=8&&counts.NEWSIG===counts.GOODSIG&&counts.GOODSIG===counts.VALIDSIG&&Object.values(failureClasses).every(x=>x===0);
 return {verified,counts,failureClasses,signatureClasses};
}
function releaseScope(bytes){
 if(bytes.some(b=>b>126||(b<32&&![9,10,13].includes(b))))bad('release_scope');
 const s=bytes.toString('ascii');if(!s.endsWith('\n'))bad('release_scope');
 const fields={},entries={MD5Sum:0,SHA1:0,SHA256:0,SHA512:0};let section=null,lines=0;
 const allowed=new Set(['Origin','Label','Suite','Version','Codename','Date','Valid-Until','Architectures','Components','Description','Acquire-By-Hash','NotAutomatic','ButAutomaticUpgrades']);
 for(const raw of s.split('\n')){
  const line=raw.endsWith('\r')?raw.slice(0,-1):raw;if(!line)continue;if(++lines>16000||line.length>4096)bad('release_scope');
  if(/^[ \t]/.test(line)){
   if(!section)bad('release_scope');const m=/^[ \t]+([a-fA-F0-9]+)[ \t]+([0-9]{1,15})[ \t]+([A-Za-z0-9_+./-]+)$/.exec(line),lengths={MD5Sum:32,SHA1:40,SHA256:64,SHA512:128};
   if(!m||m[1].length!==lengths[section]||m[3].startsWith('/')||m[3].split('/').some(p=>!p||p==='.'||p==='..'))bad('release_scope');entries[section]++;continue;
  }
  const m=/^([A-Za-z][A-Za-z0-9-]*):(?: (.*))?$/.exec(line);if(!m||Object.hasOwn(fields,m[1]))bad('release_scope');fields[m[1]]=m[2]||'';section=null;
  if(Object.hasOwn(entries,m[1])){if(fields[m[1]]!=='')bad('release_scope');section=m[1];}else if(!allowed.has(m[1]))bad('release_scope');
 }
 if(fields.Origin!=='Ubuntu'||fields.Label!=='Ubuntu'||fields.Suite!=='noble'||fields.Codename!=='noble'||fields.Version!=='24.04'||entries.SHA256<1)bad('release_scope');
 return {expectedNobleScope:true,checksumEntryCounts:entries,...parseReleaseDate(fields.Date),checksumChainVerified:false};
}
async function run(workroot){
 let record={kind:'ubuntu_anchor_runtime_preflight_candidate',status:'blocked',ownerTask:'IcUJ8UMoJUKXJWiB',cryptographicVerification:false,fullChainAcceptance:false,currentSignerAllowlistAcceptance:false,freshnessAcceptance:false,fullDebianTrust:false,buildProof:false,packageInstallations:0,containersCreated:0,keyDownloads:0,keyImports:0,rawDiagnosticsSuppressed:true,trustBoundary:'trusted_provisioned_linux_runner_existing_package_managed_root_keyring_and_host_tools'};
 const resources=[],directories=[];let oldMask;
 try{
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.platform!=='linux'||!['22','24'].includes(process.versions.node.split('.')[0])||typeof process.getuid!=='function'||typeof fetch!=='function'||!['x64','arm64'].includes(process.arch)||!fs.constants.O_NOFOLLOW||!fs.constants.O_DIRECTORY||typeof workroot!=='string'||workroot==='/')bad('profile');
  oldMask=process.umask(0o077);ancestors(workroot,false);const root=directory(workroot,resources);directories.push(root);
  const runpath=fs.mkdtempSync(path.join(workroot,'ubuntu-anchor-'));directories.push(directory(runpath,resources));record.evidenceDirectory=path.basename(runpath);
  const home=path.join(runpath,'empty-gnupg');fs.mkdirSync(home,{mode:0o700});directories.push(directory(home,resources));
  const outdir=path.join(runpath,'gpgv-output');fs.mkdirSync(outdir,{mode:0o700});directories.push(directory(outdir,resources));
  const key=retained(KEY,CAP,0,null,resources);
  const dpkg=retained('/usr/bin/dpkg-query',32*CAP,0,null,resources,true);
  const gpgv=retained('/usr/bin/gpgv',32*CAP,0,null,resources,true);
  record.trustedKeyring={sha256:key.sha256,bytes:key.size,ownerUid:0,mode:key.stat.mode&0o7777,nlink:1};
  record.hostToolIdentity={dpkgQuery:{sha256:dpkg.sha256,bytes:dpkg.size,ownerUid:0,mode:dpkg.stat.mode&0o7777},gpgv:{sha256:gpgv.sha256,bytes:gpgv.size,ownerUid:0,mode:gpgv.stat.mode&0o7777}};
  async function query(args){directories.forEach(checkDir);const r=await child(dpkg,args,key,home,65536);if(r.exitCode!==0||r.signalPresent||r.status.length)bad('identity');return r.stdout;}
  const packageBytes=await query(['-W','-f','${binary:Package}\t${Status}\t${Version}\n','ubuntu-keyring','gpgv','dpkg']);
  const pkgs=text(packageBytes).trimEnd().split('\n'),seen=new Set(),packageVersions={};
  for(const line of pkgs){const m=/^(ubuntu-keyring|gpgv|dpkg)\tinstall ok installed\t([0-9][A-Za-z0-9.+:~_-]{0,127})$/.exec(line);if(!m||seen.has(m[1]))bad('identity');seen.add(m[1]);packageVersions[m[1]]=m[2];}if(seen.size!==3)bad('identity');
  const ownershipBytes=await query(['-S',KEY,'/usr/bin/gpgv','/usr/bin/dpkg-query']);
  const expected=new Set(['ubuntu-keyring: '+KEY,'gpgv: /usr/bin/gpgv','dpkg: /usr/bin/dpkg-query']),ownership=text(ownershipBytes).trimEnd().split('\n');
  if(ownership.length!==3||ownership.some(x=>!expected.delete(x))||expected.size)bad('identity');
  record.packageIdentity={expectedPackagesInstalled:true,exactPathOwnership:true,packageVersions,localDatabaseAssertionOnly:true,independentAuthentication:false,querySha256:sha(packageBytes),ownershipQuerySha256:sha(ownershipBytes)};
  directories.forEach(checkDir);const version=await child(gpgv,['--version'],key,home,16384);
  if(version.exitCode!==0||version.signalPresent||version.status.length||!/^gpgv \(GnuPG\) 2\.(?:2|4)\.[0-9]{1,3}(?:\n|\r\n)/.test(text(version.stdout)))bad('identity');
  record.gpgvAvailability={available:true,versionOutputSha256:sha(version.stdout)};
  directories.forEach(checkDir);const acquired=await acquire();record.sourceProfile=clearSignedProfile(acquired);const input=save(path.join(runpath,'InRelease'),acquired,resources);
  record.acquisition={exactURL:URL,bytes:input.size,sha256:input.sha256,redirectsFollowed:0,credentials:'omit'};
  recheck(input);directories.forEach(checkDir);
  const output=path.join(outdir,'Release');if(fs.readdirSync(outdir).length!==0||fs.readdirSync(home).length!==0)bad('filesystem');
  const release=reserve(output,resources);
  /* Separate status pipe fd 3; keyring fd 4; executable fd 5; input fd 6.
   * Gpgv stdout is plaintext; only the parent owns/writes the output file,
   * with a hard byte cap independent of packet-parser/tool correctness. */
  const v=await child(gpgv,['--homedir',home,'--keyring','/proc/self/fd/4','--status-fd','3','--output','-','/proc/self/fd/6'],key,home,CAP,input,release);
  record.gpgvObserved={spawned:v.spawned,exitObserved:v.exitObserved,closed:v.closed,exitCode:v.exitCode,signalPresent:v.signalPresent,stderrSha256:v.stderrSha256,stderrBytes:v.stderrBytes};
  directories.forEach(checkDir);recheck(input);recheck(key);recheck(dpkg);recheck(gpgv);
  record.publicStatus={sha256:sha(v.status),bytes:v.status.length,rawStatusRetained:false};
  const projected=statusProjection(v.status);record.signatures=projected;
  record.cryptographicVerification=v.exitCode===0&&!v.signalPresent&&projected.verified;
  const projection=save(path.join(runpath,'gpgv-status-projection.json'),Buffer.from(JSON.stringify({publicStatus:record.publicStatus,signatures:projected})+'\n'),resources);recheck(projection);
  if(v.exitCode!==0||v.signalPresent||!projected.verified)bad('signature');
  // This observed fact is not erased by later scope, file or cleanup failures.
  record.cryptographicVerification=true;
  fs.fsyncSync(release.fd);Object.assign(release,readFD(release.fd,CAP,process.getuid(),0o600));
  if(release.size!==v.stdoutBytes||release.size>record.sourceProfile.conservativeOutputBytes)bad('filesystem');
  record.plaintextRelease={sha256:release.sha256,bytes:release.size,parentFileByteCap:CAP};
  record.scope=releaseScope(release.bytes);recheck(release);recheck(input);directories.forEach(checkDir);
  record.status='prerequisite_probe_only_verified';
 }catch(e){record.failureClass=failures.has(e.fixed)?e.fixed:'profile';if(e.observed)record.childFailureObservation=e.observed;}
 finally{
  let succeeded=0;for(const h of resources.slice().reverse())try{fs.closeSync(h.fd);succeeded++;}catch{}
  record=cleanupProjection(record,resources.length,succeeded);
  if(oldMask!==undefined)try{process.umask(oldMask);}catch{record.status='blocked';record.failureClass='profile';}
 }
 return record;
}
module.exports=Object.freeze({run,clearSignedProfile,packetFraming,decodeSignatureArmor,parseReleaseDate,statusProjection,releaseScope,cleanupProjection});
if(require.main===module){
 if(process.argv.length!==3){console.log(JSON.stringify({kind:'ubuntu_anchor_runtime_preflight_candidate',status:'blocked',failureClass:'profile',cryptographicVerification:false,fullChainAcceptance:false,rawDiagnosticsSuppressed:true}));process.exitCode=1;}
 else run(process.argv[2]).then(r=>{console.log(JSON.stringify(r));if(r.status!=='prerequisite_probe_only_verified')process.exitCode=1;}).catch(()=>{console.log('{"kind":"ubuntu_anchor_runtime_preflight_candidate","status":"blocked","failureClass":"profile","cryptographicVerification":false,"fullChainAcceptance":false,"rawDiagnosticsSuppressed":true}');process.exitCode=1;});
}
