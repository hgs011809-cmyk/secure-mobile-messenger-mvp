'use strict';
/* Trusted CI diagnostic admission, NOT the phase engine helper/worker/profile.
 * No spawn, signaling, network, installation or payload execution here.
 * Caller launches clean-environment setsid --fork --wait -> timeout -> Node.
 * Procfs relationships/retained bytes are observations, not an atomic liveness lease.
 * TERM/conditional KILL policy is not guaranteed termination/descendant cleanup.
 */
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const MiB=1048576,BOOT_CAP=16384,PROC_CAP=4096;
const forbiddenEnvironment=['NODE_OPTIONS','NODE_PATH','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED','LD_PRELOAD','LD_LIBRARY_PATH','GCONV_PATH','SSL_CERT_FILE','SSL_CERT_DIR'];
function bad(){throw Error('BUDGET_ADMISSION_BLOCKED');}
function uint(value,max=2147483647,positive=false){if(typeof value!=='string'||!/^(?:0|[1-9][0-9]{0,9})$/.test(value))bad();const n=Number(value);if(!Number.isSafeInteger(n)||n>max||(positive&&n===0))bad();return n;}
function tick(value){if(typeof value!=='string'||!/^(?:0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>18446744073709551615n)bad();return value;}
function parseProcStat(text){
 if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>PROC_CAP||text.includes('\0'))bad();
 const open=text.indexOf('('),close=text.lastIndexOf(')');
 if(open<2||close<=open||text[close+1]!==' '||!/^([1-9][0-9]{0,9}) $/.test(text.slice(0,open)))bad();
 const tail=text.slice(close+2).replace(/\n$/,'');if(/[\r\n]/.test(tail))bad();
 const fields=tail.split(' ');if(fields.length<20||fields.length>64||!/^\w$/.test(fields[0])||fields.slice(1).some(x=>!/^(?:0|[1-9][0-9]{0,19}|-[1-9][0-9]{0,19})$/.test(x)))bad();
 // The state and selected IDs are interpreted; other decimal fields are opaque.
 return Object.freeze({pid:uint(text.slice(0,open-1),2147483647,true),state:fields[0],ppid:uint(fields[1],2147483647,true),pgrp:uint(fields[2],2147483647,true),session:uint(fields[3],2147483647,true),starttime:tick(fields[19])});
}
function validateRelationships(self,parent,pid,ppid){
 if(!Number.isSafeInteger(pid)||!Number.isSafeInteger(ppid)||pid<=0||ppid<=0||pid===ppid||self.pid!==pid||self.ppid!==ppid||parent.pid!==ppid||self.pgrp!==ppid||self.session!==ppid||parent.pgrp!==ppid||parent.session!==ppid||!['R','S'].includes(self.state)||!['R','S'].includes(parent.state))bad();
 tick(self.starttime);tick(parent.starttime);return true;
}
function unchangedRelationships(a,b){return ['pid','ppid','pgrp','session','starttime'].every(k=>a[k]===b[k]);}
function checkRuntime(){if(process.platform!=='linux'||process.arch!=='x64'||process.versions.node!=='22.23.3'||typeof process.getuid!=='function'||!fs.constants.O_NOFOLLOW||!fs.constants.O_DIRECTORY||forbiddenEnvironment.some(k=>Object.hasOwn(process.env,k)))bad();}
function metadata(s){return {dev:s.dev.toString(),ino:s.ino.toString(),size:s.size.toString(),uid:Number(s.uid),gid:Number(s.gid),mode:Number(s.mode),nlink:Number(s.nlink),mtimeNs:s.mtimeNs.toString(),ctimeNs:s.ctimeNs.toString()};}
function sameMetadata(a,b){return ['dev','ino','size','uid','gid','mode','nlink','mtimeNs','ctimeNs'].every(k=>a[k]===b[k]);}
function closeAll(resources){let closed=0;for(const fd of resources.slice().reverse())try{fs.closeSync(fd);closed++;}catch{}const result={attempted:resources.length,succeeded:closed,failed:resources.length-closed,allClosed:closed===resources.length};if(!result.allClosed)bad();return result;}
function readCapped(p,cap,resources,{proc=false,magicExe=false,capture=true,owner=null,exactMode=null,executable=false}={}){
 let flags=fs.constants.O_RDONLY|fs.constants.O_NONBLOCK;if(!magicExe)flags|=fs.constants.O_NOFOLLOW;
 const fd=fs.openSync(p,flags);resources.push(fd);const first=fs.fstatSync(fd,{bigint:true}),id=metadata(first);
 if(!first.isFile()||first.nlink!==1n||(owner!==null&&first.uid!==BigInt(owner))||(Number(first.mode)&0o022)||(exactMode!==null&&(Number(first.mode)&0o7777)!==exactMode)||(executable&&(!(Number(first.mode)&0o111)||(Number(first.mode)&0o6000)))||(!proc&&(first.size<1n||first.size>BigInt(cap))))bad();
 const h=crypto.createHash('sha256'),chunks=[],buf=Buffer.alloc(65536);let count=0;
 for(;;){const amount=Math.min(buf.length,cap-count+1);if(amount<1)bad();const n=fs.readSync(fd,buf,0,amount,null);if(!n)break;count+=n;if(count>cap)bad();h.update(buf.subarray(0,n));if(capture)chunks.push(Buffer.from(buf.subarray(0,n)));}
 const after=metadata(fs.fstatSync(fd,{bigint:true}));if(!sameMetadata(id,after)||(!proc&&BigInt(count)!==first.size))bad();
 return {fd,identity:id,bytes:count,sha256:h.digest('hex'),data:capture?Buffer.concat(chunks,count):null};
}
function secureRoot(p,resources){
 if(typeof p!=='string'||!path.isAbsolute(p)||path.normalize(p)!==p||p==='/'||p.length>2048||/[\x00-\x1f\x7f]/.test(p))bad();
 let current='/';for(const part of ['',...p.split('/').filter(Boolean)]){if(part)current=path.join(current,part);const s=fs.lstatSync(current);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o022)||![0,process.getuid()].includes(s.uid))bad();}
 const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);resources.push(fd);
 const s=fs.fstatSync(fd,{bigint:true}),l=fs.lstatSync(p,{bigint:true});if(!s.isDirectory()||l.isSymbolicLink()||s.dev!==l.dev||s.ino!==l.ino||s.uid!==BigInt(process.getuid())||(Number(s.mode)&0o7777)!==0o700)bad();
 return {path:p,dev:s.dev.toString(),ino:s.ino.toString(),uid:Number(s.uid),mode:Number(s.mode)&0o7777};
}
function equalRoot(a,b){return ['path','dev','ino','uid','mode'].every(k=>a[k]===b[k]);}
function prepareBootstrap(root,versions){
 checkRuntime();if(versions?.setsid!=='2.39.3'||versions?.timeout!=='9.4')bad();const resources=[];let record;
 try{
  const r=secureRoot(root,resources),tools={};
  for(const [name,p,cap,owner] of [['node',process.execPath,256*MiB,null],['timeout','/usr/bin/timeout',16*MiB,0],['setsid','/usr/bin/setsid',16*MiB,0],['env','/usr/bin/env',16*MiB,0]]){const v=readCapped(p,cap,resources,{capture:false,owner,executable:true});if(name==='node'&&![0,process.getuid()].includes(v.identity.uid))bad();tools[name]={path:p,identity:v.identity,bytes:v.bytes,sha256:v.sha256};}
  if(!equalRoot(r,secureRoot(root,resources)))bad();
  record={kind:'owned_signal_budget_bootstrap_v1',root:r,tools,versions:{setsid:'2.39.3',timeout:'9.4'},trust:'trusted_provisioned_ci_host_not_independent_binary_authentication',policy:{termSeconds:95,conditionalKillGraceSeconds:5,guaranteedTermination:false,descendantCleanup:false}};
 }finally{const closed=closeAll(resources);if(record)record.fdCleanup=closed;}
 return record;
}
function admit(root,expectedBootstrapSha256){
 checkRuntime();if(typeof expectedBootstrapSha256!=='string'||!/^[a-f0-9]{64}$/.test(expectedBootstrapSha256))bad();const resources=[];let record;
 try{
  const r=secureRoot(root,resources),boot=readCapped(path.join(root,'budget-bootstrap.json'),BOOT_CAP,resources,{owner:process.getuid(),exactMode:0o600});if(boot.sha256!==expectedBootstrapSha256)bad();
  const b=JSON.parse(boot.data.toString('utf8'));if(b.kind!=='owned_signal_budget_bootstrap_v1'||!equalRoot(b.root,r)||b.versions?.setsid!=='2.39.3'||b.versions?.timeout!=='9.4'||b.policy?.guaranteedTermination!==false||b.policy?.descendantCleanup!==false||b.policy?.termSeconds!==95||b.policy?.conditionalKillGraceSeconds!==5||b.fdCleanup?.allClosed!==true||!b.tools?.timeout||!b.tools?.node)bad();
  const ppid=process.ppid,self=parseProcStat(readCapped('/proc/self/stat',PROC_CAP,resources,{proc:true}).data.toString('utf8')),parent=parseProcStat(readCapped('/proc/'+ppid+'/stat',PROC_CAP,resources,{proc:true}).data.toString('utf8'));validateRelationships(self,parent,process.pid,ppid);
  const monitor=readCapped('/proc/'+ppid+'/exe',16*MiB,resources,{magicExe:true,capture:false,owner:0,executable:true}),node=readCapped('/proc/self/exe',256*MiB,resources,{magicExe:true,capture:false,executable:true});
  if(monitor.sha256!==b.tools.timeout.sha256||monitor.bytes!==b.tools.timeout.bytes||!sameMetadata(monitor.identity,b.tools.timeout.identity)||node.sha256!==b.tools.node.sha256||node.bytes!==b.tools.node.bytes||!sameMetadata(node.identity,b.tools.node.identity))bad();
  const self2=parseProcStat(readCapped('/proc/self/stat',PROC_CAP,resources,{proc:true}).data.toString('utf8')),parent2=parseProcStat(readCapped('/proc/'+ppid+'/stat',PROC_CAP,resources,{proc:true}).data.toString('utf8'));validateRelationships(self2,parent2,process.pid,process.ppid);
  if(process.ppid!==ppid||!unchangedRelationships(self,self2)||!unchangedRelationships(parent,parent2)||!equalRoot(r,secureRoot(root,resources)))bad();
  record={kind:'owned_signal_budget_admission_v1',privateSessionGroupObserved:true,parentMonitorIdentityMatched:true,nodeIdentityMatched:true,parentStarttimeStableObserved:true,rootIdentityMatched:true,bootstrapSha256:expectedBootstrapSha256,termSeconds:95,conditionalKillGraceSeconds:5,guaranteedTermination:false,descendantCleanup:false,atomicFutureLivenessLease:false};
 }finally{const closed=closeAll(resources);if(record)record.fdCleanup=closed;}
 return Object.freeze(record);
}
function fdCounts(value,positive=true){if(!value||!Number.isSafeInteger(value.attempted)||!Number.isSafeInteger(value.succeeded)||!Number.isSafeInteger(value.failed)||value.attempted<(positive?1:0)||value.attempted>64||value.succeeded!==value.attempted||value.failed!==0||value.allClosed!==true)bad();return true;}
function validateAdmission(value){if(!value||value.kind!=='owned_signal_budget_admission_v1'||['privateSessionGroupObserved','parentMonitorIdentityMatched','nodeIdentityMatched','parentStarttimeStableObserved','rootIdentityMatched'].some(k=>value[k]!==true)||['guaranteedTermination','descendantCleanup','atomicFutureLivenessLease'].some(k=>value[k]!==false)||value.termSeconds!==95||value.conditionalKillGraceSeconds!==5||!/^[a-f0-9]{64}$/.test(value.bootstrapSha256))bad();fdCounts(value.fdCleanup);return true;}
function validateAnchorGate(r){
 if(!r||r.kind!=='ubuntu_anchor_runtime_preflight_candidate'||r.status!=='prerequisite_probe_only_verified'||r.ownerTask!=='IcUJ8UMoJUKXJWiB'||r.cryptographicVerification!==true||r.rawDiagnosticsSuppressed!==true||r.failureClass!==undefined||r.priorFailureClass!==undefined||r.childFailureObservation!==undefined)bad();
 for(const k of ['fullChainAcceptance','currentSignerAllowlistAcceptance','freshnessAcceptance','fullDebianTrust','buildProof'])if(r[k]!==false)bad();
 for(const k of ['packageInstallations','containersCreated','keyDownloads','keyImports'])if(r[k]!==0)bad();
 const v=r.gpgvObserved;if(!v||v.spawned!==true||v.exitObserved!==true||v.closed!==true||v.exitCode!==0||v.signalPresent!==false||r.signatures?.verified!==true||r.scope?.expectedNobleScope!==true||r.scope?.checksumChainVerified!==false||r.packageIdentity?.localDatabaseAssertionOnly!==true||r.packageIdentity?.independentAuthentication!==false||r.publicStatus?.rawStatusRetained!==false)bad();
 fdCounts(r.fdCleanup);validateAdmission(r.ownedBudgetAdmission);return true;
}
function validateHeadGate(r){
 if(!r||r.kind!=='final_head_with_owned_budget'||!Array.isArray(r.rows)||r.rows.length!==4)bad();validateAdmission(r.ownedBudgetAdmission);
 const expected=[['chromium','https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.4/linux64/chrome-linux64.zip'],['headless','https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.4/linux64/chrome-headless-shell-linux64.zip'],['ffmpeg','https://playwright.download.prss.microsoft.com/dbazure/download/playwright/builds/ffmpeg/1013/ffmpeg-linux.zip']];
 r.rows.slice(0,3).forEach((x,i)=>{if(x.kind!=='observed_final_target_head_only'||x.artifact!==expected[i][0]||x.exactPublicURL!==expected[i][1]||x.metadataResponseAccepted!==true||!Number.isInteger(x.status)||!(x.status===200||[301,302,303,307,308].includes(x.status))||!(x.declaredRepresentationLength===null||(Number.isSafeInteger(x.declaredRepresentationLength)&&x.declaredRepresentationLength>=0))||typeof x.identityRepresentation!=='boolean'||x.archiveBytesAcquired!==0||x.archiveVerified!==false||x.vendorAuthenticated!==false)bad();});
 const s=r.rows[3];if(s.kind!=='observed_final_target_head_summary'||s.configuredTargets!==3||s.requestAttempts!==3||s.failures!==0||s.followedRedirects!==0||s.archiveBytesAcquired!==0||s.archiveVerified!==false||s.vendorAuthenticated!==false)bad();return true;
}
module.exports=Object.freeze({parseProcStat,validateRelationships,prepareBootstrap,admit,fdCounts,validateAdmission,validateAnchorGate,validateHeadGate});
if(require.main===module){console.log('{"kind":"owned_signal_budget_admission_library","status":"blocked","noStandaloneRuntime":true}');process.exitCode=1;}
