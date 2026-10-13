'use strict';
// Exact public redirect targets OBSERVED in CI38318999013, not guessed URLs.
// Metadata only: no cookies, body retention, acquisition, redirect following or execution.
// Declared representation length is not acquired ZIP size/hash or vendor authentication.
// Native timers are best-effort event-loop bounds; use an external owned monitor for runtime.
const crypto=require('node:crypto');
const TARGETS=Object.freeze([
 Object.freeze({artifact:'chromium',url:'https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.4/linux64/chrome-linux64.zip'}),
 Object.freeze({artifact:'headless',url:'https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.4/linux64/chrome-headless-shell-linux64.zip'}),
 Object.freeze({artifact:'ffmpeg',url:'https://playwright.download.prss.microsoft.com/dbazure/download/playwright/builds/ffmpeg/1013/ffmpeg-linux.zip'})
]);
const PUBLIC_ORIGINS=new Set(['https://storage.googleapis.com','https://playwright.download.prss.microsoft.com','https://cdn.playwright.dev']);
const PUBLIC_DESTINATIONS=new Set([...TARGETS.map(x=>x.url),
 'https://cdn.playwright.dev/builds/cft/156.0.8078.4/linux64/chrome-linux64.zip',
 'https://cdn.playwright.dev/builds/cft/156.0.8078.4/linux64/chrome-headless-shell-linux64.zip',
 'https://cdn.playwright.dev/dbazure/download/playwright/builds/ffmpeg/1013/ffmpeg-linux.zip']);
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
function bad(){throw Error('HEAD_HEADER');}
function parseLength(value){if(value===null)return null;if(typeof value!=='string'||!/^(?:0|[1-9][0-9]{0,15})$/.test(value)||!Number.isSafeInteger(Number(value)))bad();return Number(value);}
function redirectProjection(location,sourceURL){
 if(typeof location!=='string'||!location.length||location.length>8192||/[^\x21-\x7e]/.test(location))bad();
 let u;try{u=new URL(location,sourceURL);}catch{bad();}
 if(u.protocol!=='https:'||u.username||u.password||u.pathname.length>2048||/[^\x21-\x7e]/.test(u.pathname))bad();
 const serialized=u.href,fragmentAt=serialized.indexOf('#'),queryAt=serialized.indexOf('?');
 return Object.freeze({origin:PUBLIC_ORIGINS.has(u.origin)?u.origin:null,originSha256:hash(u.origin),publicPath:PUBLIC_DESTINATIONS.has(u.origin+u.pathname)?u.pathname:null,pathSha256:hash(u.pathname),queryPresent:queryAt>=0&&(fragmentAt<0||queryAt<fragmentAt),fragmentPresent:fragmentAt>=0});
}
async function run(){
 if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||typeof fetch!=='function')throw Error('HEAD_PROFILE');
 const started=Date.now();let failures=0,attempts=0;
 for(const target of TARGETS){
  let record;
  try{
   if(Date.now()-started>65000)throw Error('HEAD_DEADLINE');
   attempts++;
   const response=await fetch(target.url,{method:'HEAD',redirect:'manual',credentials:'omit',signal:AbortSignal.timeout(20000),headers:{'Accept':'application/zip','Accept-Encoding':'identity'}});
   try{
    if(!Number.isInteger(response.status)||response.status<100||response.status>599)bad();
    const length=parseLength(response.headers.get('content-length')),location=response.headers.get('location'),encoding=response.headers.get('content-encoding');
    const redirect=location===null?null:redirectProjection(location,target.url);
    const identityRepresentation=encoding===null||encoding==='identity';
    const accepted=response.status===200||([301,302,303,307,308].includes(response.status)&&redirect!==null);
    record={kind:'observed_final_target_head_only',artifact:target.artifact,exactPublicURL:target.url,status:response.status,declaredRepresentationLength:length,identityRepresentation,redirect,metadataResponseAccepted:accepted,archiveBytesAcquired:0,archiveVerified:false,vendorAuthenticated:false};
   }finally{if(response.body)await response.body.cancel();}
   if(!record.metadataResponseAccepted)failures++;
  }catch(e){
   failures++;const code=e?.cause?.code;
   record={kind:'observed_final_target_head_only',artifact:target.artifact,exactPublicURL:target.url,status:null,errorClass:e?.name==='TimeoutError'?'timeout':code==='ENOTFOUND'?'dns_unavailable':e?.message==='HEAD_DEADLINE'?'deadline':'unverified',archiveBytesAcquired:0,archiveVerified:false,vendorAuthenticated:false};
  }
  console.log(JSON.stringify(record));
 }
 const summary={kind:'observed_final_target_head_summary',configuredTargets:TARGETS.length,requestAttempts:attempts,failures,followedRedirects:0,archiveBytesAcquired:0,archiveVerified:false,vendorAuthenticated:false};
 console.log(JSON.stringify(summary));if(failures)process.exitCode=1;return summary;
}
module.exports=Object.freeze({TARGETS,parseLength,redirectProjection,run});
if(require.main===module)run().catch(()=>{console.log('{"kind":"observed_final_target_head_summary","status":"blocked","archiveBytesAcquired":0,"archiveVerified":false,"vendorAuthenticated":false}');process.exitCode=1;});
