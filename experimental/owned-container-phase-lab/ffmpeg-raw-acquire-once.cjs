'use strict';
// ONE approved RAW acquisition only. No child/process signaling, decompression,
// extraction, entry materialization, installation, container, GPG or SDK.
// Timers are best-effort on a trusted event loop, NOT hard termination/erasure.
const https=require('node:https'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),util=require('node:util');
const assembly=require('./ffmpeg-byte-assembly-candidate.cjs'),raw=require('./ffmpeg-raw-zip-metadata.cjs');
const URL=assembly.PUBLIC_URL,BUDGET_MS=20000,GRACE_MS=2000,IDLE_MS=5000;
const ERROR='FFMPEG_RAW_ACQUISITION_BLOCKED';
const ROOT='C:/Users/mycom/.aside/u/0/workspaces/secure-mobile-messenger-lab/';
const SESSION='C:/Users/mycom/.aside/u/0/sessions/2026-10-13_IcUJ8UMoJUKXJWiB/';
const typed=Object.getPrototypeOf(Uint8Array.prototype),lengthGet=Object.getOwnPropertyDescriptor(typed,'length').get;
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function blocked(code,observation){const e=Error(ERROR);e.fixed=code;e.observed=observation;return e;}
function captureRawResponse(http,timers,clock){
 // Injected APIs are MOCK-only; CLI supplies native Node. All delivered owned
 // resources are tracked/closed, even unexpected late/additional resources.
 const started=clock(),asm=assembly.createFFmpegByteAssemblyCandidate(assembly.PRIOR_HEAD_CLAIM);
 return new Promise((resolve,reject)=>{
  let req,socket,res,deadline,grace,ended=false,reqClosed=false,settled=false,failed=null,reqDestroyIssued=false,socketEvents=0,responseEvents=0,acceptedBytes=0,chunks=0,status=null,headersAccepted=false,errorCode=null,rejectedError;
  const sockets=new Map(),responses=new Map(),destroyIssued=new Set();
  const elapsed=()=>Number(clock()-started)/1e6;
  const allClosed=m=>[...m.values()].every(Boolean);
  const observation=()=>({requestCreated:!!req,responseObserved:!!res,status,headersAccepted,acceptedBytes,chunks,responseEndObserved:ended,requestCloseObserved:reqClosed,socketObserved:sockets.size>0,socketCloseObserved:sockets.size>0&&allClosed(sockets),socketsDelivered:sockets.size,socketsClosed:[...sockets.values()].filter(Boolean).length,responsesDelivered:responses.size,responsesClosed:[...responses.values()].filter(Boolean).length,allDeliveredResourceClosesObserved:(!req||reqClosed)&&allClosed(sockets)&&allClosed(responses),futureUnexpectedResourceClosureProven:false,elapsedMilliseconds:elapsed(),nodeErrorCode:errorCode,primaryFailure:failed,hardWallclockTerminationProven:false});
  function refreshRejected(){if(rejectedError)rejectedError.observed=observation();}
  function destroyResource(x){if(destroyIssued.has(x))return;destroyIssued.add(x);try{x.destroy();}catch{}}
  function abortOwned(){if(req&&!reqDestroyIssued){reqDestroyIssued=true;try{req.destroy();}catch{}}for(const s of sockets.keys())destroyResource(s);for(const r of responses.keys())destroyResource(r);}
  function finish(unknown=false){if(settled)return;settled=true;timers.clearTimeout(deadline);timers.clearTimeout(grace);if(unknown||failed){asm.abandon();rejectedError=blocked(unknown?'transport_closure_unknown':failed,observation());reject(rejectedError);return;}try{const snapshot=asm.finish();if(elapsed()>BUDGET_MS){rejectedError=blocked('elapsed_budget_after_snapshot',observation());reject(rejectedError);}else resolve({snapshot,transport:observation()});}catch{asm.abandon();rejectedError=blocked('exact_body_length',observation());reject(rejectedError);}}
  function check(){refreshRejected();if(settled)return;const closed=(!req||reqClosed)&&allClosed(sockets)&&allClosed(responses);if(failed){if(!req&&closed)finish();return;}if(ended&&reqClosed&&sockets.size===1&&responses.size===1&&closed){if(elapsed()>BUDGET_MS){failed='elapsed_budget';finish();}else finish();}}
  function armGrace(){if(!settled&&!grace)grace=timers.setTimeout(()=>finish(!((!req||reqClosed)&&allClosed(sockets)&&allClosed(responses))||(!!req&&sockets.size===0)),GRACE_MS);}
  function fail(code,e){if(!failed)failed=code;if(e&&typeof e.code==='string'&&/^[A-Z0-9_]{1,64}$/.test(e.code))errorCode=e.code;asm.abandon();abortOwned();check();armGrace();}
  function registerResponse(r){responseEvents++;if(!responses.has(r)){responses.set(r,false);r.on('error',e=>fail('response_error',e));r.on('aborted',()=>fail('response_aborted'));r.once('close',()=>{responses.set(r,true);if(!ended&&!failed)fail('response_premature_close');check();});}if(failed||settled){destroyResource(r);refreshRejected();return false;}if(responseEvents!==1){fail('multiple_response');return false;}return true;}
  try{
   req=http.request(URL,{method:'GET',agent:false,family:4,autoSelectFamily:false,rejectUnauthorized:true,maxHeaderSize:16384,headers:{Accept:'application/octet-stream','Accept-Encoding':'identity',Connection:'close'}},r=>{
    if(!registerResponse(r))return;res=r;status=r.statusCode;const h=r.headers||{},rh=r.rawHeaders;
    if(status!==200||!socket||socket.authorized!==true||!Array.isArray(rh)||rh.length>512||rh.length%2){fail('response_headers');return;}
    let lengthHeaders=0;for(let i=0;i<rh.length;i+=2){if(typeof rh[i]!=='string'||typeof rh[i+1]!=='string'){fail('response_headers');return;}if(rh[i].toLowerCase()==='content-length')lengthHeaders++;}
    if(lengthHeaders!==1||h['content-length']!==String(assembly.LIMITS.maxCaptureBytes)||h['transfer-encoding']!==undefined||(h['content-encoding']!==undefined&&h['content-encoding']!=='identity')){fail('response_headers');return;}headersAccepted=true;
    r.on('data',b=>{if(settled||failed)return;try{if(elapsed()>BUDGET_MS){fail('elapsed_budget');return;}if(util.types.isProxy(b)||!util.types.isUint8Array(b))throw Error('CHUNK');const n=lengthGet.call(b);asm.push(b);acceptedBytes+=n;chunks++;}catch{fail('body_cap_or_chunk');}});
    r.on('end',()=>{if(settled||failed)return;if(r.complete!==true||acceptedBytes!==assembly.LIMITS.maxCaptureBytes){fail('incomplete_or_short_body');return;}ended=true;for(const s of sockets.keys())destroyResource(s);for(const r of responses.keys())destroyResource(r);check();armGrace();});
   });
   req.on('error',e=>fail('request_error',e));req.on('close',()=>{reqClosed=true;if(!ended&&!failed)fail('request_premature_close');check();});
   req.on('socket',s=>{socketEvents++;if(!sockets.has(s)){sockets.set(s,false);s.on('error',e=>fail('socket_error',e));s.once('close',()=>{sockets.set(s,true);if(!ended&&!failed)fail('socket_premature_close');check();});}if(failed||settled){destroyResource(s);refreshRejected();return;}if(socketEvents!==1){fail('multiple_socket');return;}socket=s;s.setTimeout(IDLE_MS,()=>fail('socket_idle_budget'));});
   deadline=timers.setTimeout(()=>fail('elapsed_budget'),BUDGET_MS);req.end();
  }catch(e){fail('request_construction',e);}
 });
}
function persistArtifact(fsApi,filename,bytes,digest,clock,started){
 // Fixed owned new file, wx+ (no overwrite). No entry paths used as sink names.
 let fd,closed=false,writeBytes=0,readBytes=0,problem=null;
 try{
  if(util.types.isProxy(bytes)||!Buffer.isBuffer(bytes)||lengthGet.call(bytes)!==assembly.LIMITS.maxCaptureBytes||sha(bytes)!==digest)throw Error('SNAPSHOT');
  fd=fsApi.openSync(filename,'wx+',0o600);
  while(writeBytes<bytes.length){if(Number(clock()-started)/1e6>BUDGET_MS)throw Error('ELAPSED');const n=fsApi.writeSync(fd,bytes,writeBytes,Math.min(65536,bytes.length-writeBytes),writeBytes);if(!Number.isInteger(n)||n<1||n>Math.min(65536,bytes.length-writeBytes))throw Error('WRITE');writeBytes+=n;}
  fsApi.fsyncSync(fd);const st=fsApi.fstatSync(fd);if(!st.isFile()||st.size!==bytes.length||st.nlink!==1)throw Error('FILE');
  const back=Buffer.alloc(bytes.length);while(readBytes<back.length){if(Number(clock()-started)/1e6>BUDGET_MS)throw Error('ELAPSED');const n=fsApi.readSync(fd,back,readBytes,Math.min(65536,back.length-readBytes),readBytes);if(!Number.isInteger(n)||n<1||n>Math.min(65536,back.length-readBytes))throw Error('READ');readBytes+=n;}
  if(sha(back)!==digest)throw Error('READBACK');
 }catch{problem='artifact_write_or_readback';}
 finally{if(fd!==undefined)try{fsApi.closeSync(fd);closed=true;}catch{problem='artifact_fd_close';}}
 if(!problem&&Number(clock()-started)/1e6>BUDGET_MS)problem='artifact_elapsed_after_close';
 if(problem||!closed)throw blocked(problem||'artifact_fd_unknown',{writeBytes,readBytes,fdClosed:closed,physicalErasureProven:false});
 return {writeBytes,readBytes,fdClosed:true,readbackSha256Matches:true,physicalErasureProven:false};
}
const OWNER='IcUJ8UMoJUKXJWiB',DELIVERABLE='ffmpeg-1013-one-raw-get-20261013-IcUJ8UMoJUKXJWiB',CONSENT_SCOPE='one-ffmpeg-raw-data-only-no-decompression';
function validateGateRecords(own,lock,state){
 const auth=state?.ffmpegFiniteInspectionAuthorization,review=state?.ffmpegRawWrapperReview;
 if(!own||own.sessionId!==OWNER||typeof own.nonce!=='string'||!/^[a-f0-9]{64}$/.test(own.nonce)||!lock||lock.sessionId!==OWNER||lock.nonce!==own.nonce)throw blocked('owner_or_bound_authority');
 const ownerNonceSha256=sha(Buffer.from(own.nonce));
 if(!auth||auth.ownerSessionId!==OWNER||auth.ownerNonceSha256!==ownerNonceSha256||auth.deliverableId!==DELIVERABLE||auth.scope!==CONSENT_SCOPE||auth.url!==URL||auth.expectedBytes!==assembly.LIMITS.maxCaptureBytes||auth.maximumGETAttempts!==1||auth.verifiedOriginalQuestionAndAnswer!==true||auth.oneFiniteAcquisition!==true||auth.pastNoonOnlyForThisFiniteDeliverable!==true||auth.newCIAuthorized!==false||auth.groupsGPGContainerExecutionExtractionSDKAuthorized!==false)throw blocked('owner_or_bound_authority');
 if(!review||review.status!=='pass'||review.ownerSessionId!==OWNER||review.ownerNonceSha256!==ownerNonceSha256||review.deliverableId!==DELIVERABLE||review.scope!==CONSENT_SCOPE||typeof review.independentReviewerId!=='string'||!review.independentReviewerId)throw blocked('bound_whole_wrapper_review_required');
 return {auth,review};
}
async function runApprovedOnce(){
 if(process.argv.length!==3||process.argv[2]!=='--approved-finite-once'||process.env.GITHUB_ACTIONS==='true')throw blocked('explicit_local_cli_required');
 const own=JSON.parse(fs.readFileSync(SESSION+'tmp/finite-ffmpeg-owner-token.json','utf8')),lock=JSON.parse(fs.readFileSync(ROOT+'TODAY_WORK_LOCK.json','utf8')),state=JSON.parse(fs.readFileSync(ROOT+'TASK_STATE.json','utf8'));
 const {review}=validateGateRecords(own,lock,state);for(const [name,pin]of Object.entries(review.sourcePins||{}))if(sha(fs.readFileSync(path.join(__dirname,name)))!==pin)throw blocked('reviewed_source_changed');
 if(!Object.hasOwn(review.sourcePins,'ffmpeg-raw-acquire-once.cjs')||!Object.hasOwn(review.sourcePins,'ffmpeg-raw-zip-metadata.cjs')||review.sourcePins['ffmpeg-byte-assembly-candidate.cjs']!=='33b171beb7a7f4eacd5c365f3305a29862c74cb689dd4c0626ac25a7d2a95b76')throw blocked('review_pin_set');
 const artifactDir=SESSION+'artifacts',archive=artifactDir+'/ffmpeg-linux-1013-observed.zip',metadata=artifactDir+'/ffmpeg-linux-1013-raw-observations.json';if(!fs.existsSync(artifactDir))fs.mkdirSync(artifactDir,{mode:0o700});const d=fs.lstatSync(artifactDir);if(!d.isDirectory()||d.isSymbolicLink())throw blocked('artifact_directory');if(fs.existsSync(archive)||fs.existsSync(metadata))throw blocked('artifact_exists');
 const marker=fs.openSync(SESSION+'tmp/ffmpeg-one-get-attempt.json','wx',0o600);try{fs.writeFileSync(marker,JSON.stringify({attemptAt:new Date().toISOString(),url:URL,scope:'ONE raw data-only attempt, no automatic retry'}));fs.fsyncSync(marker);}finally{fs.closeSync(marker);}
 const started=process.hrtime.bigint(),ensureBudget=stage=>{if(Number(process.hrtime.bigint()-started)/1e6>BUDGET_MS)throw blocked('complete_wrapper_elapsed_'+stage);};let transport,artifact,inspection,inspectionError=null;
 const captured=await captureRawResponse(https,{setTimeout,clearTimeout},()=>process.hrtime.bigint());transport=captured.transport;const bytes=captured.snapshot.bytes,digest=captured.snapshot.snapshotSha256;
 ensureBudget('before_artifact');if(sha(bytes)!==digest)throw blocked('private_snapshot_changed');artifact=persistArtifact(fs,archive,bytes,digest,()=>process.hrtime.bigint(),started);ensureBudget('after_artifact');
 ensureBudget('before_raw_parse');try{inspection=raw.inspectRawZIPMetadata(bytes);}catch(e){inspectionError=e.message===raw.ERROR?raw.ERROR:'RAW_METADATA_UNKNOWN';}ensureBudget('after_raw_parse');
 const result={kind:'actual_ffmpeg_raw_data_only_observation',at:new Date().toISOString(),url:URL,artifactPath:archive,observedByteLength:bytes.length,observedSha256:digest,transport,artifact,rawHeaderInspection:inspection||null,rawHeaderInspectionError:inspectionError,realGETAttempts:1,redirectsFollowed:0,cookiesOrCredentialsSupplied:false,contentInflated:false,entriesMaterialized:false,payloadExecuted:false,containerOperations:0,groupsSignaled:false,gpgInvoked:false,vendorAuthenticated:false,SDKOrBuildAdmitted:false,hardWallclockTerminationProven:false};
 ensureBudget('before_serialize');const meta=Buffer.from(JSON.stringify(result,null,2)+'\n');ensureBudget('after_serialize');if(meta.length>1048576)throw blocked('metadata_output_cap',{artifactPath:archive,observedByteLength:bytes.length,observedSha256:digest});let mfd,mclosed=false,mproblem=false;try{mfd=fs.openSync(metadata,'wx',0o600);fs.writeFileSync(mfd,meta);fs.fsyncSync(mfd);}catch{mproblem=true;}finally{if(mfd!==undefined)try{fs.closeSync(mfd);mclosed=true;}catch{mproblem=true;}}if(mproblem||!mclosed)throw blocked('metadata_write_or_close',{artifactPath:archive,observedByteLength:bytes.length,observedSha256:digest,metadataFDClosed:mclosed});ensureBudget('after_metadata_close');result.metadataFDClosed=true;result.metadataArtifactPath=metadata;const projected=JSON.stringify(result);ensureBudget('final_projection');console.log(projected);if(inspectionError)process.exitCode=2;
}
module.exports=Object.freeze({captureRawResponse,persistArtifact,validateGateRecords,OWNER,DELIVERABLE,CONSENT_SCOPE,URL,BUDGET_MS,GRACE_MS,IDLE_MS,ERROR});
if(require.main===module)runApprovedOnce().catch(e=>{console.log(JSON.stringify({kind:'ffmpeg_raw_data_only_blocked',fixed:e.message===ERROR?e.fixed:'unexpected',observation:e.message===ERROR?e.observed:null,realGETRetry:false,groupsSignaled:false,gpgInvoked:false,payloadExecuted:false,entriesMaterialized:false,contentInflated:false,physicalErasureProven:false}));process.exitCode=2;});
