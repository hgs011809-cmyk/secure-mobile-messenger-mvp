// Insert only after genuine SDK/SAS/cold-reauth descriptor gates, before destructive gates.
// Actual control authority stays parent RAM; child receives ciphertext/manifest only.
stage='SDK process live candidate ciphertext';
if(process.platform!=='linux'||!process.env.PRIVATE_ATTACHMENT_ROOT)throw Error('LIVE_PRIVATE_ROOT_REQUIRED');
const liveBase=process.env.PRIVATE_ATTACHMENT_ROOT;
const liveBaseStat=await liveFs.lstat(liveBase);
assert(liveBaseStat.isDirectory()&&!liveBaseStat.isSymbolicLink()&&liveBaseStat.uid===process.getuid()&&(liveBaseStat.mode&0o7777)===0o700);
const liveRoot=await liveFs.mkdtemp(path.join(liveBase,'sdk-process-live-'));liveRoots.add(liveRoot);await liveFs.chmod(liveRoot,0o700);
const liveSource=path.join(liveRoot,'source');await liveFs.mkdir(liveSource,{mode:0o700});
const liveReceiver=path.join(liveRoot,'receiver');await liveFs.mkdir(liveReceiver,{mode:0o700});
const liveHashes=[];let liveIndex=0;
async function* livePlain(){for(let i=0;i<32;i++){const p=Buffer.alloc(262144);for(let j=0;j<p.length;j++)p[j]=(i*29+j*13+7)&255;try{yield p;}finally{p.fill(0);}}}
const liveEncrypted=await encryptStream({source:livePlain(),authorize:async()=>true,maxBytes:8388608,chunkBytes:262144,writeCiphertext:async bytes=>{
 assert(bytes.length===262144&&liveIndex<32);const copy=Buffer.from(bytes);liveHashes.push(liveSha(copy));await liveFs.writeFile(path.join(liveSource,'cipher-'+liveIndex++),copy,{mode:0o600,flag:'wx'});
}});
assert(liveEncrypted.bytes===8388608&&liveIndex===32);
const liveEvent=await call(alice,'descriptorSend',{descriptor:liveEncrypted.descriptor});
const liveReceipt=sealTransportReceipt(await call(bob,'transportExport',{event:liveEvent}));
assert(JSON.stringify(liveReceipt.descriptor)===JSON.stringify(liveEncrypted.descriptor));
const liveManifest={version:1,transferId:randomBytes(16).toString('hex'),bindingId:liveSha(JSON.stringify(['sdk-process-live-v1',liveReceipt.eventId,liveReceipt.roomId,liveReceipt.senderUserId,liveReceipt.senderDeviceId])),totalBytes:8388608,chunkBytes:262144,sha256:Buffer.from(liveReceipt.descriptor.hashes.sha256,'base64').toString('hex'),expiresAt:Date.now()+8*60*1000};
// Mapping is exact: broker session.deviceId is Matrix ID; ids[n] is native ID.
const liveSender={userId:a.userId,matrixDeviceId:a.deviceId,deviceId:ids[0],accessToken:a.accessToken};
const liveRecipient={userId:b.userId,matrixDeviceId:b.deviceId,deviceId:ids[1],accessToken:b.accessToken};
async function liveOpen(){
 const ctl=new AbortController();let owned=null,adapter=null,closeRequested=false,closeTask=null;
 const startClose=()=>{closeRequested=true;ctl.abort();if(owned&&!closeTask){closeTask=owned.close();closeTask.catch(()=>{liveCleanupFailed=true;});}};
 const handle={async close(){startClose();adapter?.close();if(owned){await(closeTask??owned.close());await owned.exited;}}};
 // Retain handle before factory/startup: always cleanup sees any acquired child.
 liveHandles.add(handle);
 try{
  adapter=await createSdkProcessAuthority({broker,issuer,registry,lifecycle,recipientPage:bob.page,sender:liveSender,recipient:liveRecipient,originalReceipt:liveReceipt,transferId:liveManifest.transferId,bindingId:liveManifest.bindingId,signal:ctl.signal,deadline:Date.now()+1500,terminateOwnedChannel:startClose});
  if(closeRequested)throw Error('SESSION_CLOSED');
  owned=await openCiphertextSession({root:liveReceiver,manifest:liveManifest,authorize:adapter.authorize});
  // Retain a close request made while openCiphertextSession waited for ready.
  if(closeRequested){startClose();await handle.close();throw Error('SESSION_CLOSED');}
  await owned.command('initialize',{manifest:liveManifest});
  return {session:owned,close:()=>handle.close()};
 }catch{await handle.close();throw Error('LIVE_SESSION_OPEN_DENIED');}
}
async function livePreserved(){
 for(let i=0;i<32;i++)assert(liveSha(await liveFs.readFile(path.join(liveSource,'cipher-'+i)))===liveHashes[i]);
}
async function liveAccept(s,i){const b=await liveFs.readFile(path.join(liveSource,'cipher-'+i));assert(b.length===262144&&liveSha(b)===liveHashes[i]);return s.command('accept',{index:i,offset:i*262144,hex:b.toString('hex'),sha256:liveHashes[i]});}
let live=await liveOpen();for(let i=0;i<16;i++)assert((await liveAccept(live.session,i)).accepted===true);
const priorLivePid=live.session.pid;await live.close();await live.session.exited;
live=await liveOpen();assert(live.session.pid!==priorLivePid);
const liveResumed=await live.session.command('resume');assert(liveResumed.totalBytes===4194304&&liveResumed.present.length===16&&liveResumed.present.every((v,i)=>v===i));
assert((await liveAccept(live.session,15)).repeated===true);
for(let i=16;i<32;i++)assert((await liveAccept(live.session,i)).accepted===true);
const liveFinal=await live.session.command('finalize');assert(liveFinal.complete===true&&liveFinal.totalBytes===8388608);
// Independent parent full ciphertext hash, no plaintext path or descriptor child IPC.
const liveWhole=createHash('sha256');for(let i=0;i<32;i++){const b=await liveFs.readFile(path.join(liveReceiver,liveManifest.transferId,'chunk-'+i+'.bin'));assert(b.length===262144&&liveSha(b)===liveHashes[i]);liveWhole.update(b);}assert(liveWhole.digest('hex')===liveManifest.sha256);await livePreserved();
liveGates.push('actual-authority-candidate-child-ACK-idle-exit-differentPID-resume16-duplicate-fullcipherhash');
stage='SDK process live candidate redaction';
await call(bob,'remove',{event:liveEvent});await call(bob,'deleted',{event:liveEvent});
assert(await resolve(a.accessToken)&&await resolve(b.accessToken));
const liveRedacted=await call(bob,'transportAuthorityStatus',{event:liveEvent});assert(liveRedacted.allowed===false&&liveRedacted.stage==='REDACTED');
// Exploratory observation ONLY: generic SESSION_CLOSED cannot attribute closure
// to actual authority denial rather than deadline/protocol/exit/command timer.
let liveExploratoryCode='NO_ERROR';try{await live.session.command('resume');}catch(e){liveExploratoryCode=e?.message==='SESSION_CLOSED'?'SESSION_CLOSED':'OTHER_ERROR';}
await live.close();await live.session.exited;await livePreserved();
liveRedactionObservation={acceptance:'BLOCKED',countedGate:false,observedCode:liveExploratoryCode,closureCause:'UNKNOWN',authorityDenialEstablished:false};
// No redaction success gate. Timeouts/unattributed closures are NOT acceptance.
// No decrypt callback exists here: NOT zero-plaintext negative instrumentation.
