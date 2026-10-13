'use strict';
// SOURCE-ONLY pure adapter for retained direct-foreground gpgv transcript bytes.
// No command execution or proof of who retained bytes; receipt flags are declarations.
const crypto=require('node:crypto');
const types=require('node:util').types;
const isProxy=types.isProxy,isShared=types.isSharedArrayBuffer,isBuffer=Buffer.isBuffer,allocBuffer=Buffer.alloc;
const typedProto=Object.getPrototypeOf(Uint8Array.prototype),taLength=Object.getOwnPropertyDescriptor(typedProto,'length').get,taBacking=Object.getOwnPropertyDescriptor(typedProto,'buffer').get,taSet=Uint8Array.prototype.set;
const ownKeys=Reflect.ownKeys,getProto=Object.getPrototypeOf,getDesc=Object.getOwnPropertyDescriptor,anchor=require('./ubuntu-anchor-preflight.cjs');
const CAPS=Object.freeze({receipt:32768,status:1048576,release:1048576,stderr:262144,input:1048576});
function fail(){const e=new Error('TRANSCRIPT_BLOCKED');e.code='invalid_transcript';throw e;}
function guarded(fn){try{return fn();}catch{fail();}}
function exact(o,keys){if(!o||typeof o!=='object'||isProxy(o)||getProto(o)!==Object.prototype)fail();const ks=ownKeys(o);if(ks.length!==keys.length||ks.some(k=>typeof k!=='string'||!keys.includes(k)))fail();for(const k of keys){const d=getDesc(o,k);if(!d||!('value'in d))fail();}return o;}
function digest(b){return crypto.createHash('sha256').update(b).digest('hex');}
function privateBytes(v,cap){if(isProxy(v))fail();if(!isBuffer(v)||getProto(v)!==Buffer.prototype)fail();const n=Reflect.apply(taLength,v,[]);if(!Number.isSafeInteger(n)||n>cap||isShared(Reflect.apply(taBacking,v,[])))fail();const ks=ownKeys(v);if(ks.length!==n||ks.some((k,i)=>k!==String(i)))fail();const copy=Reflect.apply(allocBuffer,Buffer,[n]);Reflect.apply(taSet,copy,[v]);return copy;}
function bind(x,b){exact(x,['bytes','sha256']);if(!Number.isSafeInteger(x.bytes)||x.bytes!==b.length||typeof x.sha256!=='string'||!/^[a-f0-9]{64}$/.test(x.sha256)||x.sha256!==digest(b))fail();}
function canonicalJSON(s){if(typeof s!=='string'||Buffer.byteLength(s,'utf8')>CAPS.receipt)fail();let d=0,q=false,e=false;for(let i=0;i<s.length;i++){const c=s.charCodeAt(i);if(q){if(e)e=false;else if(c===92)e=true;else if(c===34)q=false;}else if(c===34)q=true;else if(c===123||c===91){if(++d>12)fail();}else if(c===125||c===93){if(--d<0)fail();}}if(q||d)fail();let v;try{v=JSON.parse(s);}catch{fail();}let canonical;try{canonical=JSON.stringify(v);}catch{fail();}if(canonical!==s)fail();return v;}
function freeze(v){if(v&&typeof v==='object'&&!Object.isFrozen(v)){for(const k of Object.keys(v))freeze(v[k]);Object.freeze(v);}return v;}
function adaptTranscript(receiptText,retained){return guarded(()=>{
 const r=canonicalJSON(receiptText);exact(r,['kind','version','gpgv','status','stderr']);if(r.kind!=='direct_foreground_gpgv_transcript'||r.version!==1)fail();exact(r.gpgv,['id','input','output','exitCode','signal','timeout','closed']);if(r.gpgv.id!=='gpgv'||r.gpgv.exitCode!==0||r.gpgv.signal!==null||r.gpgv.timeout!==false||r.gpgv.closed!==true)fail();
 exact(retained,['signedInput','releaseOutput','status','stderr']);const b={signedInput:privateBytes(retained.signedInput,CAPS.input),releaseOutput:privateBytes(retained.releaseOutput,CAPS.release),status:privateBytes(retained.status,CAPS.status),stderr:privateBytes(retained.stderr,CAPS.stderr)};
 bind(r.gpgv.input,b.signedInput);bind(r.gpgv.output,b.releaseOutput);bind(r.status,b.status);bind(r.stderr,b.stderr);
 const signed=anchor.clearSignedProfile(b.signedInput),status=anchor.statusProjection(b.status),rel=anchor.releaseScope(b.releaseOutput);const statusSequenceConsistent=status.verified===true;if(!statusSequenceConsistent||rel.expectedNobleScope!==true||b.releaseOutput.length>signed.conservativeOutputBytes)fail();
 // Narrow source-profile correlation only: CRLF normalization and RFC cleartext
 // dash-unescaping must yield the retained Release. This is NOT verification.
 const signedText=b.signedInput.toString('ascii').replace(/\r\n/g,'\n'),bodyStart=signedText.indexOf('\n\n')+2,bodyEnd=signedText.indexOf('\n-----BEGIN PGP SIGNATURE-----\n',bodyStart);
 const declaredBody=signedText.slice(bodyStart,bodyEnd+1).replace(/^- /gm,'');
 if(declaredBody!==b.releaseOutput.toString('ascii').replace(/\r\n/g,'\n'))fail();
 return freeze({kind:'retained_direct_foreground_gpgv_transcript_projection',version:1,stageOrder:['direct_foreground_gpgv','pure_parser'],gpgvCompletionDeclared:true,parserStage:'pure_node_projection',cleartextProfileCorresponds:true,signedInputProfile:{signaturePacketCount:signed.signaturePacketCount,cleartextBodyBytes:signed.cleartextBodyBytes,cryptographicVerification:false},statusSequenceConsistent,cryptographicVerification:false,trustedSigner:false,currentSignerAllowlistChecked:false,freshnessChecked:false,fullDebianChainChecked:false,buildAcceptance:false,sourceResourceClosureProven:false,releaseCandidate:{expectedNobleScope:true,releaseDateInformationalOnly:true,checksumEntryCounts:rel.checksumEntryCounts},retainedByteHashes:{signedInput:digest(b.signedInput),releaseOutput:digest(b.releaseOutput),status:digest(b.status),stderr:digest(b.stderr)},retainedByteCounts:{signedInput:b.signedInput.length,releaseOutput:b.releaseOutput.length,status:b.status.length,stderr:b.stderr.length},statusCounts:status.counts,signatureClasses:status.signatureClasses});
 });}
module.exports=Object.freeze({adaptTranscript,CAPS});
