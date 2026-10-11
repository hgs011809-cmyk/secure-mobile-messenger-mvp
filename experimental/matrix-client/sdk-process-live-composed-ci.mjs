// NEW read-and-transform candidate. No existing source/workflow mutation.
import fs from 'node:fs/promises';
const root=new URL('./',import.meta.url);
const original=new URL('./transport-composed-ci.mjs',root);
function once(source,anchor,value){if(source.split(anchor).length!==2)throw Error('LIVE_DRIVER_ANCHOR_DENIED');return source.replace(anchor,value);}
function range(source,start,end,value){if(source.split(start).length!==2||source.split(end).length!==2)throw Error('LIVE_DRIVER_RANGE_DENIED');const from=source.indexOf(start),to=source.indexOf(end);if(to<=from)throw Error('LIVE_DRIVER_RANGE_DENIED');return source.slice(0,from)+value+source.slice(to);}
export async function generateLiveSource(){
 let source=await fs.readFile(original,'utf8');
 const driver=await fs.readFile(new URL('./sdk-process-live-driver.inc.mjs',root),'utf8');
 source=once(source,"import {prepareTransportFixture,attachTransportReceiver} from './transport-pipeline.mjs';",`import {createSdkProcessAuthority} from './sdk-process-authority.mjs';
import {openCiphertextSession} from './sdk-process-session.mjs';
import * as liveFs from 'node:fs/promises';
const liveRoots=new Set(),liveHandles=new Set(),liveGates=[];let liveCleanupFailed=false,liveRedactionObservation={acceptance:'BLOCKED',countedGate:false,observedCode:'NOT_RUN',closureCause:'UNKNOWN',authorityDenialEstablished:false};
const liveSha=b=>createHash('sha256').update(b).digest('hex');`);
 source=once(source,'const transportFixtures=new Set(),transportGates=[];','');
 source=once(source,'async function assertTransportPreserved(session){const p=await session.checkPreserved();assert(p.sourcePreserved===true&&p.receiverPreserved===true&&p.quarantineEmpty===true);return true;}','');
 source=range(source,' // Actual SDK control plane, private in-process ciphertext data plane; not MXC transport.',' stage=\'sender closed peer redaction through ingress\';',driver+'\n');
 source=range(source,"stage='authenticated transport actual native revoked lease';"," console.log(JSON.stringify({status:'passed',gates,descriptorGates,transportGates,",'');
 // Retain old admission/descriptor stages, but never report removed transport proof.
 const summaryStart=" console.log(JSON.stringify({status:'passed',gates,descriptorGates,transportGates,";
 source=range(source,summaryStart,'}catch{console.log(JSON.stringify({completedGates:',` console.log(JSON.stringify({status:'candidate_driver_completed_not_acceptance',gates,descriptorGates,liveGates,liveAcceptedGateCount:liveGates.length,liveRedactionObservation,redactionAcceptanceBlocked:true,liveFixtureBytes:8388608,liveChunkBytes:262144,childBoundary:'parent-survives-ACK-idle-only',parentPlaintextIntegration:false,actualMXC:false,productionIntegration:false,atomicAuthority:false}));\n`);
 source=once(source,'completedTransportGates:transportGates','completedLiveGates:liveGates,liveRedactionObservation,redactionAcceptanceBlocked:true');
 source=once(source,"finally{let fixtureCleanupFailed=false;for(const f of transportFixtures)try{await f.dispose();}catch{fixtureCleanupFailed=true;}if(fixtureCleanupFailed){console.log('transport_fixture_cleanup_failed=true');process.exitCode=1;}",`finally{for(const h of liveHandles)try{await h.close();}catch{liveCleanupFailed=true;}
// NEVER remove fixture roots unless every owned child close/exit was observed.
if(!liveCleanupFailed){for(const r of liveRoots)try{await liveFs.rm(r,{recursive:true,force:true});try{await liveFs.lstat(r);liveCleanupFailed=true;}catch(e){if(e?.code!=='ENOENT')liveCleanupFailed=true;}}catch{liveCleanupFailed=true;}}
console.log(JSON.stringify({liveOwnedExitObserved:!liveCleanupFailed,livePrivateNamespaceAbsent:!liveCleanupFailed,independentAlwaysCleanup:false}));if(liveCleanupFailed)process.exitCode=1;`);
 // Change only genuine harness page references. All relative imports retain ORIGINAL basis.
 source=source.replaceAll('/transport.html','/sdk-process-live.html');
 source=source.replaceAll('import.meta.url',JSON.stringify(original.href));
 source=source.replace(/(from\s+['"])(\.[^'"]+)(['"])/g,(_m,a,s,b)=>a+new URL(s,original).href+b);
 if(source.includes('transportSession')||source.includes('transportGates')||source.includes('prepareTransportFixture')||source.includes('attachTransportReceiver'))throw Error('LIVE_OLD_PROOF_REMAINS');
 return source;
}
// Explicit candidate runner opt-in only. Generation is safe read-only for review.
if(process.env.SDK_PROCESS_LIVE_EXECUTE==='true'){
 if(process.env.GITHUB_ACTIONS!=='true'||process.platform!=='linux')throw Error('LIVE_CI_ONLY');
 const source=await generateLiveSource();await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
}
