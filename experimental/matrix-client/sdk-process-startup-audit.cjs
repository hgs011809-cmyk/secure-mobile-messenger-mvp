'use strict';
// Read-only STATIC audit. Never imports/runs audited modules or inspects /proc.
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const pins=Object.freeze({
 'sdk-process-session.mjs':'2bd744ff5d414294d6058db924b67f3ef63860c71419e2bd051e1cb796ccec8b',
 'sdk-process-worker.mjs':'3e974b3dfe9137abe37afe6a5200fa8bbbcbd71d0f2c135e5591e1e957bf47e8',
 'transport-composed-ci.mjs':'f13f7b42278e8448e4ed97e056473ca01c59afa21785456b3eb3a84d3d1dab88',
 'sdk-process-live-composed-ci.mjs':'8259eac1a59fe662dc2dffdfc017962b12f2b2ff000a0faee70e659fb701acc8',
 'sdk-process-live-driver.inc.mjs':'7308eeca80ffc817fb23ef3a4fdb5910c4b9cca932cdb2dcbfc1af2065d8c295',
 'SDK_PROCESS_LIVE_CI.md':'69c5c8350e400a91065a54d5e98c57a1421ca23caa00e86eb010503abb5617bb'
});
const anchors=Object.freeze([
 ['sdk-process-session.mjs'," const child=fork(worker,['--sdk-process-root='+root],{stdio:['ignore','ignore','ignore','ipc'],execArgv:[],serialization:'json',env:{TZ:'UTC'}});"],
 ['sdk-process-session.mjs',' const exited=once(child,\'exit\');'],
 ['sdk-process-worker.mjs',"const stat=await fs.readFile('/proc/self/stat','utf8');"],
 ['sdk-process-worker.mjs',"await fs.writeFile(path.join(root,'owned-child-'+process.pid+'.json'),JSON.stringify({pid:process.pid,root,start}),{mode:0o600,flag:'wx'});"],
 ['transport-composed-ci.mjs',"const context=await chromium.launchPersistentContext(profile,{headless:true,serviceWorkers:'block'});contexts.add(context);"],
 ['transport-composed-ci.mjs',"const pa=await mkdtemp(path.join(tmpdir(),'composed-a-')),pb=await mkdtemp(path.join(tmpdir(),'composed-b-'));profiles.push(pa,pb);"],
 ['sdk-process-live-composed-ci.mjs',"const original=new URL('./transport-composed-ci.mjs',root);"],
 ['sdk-process-live-composed-ci.mjs',"source=source.replaceAll('import.meta.url',JSON.stringify(original.href));"],
 ['sdk-process-live-driver.inc.mjs','owned=await openCiphertextSession({root:liveReceiver,manifest:liveManifest,authorize:adapter.authorize});'],
 ['sdk-process-live-driver.inc.mjs','liveHandles.add(handle);']
]);
function denied(code){const e=new Error(code);e.auditCode=code;throw e;}
try{
 const source=Object.create(null);
 for(const [name,hash] of Object.entries(pins)){
  const target=path.join(__dirname,name),st=fs.lstatSync(target);
  if(!st.isFile()||st.isSymbolicLink())denied('STATIC_FILE_DENIED');
  const bytes=fs.readFileSync(target);
  if(createHash('sha256').update(bytes).digest('hex')!==hash)denied('STATIC_SOURCE_PIN_DENIED');
  source[name]=bytes.toString('utf8');
 }
 for(const [name,anchor] of anchors)if(source[name].split(anchor).length!==2)denied('STATIC_ANCHOR_DENIED');
 // Relationships only. Cross-process happens-before cannot be inferred from source order.
 const session=source['sdk-process-session.mjs'],worker=source['sdk-process-worker.mjs'],driver=source['sdk-process-live-driver.inc.mjs'];
 if(session.indexOf(anchors[0][1])>=session.indexOf(anchors[1][1])||worker.indexOf(anchors[2][1])>=worker.indexOf(anchors[3][1])||driver.indexOf(anchors[9][1])>=driver.indexOf(anchors[8][1]))denied('STATIC_ORDER_DENIED');
 console.log(JSON.stringify({status:'static_audit_verified_runtime_blocked',sourcePinsChecked:6,sourcePinsMatched:6,exactOnceAnchorsChecked:10,exactOnceAnchorsMatched:10,sourceOrderChecks:3,sourceOrderChecksMatched:3,runtimeTests:0,processesLaunched:0,browserLaunches:0,containersCreated:0,transformsGenerated:0,filesWritten:0,preExecutionBirthOwnershipEstablished:false,independentAbruptParentCleanupEstablished:false,actualSdkProcessAcceptance:false,blockedCodes:['CHILD_SPAWN_BEFORE_BIRTH_MARKER','BROWSER_BIRTH_IDENTITY_UNAVAILABLE','INDEPENDENT_CONTAINMENT_NOT_ESTABLISHED']}));
}catch(e){
 const allowed=new Set(['STATIC_FILE_DENIED','STATIC_SOURCE_PIN_DENIED','STATIC_ANCHOR_DENIED','STATIC_ORDER_DENIED']);
 console.log(JSON.stringify({status:'static_audit_failed',code:allowed.has(e.auditCode)?e.auditCode:'STATIC_READ_DENIED',runtimeTests:0,processesLaunched:0,filesWritten:0}));
 process.exitCode=1;
}
