// Ciphertext-only owned fork; no SDK tokens/receipt/descriptor/key/plaintext IPC.
import {promises as fs} from 'node:fs';
import path from 'node:path';
import {SyntheticReceiver,validateManifest} from '../media-transfer-lab/receiver.mjs';
import {OPS,CODES,exact,context,same} from './sdk-process-protocol.mjs';
const root=process.argv[2]?.replace(/^--sdk-process-root=/,'');
if(process.platform!=='linux'||process.argv.length!==3||!path.isAbsolute(root||'')||!process.send)process.exit(2);
const st=await fs.lstat(root);if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&4095)!==448)process.exit(2);
const stat=await fs.readFile('/proc/self/stat','utf8');const start=stat.slice(stat.lastIndexOf(')')+2).split(' ')[19];
await fs.writeFile(path.join(root,'owned-child-'+process.pid+'.json'),JSON.stringify({pid:process.pid,root,start}),{mode:0o600,flag:'wx'});
let c=null,r=null,seq=0,request=0,checkpoint=0,busy=false,denied=false,waiting=null;
const send=m=>{if(process.connected)process.send(m);};
const fatal=()=>{denied=true;if(waiting){clearTimeout(waiting.timer);waiting.reject(Error('PROTOCOL_DENIED'));waiting=null;}process.exitCode=2;process.disconnect();};
process.on('disconnect',()=>process.exit(2));
const auth=async()=>{if(denied||waiting)throw Error('SESSION_DENIED');const q={type:'authority',context:c,command:seq,request:++request,checkpoint:++checkpoint,deadline:Date.now()+1500};return await new Promise((resolve,reject)=>{waiting={q,resolve,reject,timer:setTimeout(()=>{fatal();},1500)};send(q);});};
process.on('message',async m=>{
 if(m?.type==='decision'){
  const w=waiting;if(!w||!exact(m,['type','context','command','request','checkpoint','deadline','allowed'])||!same(m.context,c)||m.command!==w.q.command||m.request!==w.q.request||m.checkpoint!==w.q.checkpoint||m.deadline!==w.q.deadline||Date.now()>=m.deadline||typeof m.allowed!=='boolean'){fatal();return;}
  clearTimeout(w.timer);waiting=null;w.resolve(m.allowed);return;
 }
 if(!exact(m,['type','context','seq','op','payload'])||m.type!=='command'||!context(m.context)||!OPS.has(m.op)||busy||m.seq!==seq+1||(c&&!same(c,m.context))){fatal();return;}
 seq=m.seq;checkpoint=0;busy=true;if(!c)c=m.context;
 let result;
 try{
  if(denied)throw Error('SESSION_DENIED');
  if(m.op==='initialize'){
   if(r||!exact(m.payload,['manifest']))throw Error('PROTOCOL_DENIED');
   const manifest=validateManifest(m.payload.manifest);if(manifest.transferId!==c.transferId||manifest.bindingId!==c.bindingId)throw Error('PROTOCOL_DENIED');
   r=new SyntheticReceiver({root,manifest,authorize:auth});try{await r.initialize();}catch(e){denied=true;throw e;}result={initialized:true};
  }else{
   if(!r)throw Error('PROTOCOL_DENIED');
   if(m.op==='accept'){
    if(!exact(m.payload,['index','offset','hex','sha256'])||typeof m.payload.hex!=='string'||m.payload.hex.length>524288||!/^[a-f0-9]+$/.test(m.payload.hex)||m.payload.hex.length%2)throw Error('PROTOCOL_DENIED');
    const {index,offset,hex,sha256}=m.payload;result=await r.accept({index,offset,bytes:Buffer.from(hex,'hex'),sha256});
   }else{if(!exact(m.payload,[]))throw Error('PROTOCOL_DENIED');result=await r[m.op]();}
  }
  send({type:'result',context:c,seq,ok:true,result});
 }catch(e){if(m.op==='initialize')denied=true;const code=CODES.has(e.message)?e.message:'PROTOCOL_DENIED';send({type:'result',context:c,seq,ok:false,code});if(code==='PROTOCOL_DENIED'||code==='AUTH_TIMEOUT')denied=true;}
 finally{busy=false;}
});
send({type:'ready',pid:process.pid,environmentIsolated:process.env.SDK_PROCESS_PARENT_SECRET===undefined});
