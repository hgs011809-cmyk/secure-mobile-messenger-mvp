// Synthetic-only Linux SIGKILL at API boundaries; not power loss or repair.
// Keys/descriptors/plaintext remain in parent RAM; child receives ciphertext only.
// Synthetic-only POSIX fixture. Trusted single owner and serial IPC, not SDK auth.
import {SyntheticReceiver} from './receiver.mjs';
import {promises as fs} from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const CHUNK=256*1024, TOTAL=8*1024*1024;
const CODES=new Set(['not_authorized','manifest_changed','incomplete','integrity_failed','conflicting_retry']);
const COMMANDS=new Set(['initialize','accept','resume','finish','shutdown']);
let receiver,allowed,initialized=false,initializationCode='WORKER_FAILED';
let activeId=0;
let busy=false,nextId=1,plaintextCalls=0,plaintextBytes=0;
const sha=b=>createHash('sha256').update(b).digest('hex');
const fields=(o,n)=>o&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).sort().join(',')===n.sort().join(',');
function response(id,code='ok',extra={}) {
  return {id,code,pid:process.pid,accepted:false,repeated:false,count:0,totalBytes:0,
    contiguous:false,complete:false,hashMatches:false,plaintextCalls,plaintextBytes,maxPayload:0,idle:true,boundaryLength:0,...extra};
}
function send(out,stop=false) {
  if(!process.connected) return process.exit(1);
  process.send(out,error=>{
    if(error) process.exit(1);
    else if(stop) {process.disconnect();process.exit(0);}
  });
}
process.on('disconnect',()=>process.exit(0));
process.on('uncaughtException',()=>process.exit(1));
process.on('unhandledRejection',()=>process.exit(1));
process.on('message',async m=>{
  // Never emit raw errors, payloads, paths, hashes, keys or descriptors.
  if(busy||!m||!Number.isSafeInteger(m.id)||m.id!==nextId||!COMMANDS.has(m.command)) return process.exit(1);
  busy=true;activeId=m.id;nextId++;
  let out,stop=false;
  try {
    if(m.command==='initialize') {
      if(receiver||!fields(m,['id','command','root','manifest','fault','mockAllowed'])||
        typeof m.mockAllowed!=='boolean'||!['none','partial','full'].includes(m.fault)||
        m.manifest?.totalBytes!==TOTAL||m.manifest?.chunkBytes!==CHUNK) throw 0;
      allowed=m.mockAllowed; installFault(m.root,m.manifest.transferId,m.fault);
      receiver=new SyntheticReceiver({root:m.root,manifest:m.manifest,authorize:async()=>allowed,clock:()=>1000});
      await receiver.initialize();initialized=true;out=response(m.id);
    } else if(m.command==='shutdown') {
      if(!fields(m,['id','command'])) throw 0;
      stop=true;out=response(m.id);
    } else {
      if(!receiver) throw 0;
      if(m.command==='accept') {
        if(!fields(m,['id','command','index','bytes'])||!Number.isInteger(m.index)||m.index<0||m.index>=32||
          !Buffer.isBuffer(m.bytes)||m.bytes.length!==CHUNK) throw 0;
      } else if(!fields(m,['id','command'])) throw 0;
      // Failed initialization never enters acceptance or plaintext callbacks.
      if(!initialized) throw new Error(initializationCode);
      if(m.command==='accept') {
        const ack=await receiver.accept({index:m.index,offset:m.index*CHUNK,bytes:m.bytes,sha256:sha(m.bytes)});
        out=response(m.id,'ok',{accepted:ack.accepted,repeated:ack.repeated,maxPayload:receiver.maxPayloadBytes});
      } else if(m.command==='resume') {
        if(!fields(m,['id','command'])) throw 0;
        const s=await receiver.resume();
        out=response(m.id,'ok',{count:s.present.length,totalBytes:s.totalBytes,contiguous:s.present.every((v,i)=>v===i)});
      } else if(m.command==='finish') {
        if(!fields(m,['id','command'])) throw 0;
        const final=await receiver.finalize();
        out=response(m.id,'ok',{complete:final.complete,totalBytes:final.totalBytes,hashMatches:true,maxPayload:receiver.maxPayloadBytes});
      } else throw 0;
    }
  } catch(e) {
    const code=CODES.has(e?.message)?e.message:'WORKER_FAILED';
    if(m.command==='initialize'&&!initialized)initializationCode=code;
    out=response(m.id,code);
  }
  busy=false; // ACKNOWLEDGED IDLE: all receiver/decrypt awaits settled before response.
  send(out,stop);
});

// Only this dedicated child's shared fs.promises object is wrapped. No core patches.
// Partial: real short write completes, then park before sync/close/rename.
// Full: receiver writeFile/sync/close have settled, park before real rename.
function installFault(root,id,fault) {
  if(fault==='none')return;
  const target=path.join(root,id,'chunk-16.bin.pending');
  const realOpen=fs.open.bind(fs),realRename=fs.rename.bind(fs);
  let fired=false;
  async function park(length) {
    if(fired)throw Error('WORKER_FAILED');fired=true;
    const st=await fs.lstat(target);
    if(!st.isFile()||st.isSymbolicLink()||st.size!==length||(st.mode&0o7777)!==0o600||st.uid!==process.getuid())throw Error('WORKER_FAILED');
    send(response(activeId,'boundary',{idle:false,boundaryLength:length}));
    await new Promise(()=>{}); // Parent must SIGKILL. No artificial error/recovery path.
  }
  if(fault==='partial')fs.open=async function(file,...args) {
    const h=await realOpen(file,...args);
    if(file===target)h.writeFile=async function(data) {
      if(!Buffer.isBuffer(data)||data.length!==CHUNK)throw Error('WORKER_FAILED');
      let n=0;const length=CHUNK/2;
      while(n<length){const r=await h.write(data,n,length-n,n);if(r.bytesWritten<=0)throw Error('WORKER_FAILED');n+=r.bytesWritten;}
      await park(length);
    };
    return h;
  };
  if(fault==='full')fs.rename=async function(from,to) {
    if(from===target)await park(CHUNK);
    return realRename(from,to);
  };
}
