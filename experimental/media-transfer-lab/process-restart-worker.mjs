// Synthetic-only POSIX fixture. Trusted single owner and serial IPC, not SDK auth.
import {SyntheticReceiver} from './receiver.mjs';
import {decryptVerifiedStream} from './attachment-stream.mjs';
import {createHash} from 'node:crypto';
const CHUNK=256*1024, TOTAL=8*1024*1024;
const CODES=new Set(['not_authorized','manifest_changed']);
const COMMANDS=new Set(['initialize','accept','resume','finish','shutdown']);
let receiver,descriptor,expected,tempRoot,allowed,initialized=false,initializationCode='WORKER_FAILED';
let busy=false,nextId=1,plaintextCalls=0,plaintextBytes=0;
const sha=b=>createHash('sha256').update(b).digest('hex');
const fields=(o,n)=>o&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).sort().join(',')===n.sort().join(',');
function response(id,code='ok',extra={}) {
  return {id,code,pid:process.pid,accepted:false,repeated:false,count:0,totalBytes:0,
    contiguous:false,complete:false,hashMatches:false,plaintextCalls,plaintextBytes,maxPayload:0,idle:true,...extra};
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
  busy=true;nextId++;
  let out,stop=false;
  try {
    if(m.command==='initialize') {
      if(receiver||!fields(m,['id','command','root','manifest','descriptor','expected','tempRoot','mockAllowed'])||
        typeof m.mockAllowed!=='boolean'||typeof m.expected!=='string'||!/^[a-f0-9]{64}$/.test(m.expected)||
        m.manifest?.totalBytes!==TOTAL||m.manifest?.chunkBytes!==CHUNK) throw 0;
      allowed=m.mockAllowed;descriptor=m.descriptor;expected=m.expected;tempRoot=m.tempRoot;
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
        async function* source() {
          await receiver.resume();
          for(let i=0;i<32;i++) {
            await receiver.guard();const b=await receiver.read(i);await receiver.guard();
            if(b.length!==CHUNK) throw 0;
            yield b;
          }
        }
        const actual=createHash('sha256');
        const dec=await decryptVerifiedStream({source:source(),descriptor,tempRoot,maxBytes:TOTAL,chunkBytes:CHUNK,
          authorize:async()=>allowed,writePlaintext:async b=>{
            if(b.length>CHUNK) throw 0;
            plaintextCalls++;plaintextBytes+=b.length;actual.update(b);
          }});
        out=response(m.id,'ok',{complete:final.complete,totalBytes:final.totalBytes,
          hashMatches:actual.digest('hex')===expected,maxPayload:Math.max(dec.maxPayload,receiver.maxPayloadBytes)});
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
