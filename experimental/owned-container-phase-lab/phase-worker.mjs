import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { request, witness, transition, caseResult, processFact, namespaces, NONCE } from './phase-worker-contract.mjs';
// Fixed silent failure only: never expose exception stacks, profile paths or keys.
process.on('uncaughtException',()=>process.exit(1));
process.on('unhandledRejection',()=>process.exit(1));
const self=fileURLToPath(import.meta.url);
const dir='/tmp/phase-ownedfixture', socketPath=dir+'/pid1.sock', profile=dir+'/profile';
const fail=()=>{throw new Error('PHASE_WORKER_UNVERIFIED');};
const bounded=(p,ms=10000)=>new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(new Error('PHASE_WORKER_UNVERIFIED')),ms);p.then(v=>{clearTimeout(t);resolve(v);},()=>{clearTimeout(t);reject(new Error('PHASE_WORKER_UNVERIFIED'));});});
function own(){if(process.getuid()!==10001||process.geteuid()!==10001||process.getgid()!==10001||process.getegid()!==10001)fail();}
async function raw(pid,strict=true){
 const base='/proc/'+pid, status=await fs.readFile(base+'/status','utf8');
 const uid=status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m);
 if(!uid||uid.slice(1).some(x=>x!=='10001'))fail();
 const s=await fs.readFile(base+'/stat','utf8'),f=s.slice(s.lastIndexOf(')')+2).trim().split(/\s+/);
 if(s.slice(0,s.indexOf(' '))!==String(pid)||f.length<22)fail();
 const ns={};for(const [k,n] of Object.entries({pid:'pid',cgroup:'cgroup',mount:'mnt',time:'time'}))ns[k]=await fs.readlink(base+'/ns/'+n);
 const fact={pid,startTicks:f[19],state:f[0],membership:(await fs.readFile(base+'/cgroup','utf8')).trim(),oomScoreAdj:Number((await fs.readFile(base+'/oom_score_adj','utf8')).trim()),namespaces:ns};
 if(strict)processFact(fact);
 return {fact,parent:Number(f[1]),exe:path.basename(await fs.readlink(base+'/exe')),args:(await fs.readFile(base+'/cmdline','utf8')).split('\0').filter(Boolean)};
}
async function selfFact(){const p=await raw(process.pid);const ns={};for(const [k,n] of Object.entries({pid:'pid',cgroup:'cgroup',mount:'mnt',time:'time'}))ns[k]=await fs.readlink('/proc/self/ns/'+n);sameNamespace(ns,p.fact.namespaces);return p.fact;}
function sameNamespace(a,b){for(const k of ['pid','cgroup','mount','time'])if(a[k]!==b[k])fail();}
async function ancestry(pid,ns){const seen=new Set();for(let p=pid;p>0&&!seen.has(p);){seen.add(p);const r=await raw(p,false);if(!['R','S','D','I'].includes(r.fact.state))fail();sameNamespace(r.fact.namespaces,ns);if(p===1)return true;p=r.parent;}fail();}
function chrome(p){return ['chrome','chromium','headless_shell'].includes(p.exe);}
async function browserProcesses(ns){
 const found=[];
 for(const name of await fs.readdir('/proc')){
 if(!/^[1-9][0-9]*$/.test(name))continue;
 let p;try{const stat=await fs.readFile('/proc/'+name+'/stat','utf8');const state=stat.slice(stat.lastIndexOf(')')+2).split(' ')[0];if(['Z','X','x'].includes(state))continue;p=await raw(Number(name),false);}catch(e){try{await fs.lstat('/proc/'+name);}catch(g){if(g.code==='ENOENT')continue;}throw e;}
 if(chrome(p)){await ancestry(p.fact.pid,ns);found.push(p);}
 }
 return found;
}
async function cgroupObservation(){
 const handle=await fs.open('/sys/fs/cgroup','r');
 try{
 const st=await handle.stat({bigint:true}),sf=await fs.statfs('/proc/self/fd/'+handle.fd,{bigint:true});if(sf.type!==0x63677270n)fail();
 const read=async n=>(await fs.readFile('/proc/self/fd/'+handle.fd+'/'+n,'utf8')).trim();
 const cpu=(await read('cpu.max')).split(' ');if(cpu.length!==2)fail();
 const bounds={memoryMax:await read('memory.max'),memorySwapMax:await read('memory.swap.max'),cpuQuota:cpu[0],cpuPeriod:cpu[1],cpuBurst:await read('cpu.max.burst'),pidsMax:await read('pids.max'),cgroupType:await read('cgroup.type')};
 const lines=(await fs.readFile('/proc/self/mountinfo','utf8')).trim().split('\n').map(l=>{const pair=l.split(' - ');if(pair.length!==2)fail();return {left:pair[0].split(' '),right:pair[1].split(' ')};});
 const cg=lines.filter(l=>l.left[4]==='/sys/fs/cgroup');if(cg.length!==1)fail();const m=cg[0];
 const unexpected=lines.some(l=>l.left[4].startsWith('/sys/fs/cgroup/'));
 const major=((st.dev>>8n)&0xfffn)|((st.dev>>32n)&0xfffff000n),minor=(st.dev&0xffn)|((st.dev>>12n)&0xffffff00n);
 if(m.left[2]!==major+':'+minor||m.left[3]!=='/'||m.right[0]!=='cgroup2'||!m.left[5].split(',').includes('ro')||unexpected)fail();
 return {cgroupRoot:{device:String(st.dev),inode:String(st.ino),fsType:'63677270'},containerMount:{root:m.left[3],mountPoint:m.left[4],mountDevice:m.left[2],filesystem:m.right[0],readOnly:true,unexpectedOvermounts:false},bounds};
 }finally{await handle.close();}
}
async function exchange(req){return bounded(new Promise((resolve,reject)=>{
 const socket=net.createConnection(socketPath);let data='';socket.setEncoding('utf8');socket.on('connect',()=>socket.write(JSON.stringify(req)+'\n'));socket.on('data',part=>{data+=part;if(data.length>65536)socket.destroy(new Error('PHASE_WORKER_UNVERIFIED'));});socket.on('error',reject);socket.on('end',()=>{try{if(!data.endsWith('\n')||data.indexOf('\n')!==data.length-1)fail();resolve(JSON.parse(data));}catch{reject(new Error('PHASE_WORKER_UNVERIFIED'));}});
 }),25000);}
async function client(args){
 const op=args[0]==='--challenge'?'challenge':args[0]==='--release'?'release':null;
 if(!op||args.length!==(op==='challenge'?3:2)||!NONCE.test(args[1])||process.pid===1)fail();
 const before=await selfFact(),req={version:1,op,nonce:args[1],...(op==='challenge'?{milestone:args[2]}:{}),pid:process.pid};request(req);
 const out=await exchange(req);
 if(op==='challenge'){witness(out);if(out.nonce!==req.nonce||out.milestone!==req.milestone||out.client.pid!==process.pid||out.client.startTicks!==before.startTicks)fail();sameNamespace(out.client.namespaces,before.namespaces);}
 else{if(!out||Object.keys(out).sort().join('|')!=='milestone|nonce|op|version'||out.version!==1||out.op!=='released'||out.nonce!==req.nonce||!['ready','result_ready'].includes(out.milestone))fail();}
 await new Promise((resolve,reject)=>process.stdout.write(JSON.stringify(out)+'\n',e=>e?reject(e):resolve()));
}
async function main(){
 own();process.umask(0o077);const args=process.argv.slice(2);
 if(args[0]==='--child'){
 if(args.length!==1||process.pid===1||typeof process.send!=='function')fail();
 process.on('SIGTERM',()=>{});process.on('message',m=>{if(m==='shutdown')process.send({closed:true},()=>process.exit(0));else process.exit(1);});process.on('disconnect',()=>process.exit(1));process.send({ready:true});setInterval(()=>{},1000);return;
 }
 if(args[0]?.startsWith('--')){await client(args);return;}
 if(args.length!==1||!['graceful','linger'].includes(args[0])||process.pid!==1)fail();
 const mode=args[0],init=await selfFact();
 const host={pid:process.env.HOST_PID_NAMESPACE,cgroup:process.env.HOST_CGROUP_NAMESPACE,mount:process.env.HOST_MOUNT_NAMESPACE,time:process.env.HOST_TIME_NAMESPACE};namespaces(host);
 for(const k of ['pid','cgroup','mount'])if(init.namespaces[k]===host[k])fail();if(init.namespaces.time!==host.time)fail();
 if(mode==='linger')process.on('SIGTERM',()=>{});
 if((await fs.statfs('/tmp',{bigint:true})).type!==0x1021994n)fail();
 await fs.mkdir(dir,{mode:0o700});const ds=await fs.lstat(dir);if(ds.uid!==10001||(ds.mode&0o777)!==0o700||!ds.isDirectory())fail();
 const child=fork(self,['--child'],{stdio:['ignore','ignore','ignore','ipc'],execArgv:[]});
 let acknowledged=false;child.on('message',m=>{if(m&&Object.keys(m).length===1&&m.closed===true)acknowledged=true;});
 const exited=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
 await bounded(new Promise((resolve,reject)=>{child.once('message',m=>m&&Object.keys(m).length===1&&m.ready===true?resolve():reject(new Error('PHASE_WORKER_UNVERIFIED')));child.once('error',reject);}),5000);
 const {chromium}=await import('/opt/fixture/node_modules/playwright/index.mjs');
 const context=await chromium.launchPersistentContext(profile,{headless:true,args:['--no-sandbox'],chromiumSandbox:false,handleSIGTERM:false,handleSIGINT:false,handleSIGHUP:false});
 const tab=context.pages()[0]||await context.newPage();await tab.goto('about:blank');await tab.setContent('<main id="fixture">synthetic fixture</main>');if(await tab.locator('#fixture').textContent()!=='synthetic fixture')fail();
 let nodeIdentity=null,browserIdentity=null;
 async function children(){
 const cp=await raw(child.pid);if(cp.exe!=='node'||cp.parent!==1||cp.args.length!==3||cp.args[1]!==self||cp.args[2]!=='--child')fail();await ancestry(child.pid,init.namespaces);
 const observed=(await browserProcesses(init.namespaces)).filter(p=>!p.args.some(a=>a.startsWith('--type=')));if(observed.length!==1)fail();const bp=[await raw(observed[0].fact.pid)];
 for(const [p,old] of [[cp,nodeIdentity],[bp[0],browserIdentity]])if(old&&(p.fact.pid!==old.pid||p.fact.startTicks!==old.startTicks))fail();
 nodeIdentity=cp.fact;browserIdentity=bp[0].fact;
 return [{...cp.fact,role:'node_child',executableClass:'node',ancestorToInit:true},{...bp[0].fact,role:'chromium_main',executableClass:'chromium_main',ancestorToInit:true}];
 }
 await children();await cgroupObservation();
 let state={mode,milestone:'ready',pending:null,used:[]},busy=false;
 async function verifyClient(req){
 const p=await raw(req.pid);if(p.exe!=='node')fail();sameNamespace(p.fact.namespaces,init.namespaces);
 const expected=[self,req.op==='challenge'?'--challenge':'--release',req.nonce,...(req.op==='challenge'?[req.milestone]:[])];
 if(!['node',process.execPath].includes(p.args[0])||p.args.length!==expected.length+1||p.args.slice(1).some((a,i)=>a!==expected[i]))fail();return p.fact;
 }
 // Trusted controlled fixture, NOT OS peer credential authentication.
 const server=net.createServer(sock=>{
 sock.setEncoding('utf8');sock.setTimeout(30000,()=>sock.destroy());let data='',handled=false;
 sock.on('error',()=>{});sock.on('data',part=>{
 data+=part;if(data.length>8192||handled){sock.destroy();return;}if(!data.includes('\n'))return;
 handled=true;(async()=>{
 if(busy||data.indexOf('\n')!==data.length-1)fail();busy=true;
 try{
 const req=request(JSON.parse(data)),next=transition(state,req),clientFact=await verifyClient(req);
 if(req.op==='challenge'){
 const initNow=await selfFact();if(initNow.startTicks!==init.startTicks)fail();sameNamespace(initNow.namespaces,init.namespaces);
 const kids=caseResult(mode,state.milestone).childrenAlive?await children():[];
 const out={version:1,nonce:req.nonce,milestone:state.milestone,init:initNow,client:clientFact,...await cgroupObservation(),children:kids,caseResult:caseResult(mode,state.milestone)};witness(out);state=next;sock.end(JSON.stringify(out)+'\n');
 }else{
 const prior=state.milestone;state=next;
 if(prior==='ready'&&mode==='graceful'){
 child.send('shutdown');const result=await bounded(exited,5000);if(!acknowledged||result.code!==0||result.signal!==null)fail();
 await bounded(context.close(),10000);if((await browserProcesses(init.namespaces)).length!==0)fail();
 await fs.rm(profile,{recursive:true});try{await fs.lstat(profile);fail();}catch(e){if(e.code!=='ENOENT')throw e;}
 }
 if(prior==='ready'&&mode==='linger')await children();
 await new Promise((resolve,reject)=>{sock.once('error',reject);sock.end(JSON.stringify({version:1,op:'released',nonce:req.nonce,milestone:prior})+'\n',resolve);});
 if(prior==='result_ready'){
 // Wait for the exec client to flush its stdout and exit before PID1 exits.
 await bounded((async()=>{for(;;){try{const stat=await fs.readFile('/proc/'+req.pid+'/stat','utf8');const f=stat.slice(stat.lastIndexOf(')')+2).trim().split(/\s+/);if(f[19]!==clientFact.startTicks||['Z','X','x'].includes(f[0]))break;}catch(e){try{await fs.lstat('/proc/'+req.pid);}catch(g){if(g.code==='ENOENT')break;}throw e;}await new Promise(r=>setTimeout(r,20));}})(),5000);
 server.close(()=>process.exit(0));
 }
 }
 }finally{busy=false;}
 })().catch(()=>{sock.destroy();process.exit(1);});
 });
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,resolve);});await fs.chmod(socketPath,0o600);server.on('error',()=>process.exit(1));
 // No autonomous completion or self-kill. Linger is stopped only by exact-ID Docker stop.
}
main().catch(()=>process.exit(1));
