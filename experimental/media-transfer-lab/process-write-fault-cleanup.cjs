// Linux-only disposable namespace cleanup. No credential/path/raw error output.
const f=require('node:fs'),p=require('node:path');
const root=process.env.PRIVATE_ATTACHMENT_ROOT,runner=process.env.RUNNER_TEMP;
// Only the exact dedicated worker and Node executable are eligible, never suffix/prefix identity.
const worker=f.realpathSync(p.join(__dirname,'process-write-fault-worker.mjs'));
const executable=f.realpathSync(process.execPath);
function fixtureRoot(q){return typeof q==='string'&&p.isAbsolute(q)&&p.dirname(q)===root&&/^process-write-fault-[A-Za-z0-9]+$/.test(p.basename(q));}
function exactWorker(x,q){return fixtureRoot(q)&&x.exe===executable&&x.args.length===3&&x.args[0]===process.execPath&&x.args[1]===worker&&x.args[2]==='--lab-process-root='+q;}
const fail=c=>{throw Error(c);};
function privateStat(q,dir){const s=f.lstatSync(q);if(s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&4095)!==(dir?448:384)||!(dir?s.isDirectory():s.isFile()))fail('unsafe_namespace');}
function identity(pid){try{const s=f.statSync('/proc/'+pid);if(s.uid!==process.getuid())fail('foreign_owner');const t=f.readFileSync('/proc/'+pid+'/stat','utf8'),args=f.readFileSync('/proc/'+pid+'/cmdline','utf8').split('\0');if(args.at(-1)==='')args.pop();return {start:t.slice(t.lastIndexOf(')')+2).split(' ')[19],args,exe:f.realpathSync('/proc/'+pid+'/exe')};}catch(e){if(['ENOENT','ESRCH'].includes(e.code))return null;throw e;}}
// Scan is detection ONLY. It never provides authority to kill.
function scan(){const found=[];for(const n of f.readdirSync('/proc')){if(!/^\d+$/.test(n))continue;let x;try{x=identity(Number(n));}catch(e){if(e.code==='EACCES'||e.message==='foreign_owner')continue;throw e;}if(x){const arg=x.args[2],q=typeof arg==='string'&&arg.startsWith('--lab-process-root=')?arg.slice('--lab-process-root='.length):null;if(exactWorker(x,q))found.push(Number(n));}}return found;}
function markers(q,out=[]){privateStat(q,true);for(const n of f.readdirSync(q)){const a=p.join(q,n),s=f.lstatSync(a);if(s.isSymbolicLink())fail('unsafe_namespace');if(s.isDirectory())markers(a,out);else{privateStat(a,false);if(/^owned-child-\d+\.json$/.test(n)){if(s.size>2048)fail('invalid_marker');const m=JSON.parse(f.readFileSync(a,'utf8'));if(Object.keys(m).sort().join(',')!=='pid,root,start'||!Number.isSafeInteger(m.pid)||m.pid<=0||m.root!==q||!fixtureRoot(m.root)||n!=='owned-child-'+m.pid+'.json'||typeof m.start!=='string'||!/^\d+$/.test(m.start))fail('invalid_marker');const x=identity(m.pid);if(x&&x.start===m.start){if(!exactWorker(x,m.root))fail('marker_identity_mismatch');out.push(Object.freeze({pid:m.pid,start:m.start,root:m.root}));}}}}return out;}
(async()=>{
 if(process.platform!=='linux'||typeof root!=='string'||typeof runner!=='string'||!p.isAbsolute(root)||p.dirname(root)!==p.resolve(runner)||!/^synthetic-write-fault\.[A-Za-z0-9]+$/.test(p.basename(root)))fail('invalid_namespace');
 if(!f.existsSync(root)){if(scan().length)fail('workers_remain');console.log('independent_cleanup=verified; owned_workers_absent=true; private_fixture_namespace_absent=true');return;}
 privateStat(root,true);const tracked=markers(root),live=scan();
 if(process.argv.includes('--check-only')){if(tracked.length||live.length)fail('workers_remain');console.log('owned_fixture_workers_absent=true');return;}
 let forced=0;
 const untracked=live.some(pid=>!tracked.some(m=>m.pid===pid));
 for(const m of tracked){
  privateStat(m.root,true);
  // Revalidate preserved PID/start, executable and the entire argv immediately before signaling.
  const x=identity(m.pid);
  if(!x||x.start!==m.start)continue; // Gone or PID reused: never signal replacement.
  if(!exactWorker(x,m.root))fail('marker_identity_mismatch');
  try{process.kill(m.pid,'SIGKILL');forced++;}catch(e){if(e.code!=='ESRCH')throw e;}
 }
 const until=Date.now()+5000;while(scan().length&&Date.now()<until)await new Promise(r=>setTimeout(r,50));
 if(untracked)fail('untracked_worker');
 if(scan().length)fail('workers_remain');
 f.rmSync(root,{recursive:true,force:true});if(f.existsSync(root))fail('namespace_remains');
 console.log('independent_cleanup=verified; owned_workers_absent=true; private_fixture_namespace_absent=true; forced_worker_cleanup_count='+forced+'; physical_erasure=false; hard_runner_loss_cleanup=unverified');
})().catch(e=>{const codes=new Set(['invalid_namespace','unsafe_namespace','invalid_marker','foreign_owner','marker_identity_mismatch','untracked_worker','workers_remain','namespace_remains']);console.log('independent_cleanup=failed; code='+(codes.has(e.message)?e.message:'CLEANUP_FAILED')+'; raw_diagnostics_suppressed=true');process.exitCode=1;});
