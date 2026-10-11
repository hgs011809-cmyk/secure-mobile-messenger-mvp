// Independent CI-only owned-worker absence/removal. No descriptors, IDs or paths printed.
const f=require('node:fs'),p=require('node:path');
const root=process.env.PRIVATE_ATTACHMENT_ROOT,runner=process.env.RUNNER_TEMP;
const valid=typeof root==='string'&&typeof runner==='string'&&p.dirname(root)===runner&&p.basename(root).startsWith('synthetic-restart.');
const scan=()=>{
 const found=[];
 for(const name of f.readdirSync('/proc')){
  if(!/^\d+$/.test(name))continue;
  try{const args=f.readFileSync('/proc/'+name+'/cmdline','utf8').split('\0');
   if(args.some(a=>a.startsWith('--lab-process-root='+root+'/'))){if(f.statSync('/proc/'+name).uid!==process.getuid())throw Error('foreign_owner');found.push(Number(name));}
  }catch(e){if(!['ENOENT','ESRCH','EACCES'].includes(e.code))throw e;}
 }
 return found;
};
(async()=>{
 if(!valid)throw Error('invalid_namespace');
 if(process.argv.includes('--check-only')){if(scan().length)throw Error('workers_remain');console.log('owned_fixture_workers_absent=true');return;}
 const before=scan();for(const pid of before)try{process.kill(pid,'SIGKILL');}catch(e){if(e.code!=='ESRCH')throw e;}
 const until=Date.now()+5000;while(scan().length&&Date.now()<until)await new Promise(r=>setTimeout(r,50));
 if(scan().length)throw Error('workers_remain');
 f.rmSync(root,{recursive:true,force:true});if(f.existsSync(root))throw Error('namespace_remains');
 console.log('independent_cleanup=verified; owned_workers_absent=true; private_fixture_namespace_absent=true; forced_worker_cleanup_count='+before.length+'; physical_erasure=false; hard_runner_loss_cleanup=unverified');
})().catch(()=>{console.log('independent_cleanup=failed; raw_diagnostics_suppressed=true');process.exitCode=1;});
