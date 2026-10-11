// Independent Linux cleanup. No child/container creation; do not touch other suites.
const f=require('node:fs'),p=require('node:path');
const root=process.env.PRIVATE_ATTACHMENT_ROOT,base=process.env.RUNNER_TEMP;
const fail=()=>{console.log('persisted_corruption_cleanup=failed; raw_diagnostics_suppressed=true');process.exitCode=1;};
const absent=q=>{try{f.lstatSync(q);return false;}catch(e){if(e.code==='ENOENT')return true;throw Error('absence');}};
const pause=ms=>new Promise(r=>setTimeout(r,ms));
function ownedProcesses(){
  const found=[];
  for(const name of f.readdirSync('/proc')){
    if(!/^\d+$/.test(name)||Number(name)===process.pid)continue;
    try{
      const q='/proc/'+name;
      if(f.statSync(q).uid!==process.getuid())continue;
      const argv=f.readFileSync(q+'/cmdline','utf8').split('\0');
      if(!argv.some(a=>p.basename(a)==='persisted-corruption.spec.mjs'))continue;
      if(!f.readFileSync(q+'/environ','utf8').split('\0').includes('PRIVATE_ATTACHMENT_ROOT='+root))continue;
      const stat=f.readFileSync(q+'/stat','utf8'),fields=stat.slice(stat.lastIndexOf(')')+2).split(' ');
      if(fields[0]!=='Z')found.push({pid:Number(name),start:fields[19]});
    }catch(e){if(!['ENOENT','ESRCH'].includes(e.code))throw e;}
  }
  return found;
}
function same(c){try{const t=f.readFileSync('/proc/'+c.pid+'/stat','utf8'),v=t.slice(t.lastIndexOf(')')+2).split(' ');return v[19]===c.start&&v[0]!=='Z';}catch(e){if(['ENOENT','ESRCH'].includes(e.code))return false;throw e;}}
(async()=>{
  try{
    if(process.platform!=='linux'||!root||!base||!p.isAbsolute(root)||!p.isAbsolute(base)||p.dirname(root)!==base||!/^synthetic-persisted-corruption\.[A-Za-z0-9]+$/.test(p.basename(root)))throw Error('namespace');
    if(!absent(root)){
      const s=f.lstatSync(root);
      if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&4095)!==448||s.uid!==process.getuid()||p.dirname(f.realpathSync(root))!==f.realpathSync(base))throw Error('unsafe');
    }
    const owned=ownedProcesses();
    if(process.argv.includes('--check-only')){
      if(owned.length!==0)throw Error('owned_process_alive');
      if(!absent(root)&&f.readdirSync(root).some(n=>n.startsWith('persisted-corruption-')))throw Error('fixture_retained');
      console.log('owned_children_created_by_suite=0; owned_test_processes_alive=0; containers_created=0; fixture_namespaces_absent=true');return;
    }
    // Match private env + exact suite argv + uid + process start before signalling.
    for(const c of owned)if(same(c))try{process.kill(c.pid,'SIGTERM');}catch(e){if(e.code!=='ESRCH')throw e;}
    for(let i=0;i<20&&owned.some(same);i++)await pause(50);
    for(const c of owned)if(same(c))try{process.kill(c.pid,'SIGKILL');}catch(e){if(e.code!=='ESRCH')throw e;}
    for(let i=0;i<40&&owned.some(same);i++)await pause(50);
    if(owned.some(same)||ownedProcesses().length!==0)throw Error('owned_process_not_exited');
    f.rmSync(root,{recursive:true,force:true});if(!absent(root))throw Error('namespace_retained');
    console.log('owned_children_created_by_suite=0; owned_test_processes_alive=0; owned_test_processes_stopped='+owned.length+'; containers_created=0; private_namespace_absent=true; unlink_not_physical_erasure=true');
  }catch{fail();}
})();
