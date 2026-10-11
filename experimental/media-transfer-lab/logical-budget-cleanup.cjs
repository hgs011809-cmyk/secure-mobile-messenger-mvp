// Independent Linux cleanup. Read-only process inspection; NEVER signal processes.
// CI timeout supervisor owns test-runner termination. Retain root if live tests exist.
const f=require('node:fs'),p=require('node:path');
const root=process.env.PRIVATE_ATTACHMENT_ROOT,base=process.env.RUNNER_TEMP;
const fail=()=>{console.log('logical_budget_cleanup=failed; raw_diagnostics_suppressed=true');process.exitCode=1;};
const absent=q=>{try{f.lstatSync(q);return false;}catch(e){if(e.code==='ENOENT')return true;throw Error('absence');}};
function ownedProcesses(){
  const found=[];
  for(const name of f.readdirSync('/proc')){
    if(!/^\d+$/.test(name)||Number(name)===process.pid)continue;
    try{
      const q='/proc/'+name;
      if(f.statSync(q).uid!==process.getuid())continue;
      const argv=f.readFileSync(q+'/cmdline','utf8').split('\0');
      if(!argv.some(a=>p.basename(a)==='logical-budget.spec.mjs'))continue;
      if(!f.readFileSync(q+'/environ','utf8').split('\0').includes('PRIVATE_ATTACHMENT_ROOT='+root))continue;
      const stat=f.readFileSync(q+'/stat','utf8'),fields=stat.slice(stat.lastIndexOf(')')+2).split(' ');
      if(fields[0]!=='Z')found.push(Number(name));
    }catch(e){if(!['ENOENT','ESRCH'].includes(e.code))throw e;}
  }
  return found;
}
(async()=>{
  try{
    if(process.platform!=='linux'||!root||!base||!p.isAbsolute(root)||!p.isAbsolute(base)||p.dirname(root)!==base||!/^synthetic-logical-budget\.[A-Za-z0-9]+$/.test(p.basename(root)))throw Error('namespace');
    if(!absent(root)){
      const s=f.lstatSync(root);
      if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&4095)!==448||s.uid!==process.getuid()||p.dirname(f.realpathSync(root))!==f.realpathSync(base))throw Error('unsafe');
    }
    const owned=ownedProcesses();
    if(process.argv.includes('--check-only')){
      if(owned.length!==0)throw Error('owned_process_alive');
      if(!absent(root)&&f.readdirSync(root).some(n=>n.startsWith('logical-budget-')))throw Error('fixture_retained');
      console.log('owned_children_created_by_suite=0; owned_test_processes_alive=0; containers_created=0; fixture_namespaces_absent=true');return;
    }
    // Any matching live process or inspection failure blocks deletion; no posthoc kill authority.
    if(owned.length!==0||ownedProcesses().length!==0)throw Error('owned_process_alive_root_retained');
    f.rmSync(root,{recursive:true,force:true});if(!absent(root))throw Error('namespace_retained');
    console.log('owned_children_created_by_suite=0; owned_test_processes_alive=0; owned_test_processes_stopped=0; read_only_process_inspection=true; containers_created=0; private_namespace_absent=true; unlink_not_physical_erasure=true');
  }catch{fail();}
})();
