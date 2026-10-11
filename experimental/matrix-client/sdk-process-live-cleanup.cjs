// NEW fail-closed read-only inspection helper. Never signal a process.
const f=require('node:fs'),p=require('node:path');
const known=new Set(['INVALID_NAMESPACE','UNSAFE_NAMESPACE','OWNED_PROCESS_PRESENT','UNEXPECTED_CONTENT','NAMESPACE_REMAINS']);
function deny(c){throw Error(c);}
function identity(pid){try{if(f.statSync('/proc/'+pid).uid!==process.getuid())return null;const t=f.readFileSync('/proc/'+pid+'/stat','utf8');return {pid,start:t.slice(t.lastIndexOf(')')+2).split(' ')[19],exe:f.realpathSync('/proc/'+pid+'/exe'),argv:f.readFileSync('/proc/'+pid+'/cmdline','utf8').split('\0').filter(Boolean)};}catch(e){if(['ENOENT','ESRCH'].includes(e.code))return null;throw e;}}
try{
 if(process.platform!=='linux')deny('INVALID_NAMESPACE');
 const runner=p.resolve(process.env.RUNNER_TEMP||''),id=process.env.GITHUB_RUN_ID,attempt=process.env.GITHUB_RUN_ATTEMPT;
 if(!/^\d+$/.test(id||'')||!/^\d+$/.test(attempt||''))deny('INVALID_NAMESPACE');
 const root=process.env.PRIVATE_ATTACHMENT_ROOT,expected=p.join(runner,'sdk-process-live-'+id+'-'+attempt);
 if(root!==expected||!p.isAbsolute(root)||f.realpathSync(runner)!==runner)deny('INVALID_NAMESPACE');
 const worker=f.realpathSync(p.join(__dirname,'sdk-process-worker.mjs')),node=f.realpathSync(process.execPath);let workers=0,profiles=0;
 for(const n of f.readdirSync('/proc')){if(!/^\d+$/.test(n)||Number(n)===process.pid)continue;const x=identity(Number(n));if(!x)continue;
 // Detection only. Full identity observation is NOT birth ownership or kill authority.
 if(x.exe===node&&x.argv.length===3&&x.argv[1]===worker&&x.argv[2].startsWith('--sdk-process-root='+root+p.sep))workers++;
 if(x.argv.some(a=>a.startsWith('--user-data-dir='+root+p.sep)))profiles++;
 }
 if(workers||profiles)deny('OWNED_PROCESS_PRESENT');
 if(f.existsSync(root)){const s=f.lstatSync(root);if(s.isSymbolicLink()||s.uid!==process.getuid()||!s.isDirectory()||(s.mode&4095)!==448)deny('UNSAFE_NAMESPACE');if(f.readdirSync(root).length!==0)deny('UNEXPECTED_CONTENT');f.rmdirSync(root);}
 if(f.existsSync(root))deny('NAMESPACE_REMAINS');
 console.log(JSON.stringify({independentNamespaceInspection:true,ownedChildExit:'no_child_started',ownedWorkersAbsent:true,ownedProfilesAbsent:true,containersCreated:0,containerInspection:'separate_workflow_step_required',privateNamespaceAbsent:true,forcedProcessCleanup:0,runtimeTests:0,physicalErasure:false}));
}catch(e){console.log(JSON.stringify({independentNamespaceInspection:false,code:known.has(e.message)?e.message:'CLEANUP_FAILED',rawDiagnosticsSuppressed:true,signalsSent:0}));process.exitCode=1;}
