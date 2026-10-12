'use strict';
const fs=require('node:fs');
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
function bad(){const e=new Error('RUNTIME_PROFILE_UNVERIFIED');e.code=e.message;throw e;}
function obj(x){if(!x||typeof x!=='object'||Array.isArray(x))bad();return x;}
function field(o,k){obj(o);if(!own(o,k)||typeof o[k]!=='string')bad();return o[k];}
function semver(x){if(typeof x!=='string'||!/^v?(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$/.test(x))bad();return x;}
function git(x){if(typeof x!=='string'||!(/^[a-f0-9]{7,64}$/.test(x)||/^v?(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)-[0-9]{1,6}-g[a-f0-9]{7,64}$/.test(x)))bad();return x;}
function project(i,s){
 obj(i);obj(s);if(field(i,'ServerVersion')!==field(s,'Version')||semver(s.Version)!=='28.0.4'||field(s,'Os')!=='linux'||field(s,'Arch')!=='amd64')bad();
 const g=field(s,'GitCommit');if(!/^[a-f0-9]{7,40}$/.test(g))bad();const api=field(s,'ApiVersion');if(!/^[1-9][0-9]?\.(0|[1-9][0-9]?)$/.test(api))bad();
 if(field(i,'CgroupVersion')!=='2'||field(i,'CgroupDriver')!=='systemd'||field(i,'DefaultRuntime')!=='runc'||!own(i,'OomKillDisable')||i.OomKillDisable!==false)bad();
 if(!Array.isArray(s.Components)||s.Components.length<3||s.Components.length>32)bad();
 const c={};for(const a of s.Components){obj(a);const n=field(a,'Name');if(['Engine','runc','containerd'].includes(n)){if(own(c,n))bad();c[n]=a;}}
 if(!own(c,'Engine')||!own(c,'runc')||!own(c,'containerd')||field(c.Engine,'Version')!==s.Version||field(obj(c.Engine.Details),'GitCommit')!==g)bad();
 return {exactServerVersion:s.Version,exactServerGitCommit:g,apiVersion:api,cgroupVersion:'2',cgroupDriver:'systemd',defaultRuntime:'runc',runcVersion:semver(field(c.runc,'Version')),runcGitCommit:git(field(obj(c.runc.Details),'GitCommit')),containerdVersion:semver(field(c.containerd,'Version')),containerdGitCommit:git(field(obj(c.containerd.Details),'GitCommit')),oomDisableCapability:false};
}
function read(n){let fd;try{fd=fs.openSync(n,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const s=fs.fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o7777)!==0o600||s.size>4194304)bad();const b=Buffer.alloc(4194305);let used=0;while(used<b.length){const got=fs.readSync(fd,b,used,b.length-used,null);if(got===0)break;used+=got;}if(used>4194304)bad();const end=fs.fstatSync(fd);if(end.dev!==s.dev||end.ino!==s.ino||end.nlink!==1||end.size!==used||end.size>4194304||end.uid!==s.uid||(end.mode&0o7777)!==0o600)bad();return JSON.parse(b.toString('utf8',0,used));}finally{if(fd!==undefined)fs.closeSync(fd);}}
if(require.main===module){try{if(process.platform!=='linux'||process.env.CI!=='true'||process.env.GITHUB_ACTIONS!=='true'||process.env.GITHUB_REF!=='refs/heads/lab-matrix-cleanup-followup'||process.argv.length!==4)bad();console.log(JSON.stringify({readOnlyRuntimeMetadata:true,observed:project(read(process.argv[2]),read(process.argv[3])),workloadContainersCreated:0,workloadContainersStarted:0,nativeHelperExecuted:false,kernelOwnershipProven:false,kernelLimitsProven:false,actualSDKIntegration:false,rawDiagnosticsSuppressed:true}));}catch{console.log('runtime_profile_preflight=failed; fixed_schema_only=true; raw_diagnostics_suppressed=true');process.exitCode=1;}}
module.exports={project};
