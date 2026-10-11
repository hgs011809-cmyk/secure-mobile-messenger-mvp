// Direct built-in/data-URL loader. No nested processes, dependency installs or network fetches.
// Windows: evaluate only this authored, authorized file's contents in node -e main context when pathname resolution is blocked.
// vm.runInThisContext without a dynamic-import callback is NOT supported.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=process.env.MEDIA_LAB_ROOT,base=process.env.MEDIA_LAB_TMP_ROOT;
if(!root||!base||!path.isAbsolute(root)||!path.isAbsolute(base))throw new Error('explicit_lab_and_temporary_roots_required');
const names=['receiver.spec.mjs','voice-policy.spec.mjs','ingress-regression.spec.mjs','network.spec.mjs'];
for(const name of names)if(!fs.existsSync(path.join(root,name)))throw new Error('test_source_missing');
const sourcePaths=[...names,'receiver.mjs','voice-policy.mjs','../auth-bridge/sdk-policy.mjs'];
const hashes=Object.fromEntries(sourcePaths.map(name=>[name,crypto.createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex')]));
const privateRoot=fs.mkdtempSync(path.join(base,'synthetic-offline-run-'));fs.chmodSync(privateRoot,0o700);
process.env.TEMP=privateRoot;process.env.TMP=privateRoot;process.env.TMPDIR=privateRoot;
const record={version:1,node:process.version,platform:process.platform,observationTime:new Date().toISOString(),status:'started',sourceSha256:hashes,loader:'direct_builtin_data_url',matrixMediaIntegration:false,actualVoiceCall:false};
const checkpoint=path.join(root,'last-direct-offline-run.json');fs.writeFileSync(checkpoint,JSON.stringify(record,null,2)+'\n');
process.on('exit',code=>{let removed=false;try{fs.rmSync(privateRoot,{recursive:true,force:true});removed=!fs.existsSync(privateRoot);}catch{}record.status=code===0?'exited_zero':'failed_or_interrupted';record.exitCode=code;record.temporaryNamespaceRemoved=removed;fs.writeFileSync(checkpoint,JSON.stringify(record,null,2)+'\n');if(!removed)process.exitCode=1;});
const data=s=>'data:text/javascript;base64,'+Buffer.from(s).toString('base64');
const mods=[['./receiver.mjs','receiver.mjs'],['./voice-policy.mjs','voice-policy.mjs'],['../auth-bridge/sdk-policy.mjs','../auth-bridge/sdk-policy.mjs']].map(([ref,name])=>[ref,data(fs.readFileSync(path.join(root,name),'utf8'))]);
console.log('offline_namespace=prepared; loader=direct; source_checkpoint=saved');
Promise.all(names.map(name=>{let source=fs.readFileSync(path.join(root,name),'utf8');for(const [ref,url]of mods)source=source.replace(ref,url);return import(data(source));})).catch(()=>{console.error('test_loader_failed; diagnostics_suppressed=true');process.exitCode=1;});
