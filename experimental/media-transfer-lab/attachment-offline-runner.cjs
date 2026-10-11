// Authored built-in-only main-context loader. Do not use unsupported vm import context.
'use strict';
const fsA=require('node:fs'), pathA=require('node:path'), cryptoA=require('node:crypto');
const rootA=process.env.ATTACHMENT_LAB_ROOT, tempA=process.env.ATTACHMENT_LAB_TMP;
if(!rootA||!tempA)throw new Error('explicit_roots_required');
const uriA=text=>'data:text/javascript;base64,'+Buffer.from(text).toString('base64');
const filesA=['attachment-stream.mjs','attachment-stream.spec.mjs','attachment-interop.spec.mjs'];
const textsA=Object.fromEntries(filesA.map(n=>[n,fsA.readFileSync(pathA.join(rootA,n),'utf8')]));
const referenceA=fsA.readFileSync(pathA.join(rootA,'reference/matrix-encrypt-attachment-1.0.3/nodejs.js'),'utf8');
const hashA=s=>cryptoA.createHash('sha256').update(s).digest('hex');
const expectedReferenceA='bf1862f6cf249a1ac8d9c4871963be97db650a5213114b09d6a47a2269dff89e';
if(!expectedReferenceA||hashA(referenceA)!==expectedReferenceA)throw new Error('reference_source_hash_failed');
const namespaceA=fsA.mkdtempSync(pathA.join(tempA,'attachment-private-'));
if(process.platform!=='win32')fsA.chmodSync(namespaceA,0o700);
process.env.TMPDIR=namespaceA;process.env.TMP=namespaceA;process.env.TEMP=namespaceA;
const statusFileA=pathA.join(rootA,'last-attachment-local.json');
const recordA={phase:'prepared',node:process.version,platform:process.platform,referenceSourceHashMatch:true,sourceHashes:Object.fromEntries(filesA.map(n=>[n,hashA(textsA[n])])),temporaryNamespaceRemoved:false};
fsA.writeFileSync(statusFileA,JSON.stringify(recordA,null,2));
process.on('exit',code=>{let removed=false;try{fsA.rmSync(namespaceA,{recursive:true,force:true});removed=!fsA.existsSync(namespaceA);}catch{}recordA.phase=code===0&&removed?'exited_zero':'failed';recordA.exitCode=code;recordA.temporaryNamespaceRemoved=removed;fsA.writeFileSync(statusFileA,JSON.stringify(recordA,null,2));if(!removed)process.exitCode=1;console.log('attachment_namespace_removed='+removed);});
const coreURI_A=uriA(textsA['attachment-stream.mjs']);
// Source bytes remain unmodified inside a CJS-compatible wrapper. Only built-in crypto required.
const refURI_A=uriA('import crypto from "node:crypto";const referenceExports={};(function(exports,require){\n'+referenceA+'\n})(referenceExports,name=>{if(name!=="crypto")throw new Error("reference_dependency_rejected");return crypto;});export default referenceExports;');
Promise.all(filesA.filter(n=>n.endsWith('.spec.mjs')).map(n=>import(uriA(textsA[n].replaceAll('./attachment-stream.mjs',coreURI_A).replaceAll('./reference/matrix-encrypt-attachment-1.0.3/nodejs.js',refURI_A))))).catch(()=>{recordA.importFailed=true;process.exitCode=1;console.log('attachment_import_failed=true; raw_error_suppressed=true');});
