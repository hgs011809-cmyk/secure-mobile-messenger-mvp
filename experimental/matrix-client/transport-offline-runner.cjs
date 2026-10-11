// Windows main-context loading only. POSIX transport unit fixtures do not execute there.
const fs=require('node:fs'),root=process.env.TRANSPORT_WORKSPACE;
const uri=s=>'data:text/javascript;base64,'+Buffer.from(s).toString('base64');
const cryptoUri=uri(fs.readFileSync(root+'/experimental/media-transfer-lab/attachment-stream.mjs','utf8'));
const receiverUri=uri(fs.readFileSync(root+'/experimental/media-transfer-lab/receiver.mjs','utf8'));
const pipeline=fs.readFileSync(root+'/experimental/matrix-client/transport-pipeline.mjs','utf8').replaceAll('../media-transfer-lab/attachment-stream.mjs',cryptoUri).replaceAll('../media-transfer-lab/receiver.mjs',receiverUri);
const pipelineUri=uri(pipeline);
const spec=fs.readFileSync(root+'/experimental/matrix-client/transport-pipeline.spec.mjs','utf8').replaceAll('./transport-pipeline.mjs',pipelineUri);
import(uri(spec)).catch(()=>{console.log('transport_unit_loading_failed=true; raw_diagnostics_suppressed=true');process.exitCode=1;});
