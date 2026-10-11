// Main-context loader for restricted Windows pathname resolution; no SDK mock runtime proof.
const fs=require('node:fs');
const root=process.env.DESCRIPTOR_LAB_ROOT;
const uri=s=>'data:text/javascript;base64,'+Buffer.from(s).toString('base64');
const moduleUri=uri(fs.readFileSync(root+'/descriptor-receipt.mjs','utf8'));
const spec=fs.readFileSync(root+'/descriptor-receipt.spec.mjs','utf8').replaceAll('./descriptor-receipt.mjs',moduleUri);
import(uri(spec)).catch(()=>{console.log('descriptor_unit_load_failed=true; raw_diagnostics_suppressed=true');process.exitCode=1;});
