// NEW loopback CI build; existing harness sources remain untouched.
import './transport-build.mjs';
import fs from 'node:fs/promises';
const root=new URL('./',import.meta.url);
function replaceOnce(source,anchor,replacement){if(source.split(anchor).length!==2)throw Error('LIVE_BUILD_ANCHOR_DENIED');return source.replace(anchor,replacement);}
let html=await fs.readFile(new URL('./transport-browser.html',root),'utf8');
const hooks=await fs.readFile(new URL('./sdk-process-authority-hooks.inc.mjs',root),'utf8');
html=replaceOnce(html,'const api = {',hooks+'\nconst api = {\n  sdkProcessAuthorityCrossBinding,');
html=replaceOnce(html,'<title>Synthetic Matrix loopback harness</title>','<title>Synthetic SDK process loopback candidate</title>');
await fs.writeFile(new URL('./dist/sdk-process-live.html',root),html,{mode:0o600});
console.log('sdk_process_live_browser_candidate_built=true');
