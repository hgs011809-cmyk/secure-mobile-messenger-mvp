// CI-only variant. Original build, renderer and deployed application unchanged.
import './build.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
for(const [source,target] of [['descriptor-browser.html','descriptor.html'],['descriptor-receipt.mjs','descriptor-receipt.mjs']])await fs.copyFile(path.join(root,source),path.join(root,'dist',target));
