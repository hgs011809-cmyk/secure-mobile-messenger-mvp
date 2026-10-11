// Separate CI composition only; original descriptor build and policies unchanged.
import './descriptor-build.mjs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
await fs.copyFile(path.join(root,'transport-browser.html'),path.join(root,'dist/transport.html'));
