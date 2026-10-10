import http from 'node:http';import fs from 'node:fs/promises';import path from 'node:path';import {fileURLToPath} from 'node:url';
const root=path.join(path.dirname(fileURLToPath(import.meta.url)),'dist');
const mime={'.mjs':'text/javascript','.html':'text/html','.wasm':'application/wasm'};
const server=http.createServer(async(req,res)=>{try{const relative=decodeURIComponent(new URL(req.url,'http://127.0.0.1').pathname);const file=path.resolve(root,'.'+(relative==='/'?'/index.html':relative));if(!file.startsWith(root+path.sep)){res.writeHead(403).end();return;}const data=await fs.readFile(file);res.writeHead(200,{'content-type':mime[path.extname(file)]||'application/octet-stream','cache-control':'no-store'}).end(data);}catch{res.writeHead(404).end();}});
server.listen(19461,'127.0.0.1',()=>console.log('Loopback development harness ready on http://127.0.0.1:19461'));
process.on('SIGTERM',()=>server.close());
