import { chromium } from '@playwright/test';
import { fork } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const self = fileURLToPath(import.meta.url);
const dir = '/tmp/ownedfixture';
const delay = ms => new Promise(r => setTimeout(r, ms));
async function proc(pid) {
  const stat = await fs.readFile('/proc/' + pid + '/stat', 'utf8');
  const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  return { parent: Number(fields[1]), state: fields[0], exe: path.basename(await fs.readlink('/proc/' + pid + '/exe')), args: (await fs.readFile('/proc/' + pid + '/cmdline', 'utf8')).split('\0') };
}
async function ancestor(pid, workerPid) {
  const seen = new Set();
  for (let n = pid; n > 0 && !seen.has(n);) {
    seen.add(n);
    const p = await proc(n);
    if (p.state === 'Z') return false;
    if (n === workerPid) return true;
    n = p.parent;
  }
  return false;
}
async function observe(workerPid, childPid) {
  if (!(await ancestor(childPid, workerPid)) || (await proc(childPid)).exe !== 'node') throw Error('proof');
  let browser = false;
  for (const entry of await fs.readdir('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const p = await proc(Number(entry));
      if (['chrome', 'chromium', 'headless_shell'].includes(p.exe) && !p.args.some(a => a.startsWith('--type=')) && await ancestor(Number(entry), workerPid)) browser = true;
    } catch { /* vanishing entries never establish proof */ }
  }
  if (!browser) throw Error('proof');
}
function aggregate(mode, phase) {
  return { version: 1, mode, phase, namespacePrivate: true, childObserved: true, browserObserved: true, childrenAlive: phase === 'alive', childClosed: phase === 'complete', browserClosed: phase === 'complete', profileRemoved: phase === 'complete', childCount: 1 };
}
async function main() {
  const mode = process.argv[2];
  if (mode === '--child') {
    process.on('SIGTERM', () => {});
    process.on('message', m => { if (m === 'shutdown') process.exit(0); });
    process.on('disconnect', () => process.exit(0));
    process.send({ ready: true });
    setInterval(() => {}, 1000);
    return;
  }
  const ns = await fs.readlink('/proc/self/ns/pid');
  if (!/^pid:\[\d+\]$/.test(process.env.HOST_PID_NAMESPACE || '') || ns === process.env.HOST_PID_NAMESPACE) throw Error('namespace');
  if (mode === '--probe') {
    const saved = JSON.parse(await fs.readFile(dir + '/proof.json', 'utf8'));
    if (saved.mode !== 'linger' || !Number.isInteger(saved.worker) || !Number.isInteger(saved.child)) throw Error('proof');
    await observe(saved.worker, saved.child);
    console.log(JSON.stringify(aggregate('linger', 'alive')));
    return;
  }
  if (!['graceful', 'linger'].includes(mode) || process.pid !== 1) throw Error('mode');
  await fs.mkdir(dir, { mode: 0o700 });
  process.umask(0o077);
  if (mode === 'linger') process.on('SIGTERM', () => {});
  const child = fork(self, ['--child'], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  await Promise.race([new Promise((resolve, reject) => { child.once('message', m => m?.ready === true ? resolve() : reject(Error('child'))); child.once('error', reject); }), delay(5000).then(() => { throw Error('timeout'); })]);
  const context = await chromium.launchPersistentContext(dir + '/profile', { headless: true, args: ['--no-sandbox'], chromiumSandbox: false, handleSIGTERM: false, handleSIGINT: false, handleSIGHUP: false });
  const tab = context.pages()[0] || await context.newPage();
  await tab.goto('about:blank');
  await tab.setContent('<main id="fixture">synthetic fixture</main>');
  if (await tab.locator('#fixture').textContent() !== 'synthetic fixture') throw Error('fixture');
  await observe(process.pid, child.pid);
  if (mode === 'linger') {
    await fs.writeFile(dir + '/proof.json', JSON.stringify({ mode, worker: process.pid, child: child.pid }), { flag: 'wx', mode: 0o600 });
    console.log(JSON.stringify(aggregate(mode, 'alive')));
    setInterval(() => {}, 1000);
    return;
  }
  child.send('shutdown');
  const result = await Promise.race([exited, delay(5000).then(() => { throw Error('timeout'); })]);
  if (result.code !== 0 || result.signal !== null) throw Error('child');
  await Promise.race([context.close(), delay(10000).then(() => { throw Error('timeout'); })]);
  for (const entry of await fs.readdir('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    let live = false;
    try { const p = await proc(Number(entry)); live = ['chrome', 'chromium', 'headless_shell'].includes(p.exe) && await ancestor(Number(entry), process.pid); } catch {}
    if (live) throw Error('browser');
  }
  await fs.rm(dir, { recursive: true });
  try { await fs.lstat(dir); throw Error('profile'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  console.log(JSON.stringify(aggregate(mode, 'complete')));
}
main().catch(() => process.exit(1));
