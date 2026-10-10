import { fork, execFileSync } from 'node:child_process';
import { randomBytes, createHmac } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const base = 'http://127.0.0.1:18008';
const ci = fileURLToPath(new URL('.', import.meta.url));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const assert = value => { if (!value) throw new Error('gate failed'); };
const children = [];
let stage = 'server readiness';
const gates = [];
async function api(path, method = 'GET', body, token) {
    const response = await fetch(base + path, { method, signal: AbortSignal.timeout(15000),
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}) });
    if (!response.ok) throw new Error('HTTP gate failed');
    return response.json();
}
async function provision(username) {
    const secret = (await readFile(new URL('runtime/registration.secret', import.meta.url), 'utf8')).trim();
    const { nonce } = await api('/_synapse/admin/v1/register');
    const password = randomBytes(32).toString('hex');
    const mac = createHmac('sha1', secret).update([nonce, username, password, 'notadmin'].join('\0')).digest('hex');
    await api('/_synapse/admin/v1/register', 'POST', { nonce, username, password, admin: false, inhibit_login: true, mac });
    return api('/_matrix/client/v3/login', 'POST', { type: 'm.login.password',
        identifier: { type: 'm.id.user', user: username }, password, device_id: 'CI_' + username.toUpperCase() });
}
function worker() {
    const child = fork(fileURLToPath(new URL('client-worker.mjs', import.meta.url)), [], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    children.push(child);
    let sequence = 0;
    const pending = new Map();
    child.on('message', message => {
        const entry = pending.get(message.id);
        if (!entry) return;
        clearTimeout(entry.timer); pending.delete(message.id);
        if (message.ok) entry.resolve(message.value); else entry.reject(new Error('worker gate failed'));
    });
    child.on('exit', () => { for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('worker exited')); } pending.clear(); });
    return { child, call(op, args = {}) {
        return new Promise((resolve, reject) => {
            const id = ++sequence;
            const timer = setTimeout(() => { pending.delete(id); reject(new Error('worker timeout')); }, 100000);
            pending.set(id, { resolve, reject, timer });
            child.send({ id, op, args });
        });
    } };
}
async function suspend(w) {
    assert(w.child.kill('SIGSTOP'));
    // Linux /proc verifies the process is truly stopped, not just network delayed.
    for (let i = 0; i < 50; i++) {
        if (/^State:\s+T/m.test(await readFile(`/proc/${w.child.pid}/status`, 'utf8'))) return;
        await sleep(20);
    }
    throw new Error('process not stopped');
}
function resume(w) { assert(w.child.kill('SIGCONT')); }
function dbStatus(eventId) {
    return execFileSync('docker', ['compose', '-f', ci + 'compose.yaml', 'exec', '-T', 'synapse', 'python', '/ci/check_scrub.py'],
        { input: JSON.stringify({ event_id: eventId }), encoding: 'utf8', timeout: 10000, stdio: ['pipe', 'pipe', 'ignore'] }).trim();
}
const deadline = setTimeout(() => { for (const c of children) { c.kill('SIGCONT'); c.kill('SIGKILL'); } process.exit(1); }, 650000);
try {
    let ready = false;
    for (let i = 0; i < 90; i++) {
        try { await api('/_matrix/client/versions'); ready = true; break; } catch { await sleep(1000); }
    }
    assert(ready); gates.push('server-ready');
    stage = 'ordinary synthetic accounts';
    const aLogin = await provision('ci_alice');
    const bLogin = await provision('ci_bob');
    for (const login of [aLogin, bLogin]) {
        const who = await api('/_matrix/client/v3/account/whoami', 'GET', undefined, login.access_token);
        assert(who.user_id === login.user_id);
        const check = execFileSync('docker', ['compose', '-f', ci + 'compose.yaml', 'exec', '-T', 'synapse', 'python', '-c',
            'import sqlite3,sys; d=sqlite3.connect("file:/data/homeserver.db?mode=ro",uri=True); print(int(d.execute("SELECT admin FROM users WHERE name=?",(sys.stdin.read(),)).fetchone()[0]))'],
            { input: login.user_id, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
        assert(check === '0');
    }
    gates.push('ordinary-users');
    const alice = worker(), bob = worker();
    stage = 'SDK crypto and exact out-of-band device verification';
    const aDevice = await alice.call('start', aLogin);
    const bDevice = await bob.call('start', bLogin);
    const roomId = await alice.call('create', { otherUser: bLogin.user_id });
    await bob.call('join', { roomId });
    await Promise.all([alice.call('ready', { roomId }), bob.call('ready', { roomId })]);
    // Expected keys originate directly in isolated worker memory, NOT from /keys/query.
    await alice.call('verify', bDevice); await bob.call('verify', aDevice);
    gates.push('exact-synthetic-device-verification');
    const state = await api(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state`, 'GET', undefined, aLogin.access_token);
    const content = type => state.find(e => e.type === type && e.state_key === '')?.content;
    assert(content('m.room.create')['m.federate'] === false);
    assert(content('m.room.join_rules').join_rule === 'invite');
    assert(content('m.room.history_visibility').history_visibility === 'joined');
    assert(content('m.room.encryption').algorithm === 'm.megolm.v1.aes-sha2');
    assert(content('m.room.power_levels').redact === 0);
    assert((await api(`/_matrix/client/v3/devices`, 'GET', undefined, aLogin.access_token)).devices.length === 1);
    assert((await api(`/_matrix/client/v3/devices`, 'GET', undefined, bLogin.access_token)).devices.length === 1);
    gates.push('private-unfederated-encrypted-two-device-room');
    stage = 'stopped recipient delivery and decryption';
    await suspend(bob);
    const body = 'synthetic-' + randomBytes(16).toString('hex');
    const eventId = await alice.call('send', { roomId, body });
    const eventPath = `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/event/${encodeURIComponent(eventId)}`;
    const encrypted = await api(eventPath, 'GET', undefined, aLogin.access_token);
    assert(encrypted.type === 'm.room.encrypted' && encrypted.content.ciphertext && !encrypted.content.body);
    assert(dbStatus(eventId) === 'encrypted');
    resume(bob);
    await bob.call('decrypt', { roomId, eventId, body });
    gates.push('recipient-process-stopped-send-resume-sync-decrypt');
    stage = 'other-user redaction and next-sync deletion';
    await alice.call('decrypt', { roomId, eventId, body });
    await suspend(alice);
    await bob.call('redact', { roomId, eventId }); // No sender approval, Bob is not server admin.
    const acknowledged = performance.now();
    const redacted = await api(eventPath, 'GET', undefined, bLogin.access_token);
    assert(redacted.unsigned?.redacted_because && Object.keys(redacted.content).length === 0);
    const apiLogicalMs = Math.round(performance.now() - acknowledged);
    resume(alice);
    await alice.call('deleted', { roomId, eventId });
    await bob.call('deleted', { roomId, eventId });
    gates.push('other-user-redaction-logical-and-offline-next-sync');
    stage = 'active event_json rewrite <=300 seconds';
    let scrubMs;
    while (performance.now() - acknowledged <= 300000) {
        const status = dbStatus(eventId);
        assert(['encrypted', 'scrubbed'].includes(status));
        if (status === 'scrubbed') { scrubMs = Math.round(performance.now() - acknowledged); break; }
        await sleep(500);
    }
    assert(scrubMs !== undefined && scrubMs <= 300000);
    gates.push('active-logical-row-scrub-under-300s');
    // Reciprocal permission check: Alice also redacts a Bob-authored event.
    stage = 'reciprocal ordinary-user redaction';
    const reverseId = await bob.call('send', { roomId, body: 'synthetic-reciprocal' });
    await alice.call('redact', { roomId, eventId: reverseId });
    await bob.call('deleted', { roomId, eventId: reverseId });
    gates.push('both-ordinary-users-can-redact-other');
    const report = { status: 'passed', gates, apiLogicalMs, activeRowScrubMs: scrubMs, samples: 1,
        offlineModel: 'Linux SIGSTOP/SIGCONT; memory preserved; NOT cold reopen',
        physicalErasure: 'NOT verified; WAL/backups/free-pages/media/client-storage out of scope' };
    await writeFile(new URL('runtime/result.json', import.meta.url), JSON.stringify(report, null, 2), { mode: 0o600 });
    console.log(JSON.stringify(report));
} catch {
    console.error(`FAIL: ${stage}. Sensitive exception details suppressed.`);
    process.exitCode = 1;
} finally {
    clearTimeout(deadline);
    for (const child of children) { child.kill('SIGCONT'); child.kill('SIGTERM'); }
    await sleep(250);
    for (const child of children) if (child.exitCode === null) child.kill('SIGKILL');
}
