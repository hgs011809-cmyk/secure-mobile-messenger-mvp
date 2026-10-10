// Diagnose public, unauthenticated endpoint only. Never dump URLs/errors/container configuration.
import { execFileSync } from 'node:child_process';
const endpoint = '/_matrix/client/versions';
const errorCodes = new Set(['NONE', 'HTTP_STATUS', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT',
    'EHOSTUNREACH', 'ENETUNREACH', 'UND_ERR_CONNECT_TIMEOUT', 'TIMEOUT', 'CONNECTION_ERROR', 'UNKNOWN']);
export function sanitizeProbe(value) {
    return { status: Number.isInteger(value?.status) && value.status >= 100 && value.status <= 599 ? value.status : 0,
        error: errorCodes.has(value?.error) ? value.error : 'UNKNOWN' };
}
async function hostProbe(base) {
    try {
        const response = await fetch(base + endpoint, { signal: AbortSignal.timeout(3000), redirect: 'error' });
        await response.body?.cancel();
        return { status: response.status, error: response.status === 200 ? 'NONE' : 'HTTP_STATUS' };
    } catch (error) {
        return sanitizeProbe({ status: 0, error: error.name === 'TimeoutError' ? 'TIMEOUT' : error.cause?.code });
    }
}
function runDocker(args, timeout = 5000) {
    return execFileSync('docker', args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}
function localProbe(ci) {
    try {
        return sanitizeProbe(JSON.parse(runDocker(['compose', '-f', ci + 'compose.yaml', 'exec', '-T',
            'synapse', 'python', '/ci/probe_http.py'])));
    } catch { return { status: 0, error: 'CONNECTION_ERROR' }; }
}
function inspectedPrivateBridge(ci) {
    // Discover ONLY this job's own service on its exact internal bridge. No generic URL override.
    const container = runDocker(['compose', '-f', ci + 'compose.yaml', 'ps', '-q', 'synapse']);
    if (!/^[a-f0-9]{12,64}$/.test(container)) return null;
    const network = 'matrix-server-integration_offline';
    const properties = runDocker(['network', 'inspect', '--format', '{{.Internal}} {{.Driver}}', network]);
    if (properties !== 'true bridge') return null;
    const ip = runDocker(['inspect', '--format', `{{(index .NetworkSettings.Networks "${network}").IPAddress}}`, container]);
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || !octets.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) return null;
    const [a, b] = octets;
    if (!(a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168))) return null;
    return `http://${ip}:8008`;
}
export async function waitForServer(ci, budgetMs = 90000) {
    const start = Date.now();
    let attempt = 0;
    while (Date.now() - start < budgetMs) {
        const host = await hostProbe('http://127.0.0.1:18008');
        const local = localProbe(ci);
        // Emit fixed labels/codes only; no response body, route parameters or exception text.
        if (attempt % 10 === 0 || host.status === 200 || local.status === 200) {
            console.log(JSON.stringify({ readiness: { hostLoopback: sanitizeProbe(host), containerLocal: local } }));
        }
        if (host.status === 200 && local.status === 200) {
            console.log('readiness_transport=host-loopback');
            return 'http://127.0.0.1:18008';
        }
        if (local.status === 200 && host.status !== 200) {
            // Concrete differential evidence: listener works locally but published path fails.
            // Docker docs allow host access to its private user-defined bridge containers.
            let privateBase;
            try { privateBase = inspectedPrivateBridge(ci); } catch { privateBase = null; }
            const bridge = privateBase ? await hostProbe(privateBase) : { status: 0, error: 'UNKNOWN' };
            console.log(JSON.stringify({ readiness: { hostPrivateBridge: sanitizeProbe(bridge) } }));
            if (bridge.status === 200) {
                console.log('readiness_transport=host-private-internal-bridge; loopback_publication_gate=FAILED');
                return privateBase;
            }
        }
        attempt++;
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    throw new Error('sanitized readiness gate failed');
}
