// Pure fixture protocol validation. No lifecycle or kernel-proof claims.
const bad = () => { throw new Error('PHASE_WORKER_UNVERIFIED'); };
export const NONCE = /^[a-f0-9]{64}$/;
export const MAX_SEEN_NONCES = 16;
export function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join('|') !== [...keys].sort().join('|')) bad();
}
export function decimal(v) { if (typeof v !== 'string' || !/^(0|[1-9][0-9]*)$/.test(v) || BigInt(v) > 18446744073709551615n) bad(); }
export function namespaces(v) { exact(v,['pid','cgroup','mount','time']); for (const [k,t] of Object.entries({pid:'pid',cgroup:'cgroup',mount:'mnt',time:'time'})) if (typeof v[k] !== 'string' || !new RegExp('^'+t+':\\[[1-9][0-9]*\\]$').test(v[k])) bad(); }
export function processFact(v) {
 exact(v,['pid','startTicks','state','membership','oomScoreAdj','namespaces']);
 if (!Number.isSafeInteger(v.pid) || v.pid < 1 || !['R','S','D','I'].includes(v.state) || v.membership !== '0::/' || v.oomScoreAdj !== 0) bad();
 decimal(v.startTicks); namespaces(v.namespaces);
}
export function request(v) {
 if (v?.op === 'challenge') exact(v,['version','op','nonce','milestone','pid']);
 else if (v?.op === 'release') exact(v,['version','op','nonce','pid']); else bad();
 if (v.version !== 1 || typeof v.nonce !== 'string' || !NONCE.test(v.nonce) || (v.op === 'challenge' && !['ready','result_ready'].includes(v.milestone))) bad();
 if (!Number.isSafeInteger(v.pid) || v.pid <= 1) bad(); return v;
}
export function caseResult(mode,milestone) {
 if (!['graceful','linger'].includes(mode) || !['ready','result_ready'].includes(milestone)) bad();
 const closed = mode === 'graceful' && milestone === 'result_ready';
 return {mode,childObserved:true,browserObserved:true,childrenAlive:!closed,childClosed:closed,browserClosed:closed,profileRemoved:closed,childCount:1};
}
export function witness(v) {
 exact(v,['version','nonce','milestone','init','client','cgroupRoot','containerMount','bounds','children','caseResult']);
 if (v.version !== 1 || typeof v.nonce !== 'string' || !NONCE.test(v.nonce) || !['ready','result_ready'].includes(v.milestone)) bad();
 processFact(v.init); processFact(v.client); if(v.init.pid !== 1 || v.client.pid === 1) bad();
 for (const k of ['pid','cgroup','mount','time']) if(v.client.namespaces[k] !== v.init.namespaces[k]) bad();
 exact(v.cgroupRoot,['device','inode','fsType']); decimal(v.cgroupRoot.device); decimal(v.cgroupRoot.inode); if(v.cgroupRoot.fsType !== '63677270') bad();
 exact(v.containerMount,['root','mountPoint','mountDevice','filesystem','readOnly','unexpectedOvermounts']);
 const m=v.containerMount; if(m.root !== '/' || m.mountPoint !== '/sys/fs/cgroup' || typeof m.mountDevice !== 'string' || !/^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$/.test(m.mountDevice) || m.filesystem !== 'cgroup2' || m.readOnly !== true || m.unexpectedOvermounts !== false) bad();
 exact(v.bounds,['memoryMax','memorySwapMax','cpuQuota','cpuPeriod','cpuBurst','pidsMax','cgroupType']);
 const b={memoryMax:'1073741824',memorySwapMax:'0',cpuQuota:'100000',cpuPeriod:'100000',cpuBurst:'0',pidsMax:'128',cgroupType:'domain'};
 for(const k of Object.keys(b)) if(v.bounds[k] !== b[k]) bad();
 exact(v.caseResult,Object.keys(caseResult(v.caseResult?.mode,v.milestone)));
 const expected=caseResult(v.caseResult.mode,v.milestone); for(const k of Object.keys(expected)) if(v.caseResult[k] !== expected[k]) bad();
 if(!Array.isArray(v.children) || v.children.length !== (expected.childrenAlive ? 2 : 0)) bad();
 for(let i=0;i<v.children.length;i++) {
 const c=v.children[i]; exact(c,['role','pid','startTicks','state','membership','oomScoreAdj','namespaces','executableClass','ancestorToInit']);
 const {role,executableClass,ancestorToInit,...p}=c; processFact(p);
 if(role !== ['node_child','chromium_main'][i] || executableClass !== ['node','chromium_main'][i] || ancestorToInit !== true || p.pid === 1 || p.pid === v.client.pid) bad();
 for(const k of Object.keys(v.init.namespaces)) if(p.namespaces[k] !== v.init.namespaces[k]) bad();
 }
 if(v.children.length === 2 && v.children[0].pid === v.children[1].pid) bad(); return v;
}
// Pure immutable state transition: callers commit only AFTER observation/output succeeds.
export function transition(state,req) {
 request(req); exact(state,['mode','milestone','pending','used']);
 if(!['graceful','linger'].includes(state.mode) || !['ready','result_ready','done'].includes(state.milestone) || !Array.isArray(state.used) || state.used.length > MAX_SEEN_NONCES || state.used.some(n=>typeof n !== 'string' || !NONCE.test(n)) || new Set(state.used).size !== state.used.length || (state.pending !== null && (typeof state.pending !== 'string' || !NONCE.test(state.pending) || !state.used.includes(state.pending)))) bad();
 const used=[...state.used];
 if(req.op === 'challenge') {
 // One active challenge only. A fresh nonce at the SAME actual milestone
 // permanently supersedes the pending nonce; history is never evicted.
 if(req.milestone !== state.milestone || used.includes(req.nonce) || used.length >= MAX_SEEN_NONCES) bad();
 return {...state,pending:req.nonce,used:[...used,req.nonce]};
 }
 if(state.pending !== req.nonce || (state.mode === 'linger' && state.milestone === 'result_ready')) bad();
 return {...state,pending:null,used,milestone:state.milestone === 'ready' ? 'result_ready' : 'done'};
}
