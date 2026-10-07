(() => {
'use strict';
const enc = new TextEncoder();
const dec = new TextDecoder();
const app = document.getElementById('app');
const modalRoot = document.getElementById('modal-root');
const toastEl = document.getElementById('toast');
const profile = (new URL(location.href).searchParams.get('profile') || 'main').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20) || 'main';
const K = (key) => `direct.v1.${profile}.${key}`;
const icons = {
  share:'<path d="M12 3v12m0-12 4 4m-4-4L8 7"/><path d="M5 11v8h14v-8"/>',
  copy:'<rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V5H5v11h3"/>',
  link:'<path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.1-1.1"/>',
  shield:'<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',
  send:'<path d="m5 12 7-7 7 7M12 5v15"/>',
  back:'<path d="m15 18-6-6 6-6"/>',
  trash:'<path d="M4 6h16M9 6V3h6v3M6 6l1 15h10l1-15"/>',
  device:'<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 18h4"/>',
  lock:'<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  refresh:'<path d="M20 6v5h-5M4 18v-5h5"/><path d="M18 9a7 7 0 0 0-12-3L4 8m2 7a7 7 0 0 0 12 3l2-2"/>'
};
const icon = (name) => `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[name]}</svg>`;
const escapeHtml = (s='') => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {
  name: localStorage.getItem(K('name')) || '',
  peerId: localStorage.getItem(K('peerId')) || '',
  peer: null,
  peerReady: false,
  conn: null,
  connAccepted: false,
  remote: null,
  helloSent: false,
  helloVerified: false,
  safetyCode: '',
  keyChanged: false,
  manuallyVerified: false,
  peerManuallyVerified: false,
  verificationSent: false,
  inboundTimes: [],
  outboundTimes: [],
  messages: [],
  screen: 'home',
  status: '초기화 중',
  identity: null,
  identityPersistent: true,
  deferredInstall: null,
  pendingConnect: new URL(location.href).searchParams.get('connect') || '',
  handled: new Set()
};
let toastTimer;
function toast(message) { clearTimeout(toastTimer); toastEl.textContent = message; toastEl.classList.add('show'); toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2600); }
function randomBytes(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function b64url(bytes) { let s=''; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function fromB64url(s) { const p=s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4); const raw=atob(p); return Uint8Array.from(raw,c=>c.charCodeAt(0)); }
function randomId(bytes=15) { return b64url(randomBytes(bytes)).toLowerCase(); }
function makePeerId() { return `dm-${Array.from(randomBytes(15),b=>b.toString(16).padStart(2,'0')).join('')}`; }
function nowTime(ts=Date.now()) { return new Date(ts).toLocaleTimeString('ko-KR',{hour:'2-digit',minute:'2-digit',hour12:false}); }
function validPeerId(id) { return /^dm-[a-f0-9]{30}$/.test(id); }
function baseInvite() { const u = new URL(location.href); u.search=''; u.hash=''; u.searchParams.set('connect', state.peerId); return u.toString(); }
function copyText(text) { if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text); const ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();return Promise.resolve(); }
function storageKeyForPeer(id) { return K(`trusted.${id}`); }
function withinRateLimit(bucket,max=30){const cutoff=Date.now()-60000;while(bucket.length&&bucket[0]<cutoff)bucket.shift();if(bucket.length>=max)return false;bucket.push(Date.now());return true;}
function connectionLabel() { if (!navigator.onLine) return '인터넷 연결 없음'; if (state.conn?.open && state.helloVerified) return '상대와 직접 연결됨'; if (state.conn) return '연결 확인 중'; if (state.peerReady) return '초대 대기 중'; return state.status; }
function connectionDot() { if (state.conn?.open && state.helloVerified) return 'online'; if (state.conn || state.status.includes('중')) return 'busy'; return ''; }
function header(action='') { return `<header class="topbar"><div class="brand">D</div><div class="top-title"><strong>직접대화 <span class="pill">PILOT</span></strong><small><i class="status-dot ${connectionDot()}"></i>${escapeHtml(connectionLabel())}</small></div>${action}</header>${navigator.onLine?'':'<div class="offline-banner">오프라인입니다. 새 연결과 메시지 전송은 사용할 수 없습니다.</div>'}`; }
function render() { if (!state.name) return renderOnboarding(); if (state.screen === 'chat' && state.conn) return renderChat(); renderHome(); }
function renderOnboarding() {
  app.innerHTML = `<div class="shell">${header()}<main class="main"><section class="hero"><div class="eyebrow">1:1 P2P MESSENGER</div><h1>두 사람이 직접<br>연결되는 대화.</h1><p>대화 내용은 서비스 서버에 저장하지 않습니다. 상대와 동시에 접속해 실시간으로 사용합니다.</p></section><form id="start-form"><label class="field"><span>대화에 표시할 이름</span><input id="display-name" maxlength="24" autocomplete="nickname" placeholder="예: 보스" required></label><button class="primary" type="submit">내 연결 만들기</button></form><div class="notice">이 버전은 제한된 파일럿입니다. WebRTC 전송은 암호화되지만 상대의 신원은 안전 코드로 직접 확인해야 합니다. 의료·금융·법률·영업비밀 등 고위험 자료에는 아직 사용하지 마세요.</div></main><div class="footer-note">메시지 기록 없음 · 두 사람 동시 접속 필요 · 파일 전송 미지원</div></div>`;
  document.getElementById('start-form').addEventListener('submit', e => { e.preventDefault(); const name=document.getElementById('display-name').value.trim(); if (!name) return; state.name=name; localStorage.setItem(K('name'),name); initPeer().then(render); });
}
function renderHome() {
  const ready = state.peerReady;
  app.innerHTML = `<div class="shell">${header(`<button class="icon-button" id="security-info" aria-label="보안과 한계 보기">${icon('info')}</button>`)}<main class="main"><section class="hero"><div class="eyebrow">HELLO, ${escapeHtml(state.name)}</div><h1>초대 링크를 보내고<br>상대와 연결하세요.</h1><p>상대가 링크를 열고 연결을 수락하면 실시간 대화를 시작할 수 있습니다.</p></section><section class="card"><div class="card-title"><strong>내 연결 코드</strong><span class="pill">${ready?'준비됨':'연결 중'}</span></div><div class="peer-code">${ready?escapeHtml(state.peerId):'<span class="spinner"></span> 신호 서버 연결 중'}</div><div class="button-grid"><button class="mini-button" id="share" ${ready?'':'disabled'}>${icon('share')} 링크 공유</button><button class="mini-button" id="copy" ${ready?'':'disabled'}>${icon('copy')} 링크 복사</button></div></section><section class="card"><div class="card-title"><strong>상대 코드로 연결</strong></div><div class="connect-row"><input id="remote-id" aria-label="상대 연결 코드" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="dm-로 시작하는 코드" value="${escapeHtml(state.pendingConnect)}"><button id="connect" ${ready?'':'disabled'}>연결</button></div><div class="hint">초대 링크를 열면 상대 코드는 자동으로 입력됩니다.</div></section><div class="section-title">이번 파일럿의 범위</div><div class="feature-list"><div class="feature"><span class="inline-icon">${icon('lock')}</span><div><strong>암호화된 실시간 전송</strong>WebRTC 데이터 채널을 사용합니다. 메시지는 서비스 서버에 저장하지 않습니다.</div></div><div class="feature"><span class="inline-icon">${icon('shield')}</span><div><strong>안전 코드 확인</strong>대화 상대와 코드를 직접 비교해야 신원 바꿔치기 위험을 줄일 수 있습니다.</div></div><div class="feature"><span class="inline-icon">${icon('device')}</span><div><strong>기록을 남기지 않는 화면</strong>새로고침하거나 앱을 닫으면 화면의 메시지가 사라집니다.</div></div></div><div class="warning" style="margin-top:22px">무료 공용 신호 서버를 사용합니다. 메시지 본문을 전달하지는 않지만 연결 코드·접속 시각·IP 관련 메타데이터가 처리될 수 있습니다. 일부 회사·통신망에서는 TURN 서버가 없어 연결이 실패할 수 있습니다.</div>${state.deferredInstall?'<button class="secondary install" id="install">홈 화면에 설치</button>':''}</main><div class="footer-note">파일럿 v0.1 · 공용 PeerJS 신호 서버 · 실제 보안 감사 전</div></div>`;
  document.getElementById('security-info').onclick = showSecurityInfo;
  const copy=document.getElementById('copy'); if(copy) copy.onclick=()=>copyText(baseInvite()).then(()=>toast('초대 링크를 복사했습니다.'));
  const share=document.getElementById('share'); if(share) share.onclick=async()=>{const data={title:'직접대화 초대',text:`${state.name}님이 1:1 대화에 초대했습니다.`,url:baseInvite()};try{if(navigator.share)await navigator.share(data);else{await copyText(data.url);toast('공유 기능 대신 링크를 복사했습니다.');}}catch(e){if(e.name!=='AbortError')toast('공유하지 못했습니다. 링크 복사를 이용해 주세요.');}};
  document.getElementById('connect').onclick=()=>connectTo(document.getElementById('remote-id').value.trim());
  document.getElementById('remote-id').addEventListener('keydown',e=>{if(e.key==='Enter')connectTo(e.currentTarget.value.trim());});
  const install=document.getElementById('install'); if(install) install.onclick=async()=>{state.deferredInstall.prompt();await state.deferredInstall.userChoice;state.deferredInstall=null;render();};
  if (state.pendingConnect && ready) setTimeout(()=>{const id=state.pendingConnect;state.pendingConnect='';connectTo(id);},50);
}
function isSecureChannelReady() { return !!(state.conn?.open && state.helloVerified && state.manuallyVerified && state.peerManuallyVerified && !state.keyChanged); }
function renderChat() {
  const remoteName = state.remote?.name || state.conn?.metadata?.name || '연결 상대';
  const verified = isSecureChannelReady();
  app.innerHTML = `<div class="shell"><div class="chat-shell"><header class="chat-head"><button class="back" id="back" aria-label="연결 화면으로 돌아가기">${icon('back')}</button><div class="avatar">${escapeHtml(remoteName.slice(0,1).toUpperCase())}</div><div class="person"><strong>${escapeHtml(remoteName)}</strong><small>${state.helloVerified?'서명된 기기 확인 완료':'기기 확인 중'} · ${state.conn?.open?'온라인':'연결 종료'}</small></div><button class="icon-button" id="safety" aria-label="안전 코드 보기">${icon('shield')}</button></header><button class="security-bar ${verified?'verified':''}" id="security-bar">${verified?'양쪽 기기 확인 완료':state.keyChanged?'경고: 이전과 다른 상대 키입니다':!state.safetyCode?'안전 코드 생성 중':!state.manuallyVerified?'안전 코드를 직접 비교하고 확인하세요':!state.peerManuallyVerified?'상대의 확인을 기다리는 중':'안전 코드 확인 중'}</button><div class="messages" id="messages" role="log" aria-live="polite">${messageHtml()}</div><form class="composer" id="composer"><textarea id="message-input" maxlength="2000" rows="1" placeholder="메시지 입력" aria-label="메시지 입력" ${isSecureChannelReady()?'':'disabled'}></textarea><button class="send" type="submit" aria-label="메시지 보내기" disabled>${icon('send')}</button></form></div></div>`;
  document.getElementById('back').onclick=()=>{state.screen='home';render();};
  document.getElementById('safety').onclick=showSafety;
  document.getElementById('security-bar').onclick=showSafety;
  const form=document.getElementById('composer'), input=document.getElementById('message-input'), send=form.querySelector('.send');
  input.addEventListener('input',()=>{send.disabled=!input.value.trim()||!isSecureChannelReady();input.style.height='46px';input.style.height=Math.min(input.scrollHeight,130)+'px';});
  input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();form.requestSubmit();}});
  form.onsubmit=e=>{e.preventDefault();sendChat(input.value.trim());input.value='';input.style.height='46px';send.disabled=true;};
  scrollMessages();
}
function messageHtml() { if(!state.messages.length)return '<div class="empty-chat">연결되었습니다.<br>안전 코드를 확인한 뒤 대화를 시작하세요.<br><br>이 화면의 메시지는 새로고침하면 사라집니다.</div>'; return state.messages.map(m=>`<div class="message-row ${m.mine?'mine':''}"><div class="bubble">${escapeHtml(m.text)}</div><div class="message-meta">${m.mine?(m.delivered?'전달됨':'전송됨'):'수신'}<br>${escapeHtml(nowTime(m.ts))}</div></div>`).join(''); }
function scrollMessages(){const box=document.getElementById('messages');if(box)box.scrollTop=box.scrollHeight;}
async function openIdentityDb(){return await new Promise((resolve,reject)=>{const r=indexedDB.open(`direct-identity-${profile}`,1);r.onupgradeneeded=()=>r.result.createObjectStore('keys');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});}
async function idbGet(db,key){return await new Promise((resolve,reject)=>{const r=db.transaction('keys').objectStore('keys').get(key);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});}
async function idbPut(db,key,value){return await new Promise((resolve,reject)=>{const r=db.transaction('keys','readwrite').objectStore('keys').put(value,key);r.onsuccess=()=>resolve();r.onerror=()=>reject(r.error);});}
async function loadIdentity(){try{const db=await openIdentityDb();let pair=await idbGet(db,'identity');if(!pair){pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);await idbPut(db,'identity',pair);}const pub=await crypto.subtle.exportKey('spki',pair.publicKey);return {pair,publicKey:b64url(pub)};}catch(e){console.error(e);state.identityPersistent=false;const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);const pub=await crypto.subtle.exportKey('spki',pair.publicKey);return {pair,publicKey:b64url(pub)};}}
async function signText(text){return b64url(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},state.identity.pair.privateKey,enc.encode(text)));}
async function verifyText(publicKey,text,signature){try{const key=await crypto.subtle.importKey('spki',fromB64url(publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,fromB64url(signature),enc.encode(text));}catch{return false;}}
async function makeSafetyCode(a,b){const sorted=[a,b].sort().join('|');const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(sorted)));const digits=Array.from(hash.slice(0,10),v=>String(v).padStart(3,'0')).join('').slice(0,20);return digits.match(/.{1,4}/g).join(' ');}
async function initPeer(){if(state.peer||!state.name)return;if(!state.identity)state.identity=await loadIdentity();if(!validPeerId(state.peerId)){state.peerId=makePeerId();localStorage.setItem(K('peerId'),state.peerId);}state.status='신호 서버 연결 중';render();const peer=new Peer(state.peerId,{debug:1,config:{iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun1.l.google.com:19302'}]}});state.peer=peer;peer.on('open',id=>{state.peerId=id;state.peerReady=true;state.status='초대 대기 중';render();});peer.on('connection',conn=>handleIncoming(conn));peer.on('disconnected',()=>{state.peerReady=false;state.status='신호 서버 재연결 중';render();setTimeout(()=>{try{peer.reconnect();}catch{}},1200);});peer.on('close',()=>{state.peerReady=false;state.status='연결 종료';render();});peer.on('error',err=>{console.error(err);if(err.type==='unavailable-id'){state.peerId=makePeerId();localStorage.setItem(K('peerId'),state.peerId);try{peer.destroy();}catch{}state.peer=null;setTimeout(initPeer,300);return;}if(err.type==='peer-unavailable')toast('상대를 찾을 수 없습니다. 링크가 최신인지 확인하세요.');else if(err.type==='network'||err.type==='server-error')toast('신호 서버에 연결하지 못했습니다.');else toast(`연결 오류: ${err.type||'알 수 없음'}`);state.status='오류 발생';render();});}
function handleIncoming(conn){if(state.conn&&state.conn.open){conn.close();return;}state.conn=conn;state.connAccepted=false;state.helloSent=false;state.helloVerified=false;state.safetyCode='';state.keyChanged=false;state.manuallyVerified=false;state.peerManuallyVerified=false;state.verificationSent=false;state.inboundTimes=[];state.outboundTimes=[];state.handled.clear();state.remote={name:(conn.metadata?.name||'알 수 없는 사용자').slice(0,24),peerId:conn.peer,publicKey:''};bindConnection(conn);showIncoming();}
function showIncoming(){showModal(`<h2>대화 연결 요청</h2><p><strong>${escapeHtml(state.remote?.name||'알 수 없는 사용자')}</strong>가 연결을 요청했습니다.</p><div class="facts"><div class="fact"><strong>상대 연결 코드</strong><span>${escapeHtml(state.conn?.peer||'')}</span></div></div><div class="warning">표시 이름은 아직 검증되지 않았습니다. 연결 후 안전 코드를 상대와 직접 비교하세요.</div><button class="primary" id="accept">연결 수락</button><button class="danger" id="decline">거절</button>`);document.getElementById('accept').onclick=()=>{state.connAccepted=true;state.screen='chat';closeModal();if(state.conn?.open)sendHello();render();};document.getElementById('decline').onclick=()=>{state.conn?.close();resetConnection();closeModal();render();};}
function connectTo(id){if(!state.peerReady)return toast('내 연결이 준비될 때까지 잠시 기다려 주세요.');if(!validPeerId(id))return toast('올바른 상대 연결 코드를 입력해 주세요.');if(id===state.peerId)return toast('내 연결 코드로는 연결할 수 없습니다.');if(state.conn)state.conn.close();resetConnection(false);state.peerManuallyVerified=false;state.verificationSent=false;state.inboundTimes=[];state.outboundTimes=[];state.status='상대 연결 중';state.remote={name:'연결 상대',peerId:id,publicKey:''};const conn=state.peer.connect(id,{reliable:true,serialization:'json',metadata:{name:state.name,protocol:'direct-v2'}});state.conn=conn;state.connAccepted=true;state.screen='chat';bindConnection(conn);render();}
function bindConnection(conn){if(conn.__bound)return;conn.__bound=true;conn.on('open',()=>{if(state.conn!==conn)return;state.status='연결됨';if(state.connAccepted)sendHello();render();});conn.__dataQueue=Promise.resolve();conn.on('data',data=>{conn.__dataQueue=conn.__dataQueue.then(()=>handleData(data)).catch(()=>{});});conn.on('close',()=>{if(state.conn!==conn)return;state.status='상대와 연결 종료';toast('상대와 연결이 종료되었습니다.');render();});conn.on('error',err=>{console.error(err);toast('상대 연결에서 오류가 발생했습니다.');});}
async function sendHello(){if(!state.conn?.open||state.helloSent)return;state.helloSent=true;const nonce=randomId(18),name=state.name.slice(0,24),signedName=b64url(enc.encode(name));const payload=`direct-v2|${state.peerId}|${state.conn.peer}|${nonce}|${state.identity.publicKey}|${signedName}`;const signature=await signText(payload);state.conn.send({type:'hello',version:2,peerId:state.peerId,name,publicKey:state.identity.publicKey,nonce,signature});}
async function handleData(data){if(!data||typeof data!=='object'||state.conn?.peer===undefined)return;if(data.type==='hello')return handleHello(data);if(!state.helloVerified)return;if(data.type==='verified'){if(data.version!==1||data.peerId!==state.conn.peer||data.publicKey!==state.remote?.publicKey)return;state.peerManuallyVerified=true;if(state.screen==='chat')renderChat();return;}if(!isSecureChannelReady())return;if(data.type==='chat'){if(typeof data.id!=='string'||data.id.length>100||typeof data.text!=='string'||data.text.length<1||data.text.length>2000)return;if(state.handled.has(data.id))return;if(state.messages.length>=500||!withinRateLimit(state.inboundTimes)){toast('메시지 임시 한도에 도달했습니다. 연결을 종료합니다.');state.conn.close();return;}state.handled.add(data.id);state.messages.push({id:data.id,text:data.text,ts:Number(data.ts)||Date.now(),mine:false,delivered:true});state.conn.send({type:'ack',id:data.id});if(state.screen==='chat')renderChat();else toast(`${state.remote?.name||'상대'}에게 메시지가 왔습니다.`);return;}if(data.type==='ack'){const m=state.messages.find(x=>x.id===data.id&&x.mine);if(m){m.delivered=true;if(state.screen==='chat')renderChat();}}}
async function handleHello(data){if(data.version!==2||data.peerId!==state.conn.peer||typeof data.name!=='string'||typeof data.publicKey!=='string'||typeof data.nonce!=='string'||typeof data.signature!=='string')return state.conn.close();const name=data.name.slice(0,24),signedName=b64url(enc.encode(name));const payload=`direct-v2|${data.peerId}|${state.peerId}|${data.nonce}|${data.publicKey}|${signedName}`;const valid=await verifyText(data.publicKey,payload,data.signature);if(!valid){toast('상대 기기 서명을 확인하지 못했습니다.');state.conn.close();return;}state.remote={name,peerId:data.peerId,publicKey:data.publicKey};state.helloVerified=true;state.safetyCode=await makeSafetyCode(state.identity.publicKey,data.publicKey);const known=localStorage.getItem(storageKeyForPeer(data.peerId));state.keyChanged=!!known&&known!==data.publicKey;state.manuallyVerified=known===data.publicKey;if(state.manuallyVerified&&!state.keyChanged)sendVerification();if(!state.helloSent&&state.connAccepted)await sendHello();if(state.screen==='chat')renderChat();}
function sendVerification(){if(!state.conn?.open||!state.helloVerified||!state.manuallyVerified||state.keyChanged||state.verificationSent)return;state.verificationSent=true;state.conn.send({type:'verified',version:1,peerId:state.peerId,publicKey:state.identity.publicKey});}
function sendChat(text){if(!text||!isSecureChannelReady())return;if(state.messages.length>=500||!withinRateLimit(state.outboundTimes)){toast('메시지 임시 한도 또는 전송 속도 한도에 도달했습니다.');return;}const msg={type:'chat',id:randomId(12),text:text.slice(0,2000),ts:Date.now()};state.messages.push({...msg,mine:true,delivered:false});state.conn.send(msg);renderChat();}
function resetConnection(clearMessages=true){state.conn=null;state.connAccepted=false;state.remote=null;state.helloSent=false;state.helloVerified=false;state.safetyCode='';state.keyChanged=false;state.manuallyVerified=false;state.peerManuallyVerified=false;state.verificationSent=false;state.inboundTimes=[];state.outboundTimes=[];state.handled.clear();if(clearMessages)state.messages=[];state.status=state.peerReady?'초대 대기 중':'연결 준비 중';state.screen='home';}
function showSafety(){const remote=state.remote;if(!remote)return;showModal(`<h2>상대 기기 확인</h2><p>아래 코드를 상대방 화면의 코드와 전화 또는 직접 대면으로 비교하세요. 코드가 같아야 현재 연결의 기기 키가 일치합니다.</p><div class="safety-code">${escapeHtml(state.safetyCode||'생성 중')}</div>${state.keyChanged?'<div class="warning">이 연결 코드는 이전에 확인한 상대 키와 다릅니다. 상대의 기기 변경 여부를 별도로 확인하세요.</div>':''}<div class="facts"><div class="fact"><strong>상대</strong><span>${escapeHtml(remote.name)} · ${escapeHtml(remote.peerId)}</span></div><div class="fact"><strong>전송</strong><span>WebRTC DataChannel / DTLS 암호화</span></div></div><button class="primary" id="trust" ${state.safetyCode?'':'disabled'}>${state.manuallyVerified&&!state.keyChanged?'확인 완료됨':'코드를 비교했고 같습니다'}</button><button class="secondary" id="close-modal">닫기</button>`);document.getElementById('trust').onclick=()=>{localStorage.setItem(storageKeyForPeer(remote.peerId),remote.publicKey);state.manuallyVerified=true;state.keyChanged=false;sendVerification();closeModal();render();toast('이 상대 기기 키를 확인된 것으로 저장했습니다.');};document.getElementById('close-modal').onclick=closeModal;}
function showSecurityInfo(){showModal(`<h2>보안과 사용 한계</h2><p>이 파일럿은 메시지를 중앙 서버에 저장하지 않고 두 브라우저를 WebRTC 데이터 채널로 연결합니다.</p><div class="facts"><div class="fact"><strong>전송 보호</strong><span>WebRTC DTLS로 전송 구간을 암호화합니다. 앱 계층 E2EE 프로토콜을 구현한 것은 아닙니다.</span></div><div class="fact"><strong>서버 역할</strong><span>PeerJS 공용 서버가 연결 코드와 접속 후보를 중계합니다. 메시지 본문은 데이터 채널을 통해 전달됩니다.</span></div><div class="fact"><strong>남는 정보</strong><span>브라우저·네트워크·공용 신호 서버에 IP, 접속 시각, 연결 코드 등 메타데이터가 처리될 수 있습니다.</span></div><div class="fact"><strong>남는 위험</strong><span>안전 코드 비교를 생략한 키 바꿔치기, 호스팅/배포 계정 침해, 감염된 기기, 피싱, 상대의 캡처·촬영.</span></div></div><div class="warning">독립 보안 감사를 받지 않은 파일럿입니다. 의료·금융·법률·영업비밀 등 민감한 실제 자료는 보내지 마세요. 안전 코드는 별도 통화/대면으로 비교하고, 두 사람이 동시에 온라인이어야 합니다. TURN 서버가 없어 일부 네트워크에서는 연결되지 않을 수 있습니다.</div><button class="secondary" id="reset-id">이 기기의 연결 코드와 키 초기화</button><button class="primary" id="close-modal">확인</button>`);document.getElementById('close-modal').onclick=closeModal;document.getElementById('reset-id').onclick=()=>confirmReset();}
function confirmReset(){showModal(`<h2>기기 정보를 초기화할까요?</h2><p>내 연결 코드와 기기 키가 바뀝니다. 상대방에게는 이전과 다른 기기로 표시됩니다.</p><button class="danger" id="do-reset">초기화</button><button class="secondary" id="close-modal">취소</button>`);document.getElementById('close-modal').onclick=closeModal;document.getElementById('do-reset').onclick=()=>{localStorage.removeItem(K('peerId'));localStorage.removeItem(K('name'));indexedDB.deleteDatabase(`direct-identity-${profile}`);location.reload();};}
function showModal(html){modalRoot.innerHTML=`<div class="modal-layer"><section class="modal" role="dialog" aria-modal="true">${html}</section></div>`;modalRoot.querySelector('.modal-layer').onclick=e=>{if(e.target.classList.contains('modal-layer'))closeModal();};document.addEventListener('keydown',escapeModal,{once:true});}
function escapeModal(e){if(e.key==='Escape')closeModal();}
function closeModal(){modalRoot.innerHTML='';document.removeEventListener('keydown',escapeModal);}
window.addEventListener('online',()=>{toast('인터넷 연결이 복구되었습니다.');if(state.peer&&!state.peerReady){try{state.peer.reconnect();}catch{}}render();});
window.addEventListener('offline',()=>render());
window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();state.deferredInstall=e;render();});
window.addEventListener('pagehide',()=>{try{state.conn?.close();state.peer?.destroy();}catch{}});
async function boot(){if('serviceWorker' in navigator&&location.protocol.startsWith('http'))navigator.serviceWorker.register('./sw.js').catch(console.error);if(state.name){state.identity=await loadIdentity();await initPeer();}else render();}
boot().catch(e=>{console.error(e);state.status='초기화 실패';render();toast('앱을 시작하지 못했습니다. 새로고침해 주세요.');});
})();
