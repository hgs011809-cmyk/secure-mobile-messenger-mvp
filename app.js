(() => {
'use strict';
const enc = new TextEncoder();
const dec = new TextDecoder();
const app = document.getElementById('app');
const modalRoot = document.getElementById('modal-root');
const toastEl = document.getElementById('toast');
const profile = (new URL(location.href).searchParams.get('profile') || 'main').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20) || 'main';
const K = (key) => `direct.v1.${profile}.${key}`;
const runtimeConfig = window.DIRECT_CONFIG || {};
const privateMode = runtimeConfig.mode === 'private';
const apiBase = String(runtimeConfig.apiBase || '').replace(/\/$/, '');
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
  helloPromise: null,
  helloVerified: false,
  safetyCode: '',
  keyChanged: false,
  manuallyVerified: false,
  peerManuallyVerified: false,
  verificationSent: false,
  pendingVerification: null,
  inboundTimes: [],
  outboundTimes: [],
  messages: [],
  screen: 'home',
  status: '초기화 중',
  identity: null,
  identityPersistent: true,
  deferredInstall: null,
  pendingConnect: new URL(location.href).searchParams.get('connect') || '',
  handled: new Set(),
  draft: '',
  connectionError: '',
  handshakeTimer: null,
  handshakeStage: '연결 준비 중',
  peerIdRetryCount: 0,
  peerRetryTimer: null,
  lastRemotePeerId: localStorage.getItem(K('lastRemotePeerId')) || '',
  autoReconnectPending: false,
  autoReconnectAttempts: 0,
  autoReconnectTimer: null,
  unreadCount: 0,
  keepAwake: localStorage.getItem(K('keepAwake')) === '1',
  wakeLock: null,
  swRegistration: null,
  updateReady: false,
  reloadingForUpdate: false,
  deviceId: localStorage.getItem(K('deviceId')) || '',
  authBusy: false,
  authStatus: privateMode ? '기기 인증 준비 중' : '',
  authError: '',
  privateSession: null
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
function normalizePeerId(value) { const raw=String(value||'').trim(); if(validPeerId(raw))return raw; try{const id=new URL(raw).searchParams.get('connect')||'';if(validPeerId(id))return id;}catch{} return raw; }
function baseInvite() { const u = new URL(location.href); u.search=''; u.hash=''; u.searchParams.set('connect', state.peerId); return u.toString(); }
function copyText(text) { if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text); const ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();return Promise.resolve(); }
function storageKeyForPeer(id) { return K(`trusted.${id}`); }
function withinRateLimit(bucket,max=30){const cutoff=Date.now()-60000;while(bucket.length&&bucket[0]<cutoff)bucket.shift();if(bucket.length>=max)return false;bucket.push(Date.now());return true;}
function withDeadline(promise,ms,message){let timer;return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error(message)),ms);})]).finally(()=>clearTimeout(timer));}
function ensurePeerId(){if(!validPeerId(state.peerId)){state.peerId=makePeerId();localStorage.setItem(K('peerId'),state.peerId);}return state.peerId;}
function authMessage(error){const code=error?.code||'';if(code==='invite_invalid')return '초대 코드가 올바르지 않거나 이미 사용되었습니다.';if(['device_not_found','device_revoked','signature_invalid','peer_mismatch'].includes(code))return '이 기기의 서버 등록을 확인할 수 없습니다. 새 초대 코드가 필요합니다.';if(code==='peer_already_registered')return '이 연결 코드는 이미 다른 기기 등록에 묶여 있습니다. 관리자에게 기존 등록 해제를 요청하세요.';if(code==='rate_limited')return '요청이 너무 많습니다. 잠시 후 다시 시도하세요.';return error?.message||'인증 서버에 연결하지 못했습니다. 잠시 후 다시 시도하세요.';}
async function apiJson(path,body){if(!privateMode||!apiBase)throw new Error('인증 서버 설정이 없습니다.');const response=await withDeadline(fetch(`${apiBase}${path}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'}),8000,'인증 서버 응답 시간이 초과되었습니다.');let data={};try{data=await response.json();}catch{}if(!response.ok){const error=new Error(data.message||`인증 요청 실패 (${response.status})`);error.code=data.code||data.error||'';error.status=response.status;throw error;}return data;}
async function requestPrivateSession(){if(!state.deviceId)throw Object.assign(new Error('기기 등록이 필요합니다.'),{code:'device_not_found'});ensurePeerId();const challenge=await apiJson('/v1/challenge',{deviceId:state.deviceId,peerId:state.peerId});const signature=await signText(challenge.challengeText);const session=await apiJson('/v1/session',{deviceId:state.deviceId,peerId:state.peerId,challengeId:challenge.challengeId,signature});if(!session?.signalToken||!Array.isArray(session.iceServers))throw new Error('인증 서버 응답 형식이 올바르지 않습니다.');state.privateSession=session;return session;}
function handleAuthFailure(error,{forgetDevice=false}={}){console.error(error);state.authError=authMessage(error);state.authStatus='기기 인증 실패';if(forgetDevice||['device_not_found','device_revoked','signature_invalid','peer_mismatch'].includes(error?.code)){state.deviceId='';localStorage.removeItem(K('deviceId'));if(state.peer){const failedPeer=state.peer;state.peer=null;try{failedPeer.destroy();}catch{}}}state.peerReady=false;render();}
async function registerDevice(invite){if(state.authBusy)return;state.authBusy=true;state.authError='';state.authStatus='초대 코드 확인 중';render();try{if(!state.identity)state.identity=await loadIdentity();ensurePeerId();const result=await apiJson('/v1/register',{invite:String(invite||'').trim(),peerId:state.peerId,publicKey:state.identity.publicKey});if(!result?.deviceId)throw new Error('기기 등록 응답이 올바르지 않습니다.');state.deviceId=result.deviceId;localStorage.setItem(K('deviceId'),state.deviceId);state.authStatus='기기 등록 완료';toast('이 기기를 파일럿 서버에 등록했습니다.');}catch(error){state.authBusy=false;handleAuthFailure(error);return;}state.authBusy=false;await initPeer();render();}
async function reconnectPrivatePeer(peer){if(!privateMode||state.authBusy||state.peer!==peer||peer.destroyed)return;state.authBusy=true;state.authStatus='기기 재인증 중';render();try{const session=await requestPrivateSession();if(state.peer!==peer)return;peer.options.token=session.signalToken;peer.options.config={iceServers:session.iceServers};state.authError='';state.authStatus='기기 인증 완료';peer.reconnect();}catch(error){state.authBusy=false;handleAuthFailure(error);return;}finally{state.authBusy=false;}}
function clearAutoReconnectTimer(){if(state.autoReconnectTimer){clearTimeout(state.autoReconnectTimer);state.autoReconnectTimer=null;}}
function setUnread(count){state.unreadCount=Math.max(0,count);try{if(state.unreadCount&&'setAppBadge' in navigator)navigator.setAppBadge(state.unreadCount);else if(!state.unreadCount&&'clearAppBadge' in navigator)navigator.clearAppBadge();}catch{}}
async function showIncomingNotification(){if(typeof Notification==='undefined'||Notification.permission!=='granted'||!document.hidden)return;const options={body:'앱을 열어 새 메시지를 확인하세요.',icon:'./icon-192.png',badge:'./icon-192.png',tag:'direct-message',renotify:true};try{if('serviceWorker' in navigator){const reg=await navigator.serviceWorker.ready;await reg.showNotification('직접대화 새 메시지',options);}else new Notification('직접대화 새 메시지',options);}catch{}}
async function acquireWakeLock(){if(!state.keepAwake||document.hidden||state.screen!=='chat'||!state.conn?.open||!('wakeLock' in navigator)||state.wakeLock)return;try{state.wakeLock=await navigator.wakeLock.request('screen');state.wakeLock.addEventListener('release',()=>{state.wakeLock=null;});}catch{}}
function releaseWakeLock(){try{state.wakeLock?.release();}catch{}state.wakeLock=null;}
function syncWakeLock(){if(state.keepAwake&&!document.hidden&&state.screen==='chat'&&state.conn?.open)acquireWakeLock();else releaseWakeLock();}
function notificationButtonText(){if(typeof Notification==='undefined')return '알림 미지원';if(Notification.permission==='granted')return '메시지 알림 켜짐';if(Notification.permission==='denied')return '알림이 차단됨';return '메시지 알림 켜기';}
function bindUtilityButtons(){const notify=document.getElementById('enable-notifications');if(notify)notify.onclick=async()=>{if(typeof Notification==='undefined')return toast('이 브라우저는 알림을 지원하지 않습니다.');if(Notification.permission==='denied')return toast('Android 설정에서 이 앱의 알림 권한을 허용해 주세요.');const permission=await Notification.requestPermission();render();toast(permission==='granted'?'앱이 실행 중일 때 메시지 알림을 표시합니다.':'알림 권한이 허용되지 않았습니다.');};const wake=document.getElementById('keep-awake');if(wake)wake.onclick=()=>{state.keepAwake=!state.keepAwake;localStorage.setItem(K('keepAwake'),state.keepAwake?'1':'0');syncWakeLock();render();toast(state.keepAwake?'대화 중 화면 켜짐 유지를 사용합니다.':'화면 켜짐 유지를 해제했습니다.');};}
function updateBanner(){return state.updateReady?'<div class="update-banner"><span>새 버전이 준비되었습니다.</span><button id="apply-update">업데이트</button></div>':'';}
function bindUpdateButton(){const button=document.getElementById('apply-update');if(!button)return;button.onclick=()=>{const warning=state.conn||state.messages.length||state.draft?'현재 연결과 화면 메시지, 작성 문구가 사라질 수 있습니다.':'';showModal(`<h2>앱을 업데이트할까요?</h2>${warning?`<div class="warning">${warning}</div>`:''}<p>새 버전을 적용하면 앱이 다시 열립니다.</p><button class="primary" id="confirm-update">업데이트 적용</button><button class="secondary" id="close-modal">나중에</button>`);document.getElementById('confirm-update').onclick=()=>{const worker=state.swRegistration?.waiting;if(!worker)return location.reload();state.reloadingForUpdate=true;worker.postMessage({type:'SKIP_WAITING'});};document.getElementById('close-modal').onclick=closeModal;};}
function connectionLabel() { if (!navigator.onLine) return '인터넷 연결 없음'; if (!state.name) return '이름 설정 후 시작'; if (state.conn?.open && state.helloVerified) return '상대와 직접 연결됨'; if (state.conn) return '연결 확인 중'; if (state.peerReady) return '초대 대기 중'; return state.status; }
function connectionDot() { if (state.conn?.open && state.helloVerified) return 'online'; if (state.conn || state.status.includes('중')) return 'busy'; return ''; }
function header(action='') { return `<header class="topbar"><div class="brand">D</div><div class="top-title"><strong>직접대화 <span class="pill">PILOT</span></strong><small><i class="status-dot ${connectionDot()}"></i>${escapeHtml(connectionLabel())}</small></div>${action}</header>${navigator.onLine?'':'<div class="offline-banner">오프라인입니다. 새 연결과 메시지 전송은 사용할 수 없습니다.</div>'}`; }
function render() { if (!state.name) return renderOnboarding(); if (privateMode && !state.deviceId) return renderDeviceRegistration(); if (state.screen === 'chat' && state.conn) return renderChat(); renderHome(); }
function renderOnboarding() {
  app.innerHTML = `<div class="shell">${header()}${updateBanner()}<main class="main"><section class="hero"><div class="eyebrow">1:1 P2P MESSENGER</div><h1>두 사람이 직접<br>연결되는 대화.</h1><p>대화 내용은 서비스 서버에 저장하지 않습니다. 상대와 동시에 접속해 실시간으로 사용합니다.</p></section><form id="start-form"><label class="field"><span>대화에 표시할 이름</span><input id="display-name" maxlength="24" autocomplete="nickname" placeholder="예: 보스" required></label><button class="primary" type="submit">내 연결 만들기</button></form><div class="notice">이 버전은 제한된 파일럿입니다. WebRTC 전송은 암호화되지만 상대의 신원은 안전 코드로 직접 확인해야 합니다. 의료·금융·법률·영업비밀 등 고위험 자료에는 아직 사용하지 마세요.</div><button class="secondary install" id="install">${state.deferredInstall?'홈 화면에 설치':'홈 화면에 추가 안내'}</button></main><div class="footer-note">메시지 기록 없음 · 두 사람 동시 접속 필요 · 파일 전송 미지원</div></div>`;
  document.getElementById('start-form').addEventListener('submit', e => { e.preventDefault(); const name=document.getElementById('display-name').value.trim(); if (!name) return; state.name=name; localStorage.setItem(K('name'),name); initPeer().then(render); });
  bindUpdateButton();
  bindInstallButton();
}
function renderDeviceRegistration(){
  app.innerHTML=`<div class="shell">${header()}${updateBanner()}<main class="main"><section class="hero"><div class="eyebrow">PRIVATE PILOT</div><h1>이 기기를<br>한 번만 등록하세요.</h1><p>관리자가 전달한 일회용 초대 코드를 입력하면 이 기기의 공개키가 파일럿 서버에 등록됩니다.</p></section>${state.authError?`<div class="warning" style="margin-bottom:17px">${escapeHtml(state.authError)}</div>`:''}<form id="register-device"><label class="field"><span>일회용 초대 코드</span><input id="invite-code" maxlength="80" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="예: ABCD-EFGH-IJKL-MNOP" required></label><button class="primary" type="submit" ${state.authBusy?'disabled':''}>${state.authBusy?'확인 중':'이 기기 등록'}</button></form><div class="notice">초대 코드는 등록과 동시에 폐기됩니다. 서버에는 기기 공개키와 연결 코드만 저장하며, 기기 개인키와 대화 내용은 보내지 않습니다.</div><button class="secondary" id="reset-registration">이름과 기기 정보 다시 만들기</button></main><div class="footer-note">파일럿 v0.5.0 · 일회용 초대 기반 기기 등록</div></div>`;
  document.getElementById('register-device').onsubmit=e=>{e.preventDefault();registerDevice(document.getElementById('invite-code').value);};
  document.getElementById('reset-registration').onclick=confirmReset;
  bindUpdateButton();
}
function bindInstallButton() {
  const installButton = document.getElementById('install');
  if (!installButton) return;
  installButton.onclick = async () => {
    if (state.deferredInstall) {
      const installPrompt = state.deferredInstall;
      state.deferredInstall = null;
      installButton.textContent = '홈 화면에 추가 안내';
      try { installPrompt.prompt(); await installPrompt.userChoice; } catch { toast('설치 메뉴를 열지 못했습니다.'); }
      return;
    }
    showModal('<h2>홈 화면에 추가</h2><p><strong>iPhone/iPad</strong>에서는 Safari 공유 버튼을 누른 뒤 <strong>홈 화면에 추가</strong>를 선택하세요.</p><p><strong>Android</strong>에서는 Chrome 메뉴(⋮)에서 <strong>앱 설치</strong> 또는 <strong>홈 화면에 추가</strong>를 선택하세요.</p><p>설치 메뉴가 보이지 않으면 Safari 또는 Chrome으로 이 페이지를 다시 여세요.</p><button class="secondary" id="close-modal">닫기</button>');
    document.getElementById('close-modal').onclick = closeModal;
  };
}

function renderHome() {
  const ready = state.peerReady;
  app.innerHTML = `<div class="shell">${header(`<button class="icon-button" id="security-info" aria-label="보안과 한계 보기">${icon('info')}</button>`)}${updateBanner()}<main class="main"><section class="hero"><div class="eyebrow">HELLO, ${escapeHtml(state.name)}</div><h1>초대 링크를 보내고<br>상대와 연결하세요.</h1><p>상대가 링크를 열고 연결을 수락하면 실시간 대화를 시작할 수 있습니다.</p></section>${state.authError?`<div class="warning" style="margin-bottom:17px"><strong>기기 인증이 필요합니다.</strong><br>${escapeHtml(state.authError)}<button class="secondary" id="retry-auth" style="margin-top:10px" ${state.authBusy?'disabled':''}>${state.authBusy?'인증 중':'다시 인증'}</button></div>`:''}${state.connectionError?`<div class="warning" style="margin-bottom:17px"><strong>연결이 중단되었습니다.</strong><br>${escapeHtml(state.connectionError)}<br>두 사람 모두 앱을 화면에 열어 둔 뒤 다시 연결하세요.${state.pendingConnect?'<button class="secondary" id="retry-connect" style="margin-top:10px">다시 연결</button>':''}</div>`:''}${!state.identityPersistent?'<div class="warning" style="margin-bottom:17px"><strong>기기 키를 저장하지 못했습니다.</strong><br>브라우저 저장소 제한으로 앱을 다시 열면 안전 코드가 바뀔 수 있습니다.</div>':''}<section class="card"><div class="card-title"><strong>내 연결 코드</strong><span class="pill">${ready?'준비됨':'연결 중'}</span></div><div class="peer-code">${ready?escapeHtml(state.peerId):'<span class="spinner"></span> 신호 서버 연결 중'}</div><div class="button-grid"><button class="mini-button" id="share" ${ready?'':'disabled'}>${icon('share')} 초대 링크 공유</button><button class="mini-button" id="copy" ${ready?'':'disabled'}>${icon('copy')} 코드 복사</button></div></section><section class="card"><div class="card-title"><strong>상대 코드 또는 초대 링크로 연결</strong></div><div class="connect-row"><input id="remote-id" aria-label="상대 연결 코드 또는 초대 링크" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="dm- 코드 또는 전체 링크" value="${escapeHtml(state.pendingConnect)}"><button id="connect" ${ready?'':'disabled'}>연결</button></div><div class="hint">Android에서 링크가 바로 연결되지 않으면 전체 링크나 dm- 코드를 이 칸에 붙여 넣으세요.</div></section><section class="card"><div class="card-title"><strong>Android 사용 안정성</strong></div><div class="button-grid"><button class="mini-button" id="enable-notifications">${notificationButtonText()}</button><button class="mini-button" id="keep-awake">${state.keepAwake?'화면 켜짐 유지 중':'화면 켜짐 유지'}</button></div><div class="hint">알림은 앱 프로세스가 살아 있을 때만 보조적으로 동작합니다. 화면 켜짐 유지는 대화 화면에서만 적용됩니다.</div></section><div class="section-title">이번 파일럿의 범위</div><div class="feature-list"><div class="feature"><span class="inline-icon">${icon('lock')}</span><div><strong>WebRTC DTLS 전송 암호화</strong>앱 계층 E2EE가 아닌 브라우저 간 전송 구간 암호화입니다. 메시지는 서비스 서버에 저장하지 않습니다.</div></div><div class="feature"><span class="inline-icon">${icon('shield')}</span><div><strong>안전 코드 확인</strong>대화 상대와 코드를 직접 비교해야 신원 바꿔치기 위험을 줄일 수 있습니다.</div></div><div class="feature"><span class="inline-icon">${icon('device')}</span><div><strong>기록을 남기지 않는 화면</strong>새로고침하거나 앱을 닫으면 화면의 메시지가 사라집니다.</div></div></div>${privateMode?'<div class="warning" style="margin-top:22px">인증된 자체 신호 서버와 단기 TURN 자격증명을 사용합니다. 서버는 연결 코드·접속 시각·IP 관련 메타데이터를 처리하지만 메시지 본문은 전달하거나 저장하지 않습니다. 두 사람 모두 앱을 화면에 열어 두어야 하며, Android가 앱을 종료하면 알림과 전달을 보장할 수 없습니다.</div>':'<div class="warning" style="margin-top:22px">무료 공용 신호 서버를 사용합니다. 메시지 본문을 전달하지는 않지만 연결 코드·접속 시각·IP 관련 메타데이터가 처리될 수 있습니다. Wi-Fi와 모바일 데이터처럼 서로 다른 네트워크에서는 TURN 서버가 없어 연결이 실패할 수 있습니다. 두 사람 모두 앱을 화면에 열어 두어야 하며, 네트워크를 바꾸면 다시 연결해야 할 수 있습니다. 알림 권한을 허용하면 앱 프로세스가 살아 있을 때 일반 알림을 시도합니다. Android가 앱을 종료하면 알림과 전달을 보장할 수 없습니다.</div>'}<button class="secondary install" id="install">${state.deferredInstall?'홈 화면에 설치':'홈 화면에 추가 안내'}</button></main><div class="footer-note">파일럿 v0.5.0 · ${privateMode?'인증 신호 서버 + 단기 TURN':'공용 PeerJS 신호 서버'}</div></div>`;
  document.getElementById('security-info').onclick = showSecurityInfo;
  const retryAuth=document.getElementById('retry-auth');if(retryAuth)retryAuth.onclick=()=>{state.authError='';if(privateMode&&state.peer&&!state.peerReady)reconnectPrivatePeer(state.peer);else initPeer();};
  const retry=document.getElementById('retry-connect');if(retry)retry.onclick=()=>connectTo(state.pendingConnect);
  const copy=document.getElementById('copy'); if(copy) copy.onclick=()=>copyText(state.peerId).then(()=>toast('내 연결 코드를 복사했습니다.'));
  const share=document.getElementById('share'); if(share) share.onclick=async()=>{const data={title:'직접대화 초대',text:`${state.name}님이 1:1 대화에 초대했습니다.`,url:baseInvite()};try{if(navigator.share)await navigator.share(data);else{await copyText(data.url);toast('공유 기능 대신 링크를 복사했습니다.');}}catch(e){if(e.name!=='AbortError')toast('공유하지 못했습니다. 링크 복사를 이용해 주세요.');}};
  document.getElementById('connect').onclick=()=>connectTo(document.getElementById('remote-id').value.trim());
  document.getElementById('remote-id').addEventListener('keydown',e=>{if(e.key==='Enter')connectTo(e.currentTarget.value.trim());});
  bindUtilityButtons();
  bindUpdateButton();
  bindInstallButton();
  if (state.pendingConnect && ready && navigator.onLine && !state.connectionError) setTimeout(()=>{const id=state.pendingConnect;state.pendingConnect='';connectTo(id);},50);
  syncWakeLock();
}
function isSecureChannelReady() { return !!(state.conn?.open && state.helloVerified && state.manuallyVerified && state.peerManuallyVerified && !state.keyChanged); }
function renderChat() {
  const remoteName = state.remote?.name || state.conn?.metadata?.name || '연결 상대';
  const verified = isSecureChannelReady();
  const safetyStatus = verified?'양쪽 기기 확인 완료':state.keyChanged?'경고: 이전과 다른 상대 키입니다':!state.conn?.open?'직접 연결 수립 중':!state.safetyCode?state.handshakeStage:!state.manuallyVerified?'안전 코드를 직접 비교하고 확인하세요':!state.peerManuallyVerified?'상대의 확인을 기다리는 중':'안전 코드 확인 중';
  app.innerHTML = `<div class="shell"><div class="chat-shell"><header class="chat-head"><button class="back" id="back" aria-label="연결 화면으로 돌아가기">${icon('back')}</button><div class="avatar">${escapeHtml(remoteName.slice(0,1).toUpperCase())}</div><div class="person"><strong>${escapeHtml(remoteName)}</strong><small>${state.helloVerified?'서명된 기기 확인 완료':'기기 확인 중'} · ${state.conn?.open?'온라인':state.conn?'연결 중':'연결 종료'}</small></div><button class="icon-button" id="safety" aria-label="안전 코드 보기">${icon('shield')}</button></header>${updateBanner()}${!state.identityPersistent?'<div class="warning" style="margin:10px 13px 0">기기 키가 저장되지 않아 앱 재실행 시 안전 코드가 바뀔 수 있습니다.</div>':''}<button class="security-bar ${verified?'verified':''}" id="security-bar">${safetyStatus}</button><div class="messages" id="messages" role="log" aria-live="polite">${messageHtml()}</div><form class="composer" id="composer"><textarea id="message-input" maxlength="2000" rows="1" placeholder="메시지 입력" aria-label="메시지 입력" ${isSecureChannelReady()?'':'disabled'}>${escapeHtml(state.draft)}</textarea><button class="send" type="submit" aria-label="메시지 보내기" disabled>${icon('send')}</button></form></div></div>`;
  bindUpdateButton();
  document.getElementById('back').onclick=()=>{state.screen='home';render();};
  document.getElementById('safety').onclick=showSafety;
  document.getElementById('security-bar').onclick=showSafety;
  const form=document.getElementById('composer'), input=document.getElementById('message-input'), send=form.querySelector('.send');
  input.addEventListener('input',()=>{state.draft=input.value;send.disabled=!input.value.trim()||!isSecureChannelReady();input.style.height='46px';input.style.height=Math.min(input.scrollHeight,130)+'px';});
  input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();form.requestSubmit();}});
  form.onsubmit=e=>{e.preventDefault();sendChat(input.value.trim());};
  input.style.height='46px';input.style.height=Math.min(input.scrollHeight,130)+'px';send.disabled=!input.value.trim()||!isSecureChannelReady();
  scrollMessages();
  syncWakeLock();
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
function clearPeerRetryTimer(){if(state.peerRetryTimer){clearTimeout(state.peerRetryTimer);state.peerRetryTimer=null;}}
function schedulePeerRetry(){clearPeerRetryTimer();const delay=Math.min(1000+state.peerIdRetryCount*1000,8000);state.peerRetryTimer=setTimeout(()=>{state.peerRetryTimer=null;initPeer();},delay);}
async function initPeer(){
  if(state.peer||!state.name)return;
  clearPeerRetryTimer();
  if(privateMode&&!state.deviceId){state.authStatus='기기 등록 필요';render();return;}
  if(!state.identity)state.identity=await loadIdentity();
  ensurePeerId();
  state.status=privateMode?'기기 인증 중':'신호 서버 연결 중';
  state.authError='';
  render();
  let peerOptions={debug:1,config:{iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun1.l.google.com:19302'}]}};
  if(privateMode){
    state.authBusy=true;
    try{const session=await requestPrivateSession();const signaling=session.signaling||{};peerOptions={debug:1,host:signaling.host||runtimeConfig.signalHost,port:Number(signaling.port||runtimeConfig.signalPort||443),path:signaling.path||runtimeConfig.signalPath||'/peerjs',secure:signaling.secure!==false,token:session.signalToken,config:{iceServers:session.iceServers}};state.authStatus='기기 인증 완료';}
    catch(error){state.authBusy=false;handleAuthFailure(error);return;}
    state.authBusy=false;
  }
  const peer=new Peer(state.peerId,peerOptions);
  state.peer=peer;
  peer.on('open',id=>{if(state.peer!==peer)return;state.peerId=id;state.peerReady=true;state.peerIdRetryCount=0;state.connectionError='';state.authError='';state.status='초대 대기 중';clearPeerRetryTimer();render();});
  peer.on('connection',conn=>{if(state.peer!==peer){conn.close();return;}handleIncoming(conn);});
  peer.on('disconnected',()=>{if(state.peer!==peer)return;state.peerReady=false;state.status='신호 서버 재연결 중';render();setTimeout(()=>{if(state.peer!==peer)return;if(privateMode)reconnectPrivatePeer(peer);else try{peer.reconnect();}catch{}},1200);});
  peer.on('close',()=>{if(state.peer!==peer)return;state.peerReady=false;state.status='연결 종료';render();});
  peer.on('error',err=>{if(state.peer!==peer)return;console.error(err);if(err.type==='unavailable-id'){state.peer=null;try{peer.destroy();}catch{}state.peerReady=false;state.peerIdRetryCount+=1;state.status='기존 연결 코드 복구 중';state.connectionError=state.peerIdRetryCount>=3?'같은 연결 코드가 이전 앱 실행이나 다른 창에 아직 남아 있습니다. 다른 창을 닫고 잠시 기다리면 같은 코드를 다시 사용합니다.':'';render();schedulePeerRetry();return;}if(privateMode&&['network','server-error','socket-error','socket-closed'].includes(err.type)&&!state.peerReady){state.peer=null;try{peer.destroy();}catch{}state.status='인증 신호 서버 재연결 중';state.connectionError='인증 신호 서버에 연결하지 못했습니다. 잠시 후 자동으로 다시 시도합니다.';render();schedulePeerRetry();return;}if(err.type==='peer-unavailable'){if(state.conn&&!state.helloVerified){failConnection('상대 앱을 찾을 수 없습니다. 상대가 앱을 화면에 열어 둔 상태인지 확인하세요.',state.conn);return;}toast('상대를 찾을 수 없습니다. 상대 앱이 열려 있는지 확인하세요.');}else if(err.type==='network'||err.type==='server-error'){if(state.conn&&!state.helloVerified){failConnection('신호 서버에 연결하지 못했습니다. 네트워크를 확인하고 다시 시도하세요.',state.conn);return;}toast('신호 서버에 연결하지 못했습니다.');}else toast(`연결 오류: ${err.type||'알 수 없음'}`);state.status='오류 발생';render();});
}
function handleIncoming(conn){if(state.conn){conn.close();toast('이미 다른 연결을 처리 중입니다.');return;}state.conn=conn;state.connAccepted=false;state.helloSent=false;state.helloPromise=null;state.helloVerified=false;state.handshakeStage='연결 준비 중';state.safetyCode='';state.keyChanged=false;state.manuallyVerified=false;state.peerManuallyVerified=false;state.verificationSent=false;state.pendingVerification=null;state.inboundTimes=[];state.outboundTimes=[];state.handled.clear();state.remote={name:(conn.metadata?.name||'알 수 없는 사용자').slice(0,24),peerId:conn.peer,publicKey:''};bindConnection(conn);showIncoming();}
function showIncoming(){showModal(`<h2>대화 연결 요청</h2><p><strong>${escapeHtml(state.remote?.name||'알 수 없는 사용자')}</strong>가 연결을 요청했습니다.</p><div class="facts"><div class="fact"><strong>상대 연결 코드</strong><span>${escapeHtml(state.conn?.peer||'')}</span></div></div><div class="warning">표시 이름은 아직 검증되지 않았습니다. 연결 후 안전 코드를 상대와 직접 비교하세요.</div><button class="primary" id="accept">연결 수락</button><button class="danger" id="decline">거절</button>`);document.getElementById('accept').onclick=()=>{const peerId=state.conn?.peer||'';if(validPeerId(peerId)&&state.lastRemotePeerId!==peerId){state.messages=[];state.draft='';}if(validPeerId(peerId)){state.lastRemotePeerId=peerId;localStorage.setItem(K('lastRemotePeerId'),peerId);}state.connAccepted=true;state.screen='chat';closeModal();if(state.conn?.open){startHandshakeTimeout(state.conn);sendHello();}render();};document.getElementById('decline').onclick=()=>{const conn=state.conn;resetConnection({clearMessages:true,clearDraft:true});closeModal();try{conn?.close();}catch{}render();};}
function clearHandshakeTimer(){if(state.handshakeTimer){clearTimeout(state.handshakeTimer);state.handshakeTimer=null;}}
function startHandshakeTimeout(conn){clearHandshakeTimer();state.handshakeTimer=setTimeout(()=>{if(state.conn===conn&&!state.helloVerified)failConnection('안전 코드 생성 시간이 초과되었습니다. 상대 앱을 화면에 열어 둔 뒤 다시 연결하세요.',conn);},15000);}
function failConnection(reason,conn=state.conn){if(conn&&state.conn!==conn)return;const retryId=state.remote?.peerId||conn?.peer||state.lastRemotePeerId||'';const active=conn;resetConnection({clearMessages:false,clearDraft:false});closeModal();state.pendingConnect=validPeerId(retryId)?retryId:'';state.connectionError=reason;state.status='연결 실패';try{active?.close();}catch{}render();toast(reason);}
function connectTo(value){const id=normalizePeerId(value);if(!state.peerReady)return toast('내 연결이 준비될 때까지 잠시 기다려 주세요.');if(!validPeerId(id))return toast('올바른 상대 연결 코드를 입력해 주세요.');if(id===state.peerId)return toast('내 연결 코드로는 연결할 수 없습니다.');const samePeer=state.lastRemotePeerId===id;const active=state.conn;resetConnection({clearMessages:!samePeer,clearDraft:!samePeer});try{active?.close();}catch{}state.lastRemotePeerId=id;localStorage.setItem(K('lastRemotePeerId'),id);state.connectionError='';state.pendingConnect='';state.peerManuallyVerified=false;state.verificationSent=false;state.pendingVerification=null;state.inboundTimes=[];state.outboundTimes=[];state.status='상대 연결 중';state.remote={name:'연결 상대',peerId:id,publicKey:''};const conn=state.peer.connect(id,{reliable:true,serialization:'json',metadata:{name:state.name,protocol:'direct-v2'}});state.conn=conn;state.connAccepted=true;state.screen='chat';bindConnection(conn);render();}
function bindConnection(conn){if(conn.__bound)return;conn.__bound=true;const openTimer=setTimeout(()=>{if(state.conn===conn&&!conn.open)failConnection('직접 연결 시간이 초과되었습니다. 두 앱을 화면에 열어 두고 다시 연결하세요.',conn);},15000);conn.on('open',()=>{clearTimeout(openTimer);if(state.conn!==conn)return;state.status='연결됨';if(state.connAccepted){startHandshakeTimeout(conn);sendHello();}render();});let dataQueue=Promise.resolve();conn.on('data',data=>{dataQueue=dataQueue.then(()=>handleData(data,conn)).catch(err=>{console.error(err);if(state.conn===conn)failConnection('수신 데이터를 처리하지 못했습니다. 두 앱을 열어 둔 뒤 다시 연결하세요.',conn);});});conn.on('close',()=>{clearTimeout(openTimer);if(state.conn!==conn)return;failConnection(state.connAccepted?'상대 앱이 닫혔거나 네트워크가 변경되어 연결이 종료되었습니다.':'연결 요청이 취소되었거나 만료되었습니다.',conn);});conn.on('error',err=>{clearTimeout(openTimer);console.error(err);if(state.conn===conn)failConnection('상대 연결에서 오류가 발생했습니다. 두 앱을 열어 둔 뒤 다시 시도하세요.',conn);});}
async function sendHello(){if(!state.conn?.open)return;if(state.helloSent)return state.helloPromise;state.helloSent=true;state.handshakeStage='내 기기 정보 서명 중';if(state.screen==='chat')renderChat();const conn=state.conn;state.helloPromise=(async()=>{const nonce=randomId(18),name=state.name.slice(0,24),signedName=b64url(enc.encode(name));const payload=`direct-v2|${state.peerId}|${conn.peer}|${nonce}|${state.identity.publicKey}|${signedName}`;const signature=await signText(payload);if(state.conn!==conn||!conn.open)return;conn.send({type:'hello',version:2,peerId:state.peerId,name,publicKey:state.identity.publicKey,nonce,signature});state.handshakeStage='상대 기기 정보 대기 중';if(state.screen==='chat')renderChat();})().catch(err=>{console.error(err);if(state.conn===conn)failConnection('기기 확인 정보를 보내지 못했습니다. 다시 연결하세요.',conn);});return state.helloPromise;}
async function handleData(data,conn){if(state.conn!==conn||!data||typeof data!=='object'||conn.peer===undefined)return;if(data.type==='hello'){state.handshakeStage='상대 서명 확인 중';if(state.screen==='chat')renderChat();return handleHello(data,conn);}if(data.type==='verified'){if(data.version!==1||data.peerId!==conn.peer)return;if(!state.helloVerified){state.pendingVerification=data;return;}if(data.publicKey!==state.remote?.publicKey)return;state.peerManuallyVerified=true;if(state.screen==='chat')renderChat();return;}if(!state.helloVerified)return;if(!isSecureChannelReady())return;if(data.type==='chat'){if(typeof data.id!=='string'||data.id.length>100||typeof data.text!=='string'||data.text.length<1||data.text.length>2000)return;if(state.handled.has(data.id))return;if(state.messages.length>=500||!withinRateLimit(state.inboundTimes)){toast('메시지 임시 한도에 도달했습니다. 연결을 종료합니다.');conn.close();return;}state.handled.add(data.id);state.messages.push({id:data.id,text:data.text,ts:Number(data.ts)||Date.now(),mine:false,delivered:true});try{conn.send({type:'ack',id:data.id});}catch{}if(document.hidden){setUnread(state.unreadCount+1);showIncomingNotification();}if(state.screen==='chat')renderChat();else toast(`${state.remote?.name||'상대'}에게 메시지가 왔습니다.`);return;}if(data.type==='ack'){const m=state.messages.find(x=>x.id===data.id&&x.mine);if(m){m.delivered=true;if(state.screen==='chat')renderChat();}}}
async function handleHello(data,conn){if(state.conn!==conn)return;if(data.version!==2||data.peerId!==conn.peer||typeof data.name!=='string'||typeof data.publicKey!=='string'||typeof data.nonce!=='string'||typeof data.signature!=='string')return failConnection('상대의 기기 확인 정보가 올바르지 않습니다.',conn);const name=data.name.slice(0,24),signedName=b64url(enc.encode(name));const payload=`direct-v2|${data.peerId}|${state.peerId}|${data.nonce}|${data.publicKey}|${signedName}`;const valid=await withDeadline(verifyText(data.publicKey,payload,data.signature),5000,'서명 확인 시간 초과');if(state.conn!==conn)return;if(!valid){failConnection('상대 기기 서명을 확인하지 못했습니다.',conn);return;}state.handshakeStage='안전 코드 계산 중';if(state.screen==='chat')renderChat();state.connectionError='';state.remote={name,peerId:data.peerId,publicKey:data.publicKey};state.helloVerified=true;state.safetyCode=await withDeadline(makeSafetyCode(state.identity.publicKey,data.publicKey),5000,'안전 코드 계산 시간 초과');if(state.conn!==conn)return;state.handshakeStage='안전 코드를 직접 비교하세요';clearHandshakeTimer();const known=localStorage.getItem(storageKeyForPeer(data.peerId));state.keyChanged=!!known&&known!==data.publicKey;state.manuallyVerified=known===data.publicKey;if(state.pendingVerification){const pending=state.pendingVerification;state.pendingVerification=null;if(pending.version===1&&pending.peerId===conn.peer&&pending.publicKey===state.remote.publicKey)state.peerManuallyVerified=true;}if(!state.helloSent&&state.connAccepted)sendHello();if(state.manuallyVerified&&!state.keyChanged)sendVerification();if(state.screen==='chat')renderChat();}
function sendVerification(){if(!state.conn?.open||!state.helloVerified||!state.manuallyVerified||state.keyChanged||state.verificationSent)return;state.verificationSent=true;try{state.conn.send({type:'verified',version:1,peerId:state.peerId,publicKey:state.identity.publicKey});}catch{state.verificationSent=false;toast('기기 확인 응답을 보내지 못했습니다.');}}
function sendChat(text){if(!text||!isSecureChannelReady())return false;if(state.messages.length>=500||!withinRateLimit(state.outboundTimes)){toast('메시지 임시 한도 또는 전송 속도 한도에 도달했습니다.');return false;}const msg={type:'chat',id:randomId(12),text:text.slice(0,2000),ts:Date.now()};state.messages.push({...msg,mine:true,delivered:false});try{state.conn.send(msg);state.draft='';renderChat();return true;}catch{state.messages.pop();toast('메시지를 보내지 못했습니다. 작성 문구는 유지됩니다.');renderChat();return false;}}
function resetConnection({clearMessages=true,clearDraft=false}={}){clearHandshakeTimer();releaseWakeLock();state.conn=null;state.connAccepted=false;state.remote=null;state.helloSent=false;state.helloPromise=null;state.helloVerified=false;state.handshakeStage='연결 준비 중';state.safetyCode='';state.keyChanged=false;state.manuallyVerified=false;state.peerManuallyVerified=false;state.verificationSent=false;state.pendingVerification=null;state.inboundTimes=[];state.outboundTimes=[];state.handled.clear();if(clearMessages)state.messages=[];if(clearDraft)state.draft='';state.status=state.peerReady?'초대 대기 중':'연결 준비 중';state.screen='home';}
function showSafety(){const remote=state.remote;if(!remote)return;showModal(`<h2>상대 기기 확인</h2><p>아래 코드를 상대방 화면의 코드와 전화 또는 직접 대면으로 비교하세요. 코드가 같아야 현재 연결의 기기 키가 일치합니다.</p><div class="safety-code">${escapeHtml(state.safetyCode||'생성 중')}</div>${state.keyChanged?'<div class="warning">이 연결 코드는 이전에 확인한 상대 키와 다릅니다. 상대의 기기 변경 여부를 별도로 확인하세요.</div>':''}<div class="facts"><div class="fact"><strong>상대</strong><span>${escapeHtml(remote.name)} · ${escapeHtml(remote.peerId)}</span></div><div class="fact"><strong>전송</strong><span>WebRTC DataChannel / DTLS 암호화</span></div></div><button class="primary" id="trust" ${state.safetyCode?'':'disabled'}>${state.manuallyVerified&&!state.keyChanged?'확인 완료됨':'코드를 비교했고 같습니다'}</button><button class="secondary" id="close-modal">닫기</button>`);document.getElementById('trust').onclick=()=>{localStorage.setItem(storageKeyForPeer(remote.peerId),remote.publicKey);state.manuallyVerified=true;state.keyChanged=false;sendVerification();closeModal();render();toast('이 상대 기기 키를 확인된 것으로 저장했습니다.');};document.getElementById('close-modal').onclick=closeModal;}
function showSecurityInfo(){showModal(`<h2>보안과 사용 한계</h2><p>이 파일럿은 메시지를 중앙 서버에 저장하지 않고 두 브라우저를 WebRTC 데이터 채널로 연결합니다.</p><div class="facts"><div class="fact"><strong>전송 보호</strong><span>WebRTC DTLS로 전송 구간을 암호화합니다. 앱 계층 E2EE 프로토콜을 구현한 것은 아닙니다.</span></div><div class="fact"><strong>서버 역할</strong><span>${privateMode?'인증된 자체 PeerServer가 신호를 처리하고, 직접 연결이 안 될 때 자체 TURN이 암호화된 WebRTC 패킷을 중계합니다. TURN 자격증명은 기기 서명 후 단기로 발급됩니다.':'PeerJS 공용 서버가 연결 코드와 접속 후보를 중계합니다. 메시지 본문은 데이터 채널을 통해 전달됩니다.'}</span></div><div class="fact"><strong>남는 정보</strong><span>브라우저·네트워크·${privateMode?'자체 신호/TURN':'공용 신호'} 서버에 IP, 접속 시각, 연결 코드 등 메타데이터가 처리될 수 있습니다.</span></div><div class="fact"><strong>남는 위험</strong><span>안전 코드 비교를 생략한 키 바꿔치기, 호스팅/배포 계정 침해, 감염된 기기, 피싱, 상대의 캡처·촬영.</span></div></div><div class="warning">독립 보안 감사를 받지 않은 파일럿입니다. 의료·금융·법률·영업비밀 등 민감한 실제 자료는 보내지 마세요. 안전 코드는 별도 통화/대면으로 비교하고, 두 사람이 동시에 온라인이어야 합니다.${privateMode?' TURN을 사용해도 앱 종료 상태의 수신은 보장하지 않습니다.':' TURN 서버가 없어 일부 네트워크에서는 연결되지 않을 수 있습니다.'}</div><button class="secondary" id="reset-id">이 기기의 연결 코드와 키 초기화</button><button class="primary" id="close-modal">확인</button>`);document.getElementById('close-modal').onclick=closeModal;document.getElementById('reset-id').onclick=()=>confirmReset();}
function confirmReset(){showModal(`<h2>기기 정보를 초기화할까요?</h2><p>내 연결 코드와 기기 키가 바뀝니다. 상대방에게는 이전과 다른 기기로 표시됩니다.${privateMode?' 자체 서버를 다시 사용하려면 새 일회용 초대 코드가 필요합니다.':''}</p><button class="danger" id="do-reset">초기화</button><button class="secondary" id="close-modal">취소</button>`);document.getElementById('close-modal').onclick=closeModal;document.getElementById('do-reset').onclick=()=>{localStorage.removeItem(K('peerId'));localStorage.removeItem(K('name'));localStorage.removeItem(K('deviceId'));indexedDB.deleteDatabase(`direct-identity-${profile}`);location.reload();};}
function showModal(html){modalRoot.innerHTML=`<div class="modal-layer"><section class="modal" role="dialog" aria-modal="true">${html}</section></div>`;modalRoot.querySelector('.modal-layer').onclick=e=>{if(e.target.classList.contains('modal-layer'))closeModal();};document.addEventListener('keydown',escapeModal,{once:true});}
function escapeModal(e){if(e.key==='Escape')closeModal();}
function closeModal(){modalRoot.innerHTML='';document.removeEventListener('keydown',escapeModal);}
function resumePeer(){if(!state.name)return;if(!state.peer||state.peer.destroyed){state.peer=null;state.peerReady=false;initPeer();return;}if(!state.peerReady){if(privateMode)reconnectPrivatePeer(state.peer);else try{state.peer.reconnect();}catch{}}}
window.addEventListener('online',()=>{toast('인터넷 연결이 복구되었습니다.');resumePeer();render();});
window.addEventListener('offline',()=>{if(state.conn)failConnection('네트워크가 끊겼습니다. 연결이 복구되면 다시 연결하세요.',state.conn);else render();});
window.addEventListener('pageshow',resumePeer);
document.addEventListener('visibilitychange',()=>{if(document.hidden){releaseWakeLock();return;}setUnread(0);resumePeer();syncWakeLock();});
window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();state.deferredInstall=e;const installButton=document.getElementById('install');if(installButton)installButton.textContent='홈 화면에 설치';});
function renderCompatibilityError(message){app.innerHTML=`<div class="shell"><main class="main"><section class="hero"><div class="eyebrow">지원 확인 필요</div><h1>이 브라우저에서는<br>앱을 시작할 수 없습니다.</h1><p>${escapeHtml(message)}</p></section><div class="warning">Android 최신 Chrome에서 다시 열어 주세요. 카카오톡 내부 브라우저에서는 일부 기능이 동작하지 않을 수 있습니다.</div></main></div>`;}
async function registerServiceWorker(){if(!('serviceWorker' in navigator)||!location.protocol.startsWith('http'))return;try{const reg=await navigator.serviceWorker.register('./sw.js?v=18');state.swRegistration=reg;if(reg.waiting){state.updateReady=true;render();}reg.addEventListener('updatefound',()=>{const worker=reg.installing;if(!worker)return;worker.addEventListener('statechange',()=>{if(worker.state==='installed'&&navigator.serviceWorker.controller){state.updateReady=true;render();}});});navigator.serviceWorker.addEventListener('controllerchange',()=>{if(state.reloadingForUpdate)location.reload();});}catch(e){console.error(e);}}
async function boot(){if(typeof Peer==='undefined'||!window.crypto?.subtle||!window.indexedDB)return renderCompatibilityError('WebRTC 또는 안전한 기기 키 저장 기능을 사용할 수 없습니다.');registerServiceWorker();if(state.name){state.identity=await loadIdentity();await initPeer();}else render();}
boot().catch(e=>{console.error(e);state.status='초기화 실패';render();toast('앱을 시작하지 못했습니다. 새로고침해 주세요.');});
})();
