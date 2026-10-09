# 직접대화 실사용 전환 계획

## 현재 운영 범위

v0.5.0은 Android Chrome/PWA에서 두 사용자가 앱을 실행한 상태로 사용하는 1:1 포그라운드 메신저를 목표로 합니다.

- 공용 PeerJS Cloud 신호 서버
- Google STUN
- WebRTC DataChannel / DTLS 전송 암호화
- 안전 코드 직접 대조
- 서버 메시지 본문 저장 없음

아직 독립 보안 감사를 받지 않았으며 앱 계층 E2EE 프로토콜을 구현한 제품이 아닙니다.

## A단계: 포그라운드 안정화

- [x] Android 홈 화면 설치
- [x] 고정 연결 코드와 중복 탭 복구
- [x] 전체 초대 링크 또는 `dm-...` 코드 수동 연결
- [x] 작성 중 문구 보존
- [x] 안전 코드 생성 시간초과
- [x] 상대별 화면 메시지·초안 분리
- [x] 오래된 PeerJS 이벤트 차단
- [x] 전송 실패 시 초안 유지
- [x] 선택형 일반 알림과 화면 켜짐 유지
- [x] 사용자 승인 후 서비스 워커 업데이트
- [x] WebRTC 직접 연결 단계와 기기 확인 단계를 구분하고 15초 timeout 후 재시도 화면으로 복귀
- [x] 데스크톱 A/B/C 회귀 시험: 안전 코드, 송수신·ack, 수신 중 초안 보존, 상대별 대화 분리, 재연결
- [ ] Android 두 대에서 v0.5.0 실기기 회귀 시험

## B단계: 자체 신호 서버와 TURN

목적: 통신사, 회사망, VPN, 대칭 NAT 등에서 직접 연결 성공률을 높입니다.

- [x] Caddy `forward_auth`로 모든 PeerJS 경로 인증
- [x] 일회용 초대 코드와 기기 공개키 등록
- [x] 비추출 P-256 기기 키의 단기 challenge 서명 검증
- [x] peerId 고정, 짧은 수명, 1회용 signaling 토큰
- [x] TURN 장기 비밀키를 브라우저에 노출하지 않는 10분 coturn REST 자격증명
- [x] 기기 목록·폐기·초대 발급 내부 관리 CLI
- [x] API CORS, 요청 크기 제한, 메모리 속도 제한, 무로그 기본값
- [x] PWA 등록 화면과 공용/자체 서버 모드 분리
- [x] NCP 서버·DNS 실제 배포
- [x] 외부망 API·인증 signaling·STUN·TURN 자격증명/할당 검증
- [ ] Android 두 대에서 자체 서버 모드 연결 및 모바일망↔Wi-Fi TURN 경로 검증
- [ ] 장애 모니터링과 최소 로그 보존 정책 확정

주의: PeerJS의 `key`와 기본 `token`은 인증 수단이 아닙니다. PeerServer 포트를 외부에 직접 노출하지 않고 Caddy 인증 경로만 허용해야 합니다.

## C단계: Web Push 깨우기 알림

목적: 상대 앱이 백그라운드이거나 종료됐을 때 메시지 내용 없이 “앱을 열어 주세요” 알림을 전달합니다.

필요 구성:

- VAPID 키를 보관하는 백엔드
- 브라우저 PushSubscription 등록·해지 API
- 연결 코드와 구독 정보의 수명·삭제 정책
- 초대 또는 기기 인증
- 메시지 본문을 포함하지 않는 일반 알림

Web Push는 상대를 깨우는 신호일 뿐입니다. 실제 메시지는 앱이 열리고 P2P 연결이 다시 만들어진 뒤 전송합니다.

## D단계: 암호화된 오프라인 대기열

상대가 완전히 오프라인인 동안 메시지를 임시 보관하려면 별도 앱 계층 암호화 프로토콜, 키 교체, 재전송, 중복 제거, 만료·삭제 정책, 독립 보안 검토가 필요합니다. 검증된 E2EE SDK 또는 프로토콜을 우선 검토합니다.

## 2026-10-10 NCP 배포 및 검증 결과

- 도메인: `api`·`signal`·`turn.thevault73.com`을 공인 IP `211.233.206.144`에 연결하고 HTTPS 인증서를 발급함
- 운영 스택: NCP 한국 VPC의 Micro(g3)에 Caddy, Node 인증 API, PeerServer 1.0.2, coturn 4.18.0 배포
- 인증 검증: 일회용 초대 재사용 거부, P-256 challenge 재사용 거부, 1회용 WSS 토큰 재사용 거부, 기기 폐기 후 재인증 거부 자동화
- TURN 검증: 10분 coturn REST 자격증명으로 UDP 인증·할당과 TCP 릴레이 성공. 서버 정책이 동일 클라이언트 자기 릴레이를 차단하므로 Android 두 대의 UDP 릴레이는 실기기 단계에서 확인
- 배포 검증: GitHub Actions `Deploy NCP pilot #17` 성공, 최신 CI와 Pages 배포도 성공
- 네트워크 정책: SSH 22는 관리자 IP /32만 허용. 공개 80/443, TURN 3478 TCP·UDP와 49160-49200 UDP만 인바운드 허용
- 최소 아웃바운드: DNS 53 TCP·UDP, HTTP 80, HTTPS 443, NTP 123 UDP, TURN peer relay 1024-65535 UDP만 허용
- 비밀값: 서버의 Docker secret으로만 보관하고 GitHub Pages에는 포함하지 않음
- 로그: 연결 메타데이터 최소화를 위해 Caddy access log와 coturn session log는 비활성화
- 클라이언트 전환: 자체 서버 모드는 구현됐지만 `config.js`는 Android 두 대 검증 전까지 `public` 모드 유지

## B·C단계 시작에 필요한 결정

- [x] 도메인: `thevault73.com`
- [x] Linux 호스팅 후보: NCP 한국 VPC
- [ ] 월 운영비 승인과 Micro 무료 적용 여부 확인
- [x] 사용자 인증 방식: 일회용 초대 기반 기기 공개키 등록
- [x] 장기 클라이언트 토큰 대신 기기 서명과 단기 자격증명 사용
- [ ] 장애 조사 시 필요한 최소 로그와 보존 기간

비밀키나 TURN 공유 비밀값은 정적 GitHub Pages 클라이언트에 넣지 않습니다. 공개 `config.js`는 Android 실기기 검증과 단계적 전환이 끝날 때까지 `public` 모드를 유지합니다.
