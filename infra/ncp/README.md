# NCP 파일럿 인프라

이 폴더는 `thevault73.com`의 하위 도메인으로 자체 PeerServer와 coturn을 배포하기 위한 준비물입니다. 현재는 **배포 전 스캐폴드**이며 NCP 자원을 생성하지 않았습니다.

## 확정된 범위

- `signal.thevault73.com`: Caddy HTTPS/WSS → PeerServer
- `turn.thevault73.com`: coturn TURN/STUN
- NCP 한국 리전, 별도 전용 VPC와 Public Subnet
- 정적 GitHub Pages에 TURN 공유 비밀키를 넣지 않음
- TURN은 시간 제한 자격증명만 사용하도록 `use-auth-secret` 구성
- 연결 메타데이터 최소화를 위해 Caddy access log와 coturn session log 비활성화
- 인증 API와 앱의 TURN 연결은 보류
- Caddy, PeerServer, coturn 이미지는 검토한 Docker digest에 고정
- IPv6는 초기 파일럿에서 비활성화하고 예약·사설 IPv4 relay 대상은 차단

TURN 서버는 WebRTC 암호화 데이터를 릴레이할 뿐 DataChannel 평문을 해독하지 않습니다. 그러나 현재 앱은 독립 보안 감사와 앱 계층 E2EE를 완료하지 않았으므로 고위험 자료에 사용하지 않습니다.

## NCP 예상 비용

콘솔에서 확인한 2026-10-09 기준입니다.

| 항목 | 사양 | 월 표시 요금 |
| --- | --- | ---: |
| Micro(g3) Server | 1 vCPU, 1GB RAM | 10,850원 |
| Public IP | 1개 | 4,032원 |
| 합계 | 트래픽·부가세 전 | 14,882원 |

콘솔은 결제정보 등록 계정의 Micro 서버를 1년간 무료로 사용할 수 있다고 안내합니다. 실제 계정 적용 여부와 트래픽 요금은 생성 직전 다시 확인합니다.

## 전용 네트워크 계획

기존 `vault` Subnet은 사용하지 않습니다. 신규 프로젝트를 분리해 아래처럼 생성합니다.

- VPC: `secure-msg-vpc`, 예: `10.20.0.0/24`
- Public Subnet: `secure-msg-public-kr1`, 예: `10.20.0.0/27`
- 서버: `secure-msg-pilot-1`, Ubuntu 24.04, Micro(g3)
- 공인 IP: 서버 1대에 고정 할당
- 반납 보호: 설정

CIDR은 NCP 콘솔에서 허용 범위를 확인한 뒤 최종 확정합니다.

## ACG 인바운드 규칙

| 프로토콜 | 포트 | 소스 | 용도 |
| --- | --- | --- | --- |
| TCP | 22 | 관리자 현재 공인 IP `/32`만 | SSH |
| TCP | 80 | `0.0.0.0/0` | ACME 인증과 HTTPS 전환 |
| TCP | 443 | `0.0.0.0/0` | PeerServer WSS |
| TCP | 3478 | `0.0.0.0/0` | TURN TCP |
| UDP | 3478 | `0.0.0.0/0` | STUN/TURN UDP |
| UDP | 49160-49200 | `0.0.0.0/0` | 파일럿 TURN relay 범위 |

SSH는 전 세계에 개방하지 않습니다. 호스트 UFW에도 같은 규칙을 적용합니다.

## DNS

공인 IP가 발급된 뒤 도메인 DNS에서 두 A 레코드를 같은 IP로 연결합니다.

- `signal.thevault73.com`
- `turn.thevault73.com`

초기 TTL은 300초를 권장합니다. Caddy가 `signal` 인증서를 자동 발급하므로 80/TCP와 443/TCP가 먼저 열려 있어야 합니다. 현재 TURN은 3478 TCP/UDP만 사용하며 TURN TLS/DTLS는 후속 단계입니다. TURN 제어 트래픽과 접속 메타데이터는 네트워크 관찰자에게 노출될 수 있지만, TURN을 통과하는 WebRTC DataChannel 본문은 DTLS로 계속 암호화됩니다. 적대적 네트워크까지 운영 범위로 넓히기 전에는 5349 기반 TURN TLS도 추가해야 합니다.

## 서버 배포 절차

Ubuntu 서버에 Docker Engine과 Compose v2를 설치한 뒤 이 폴더를 복사합니다.

```sh
cp .env.example .env
# .env에서 운영 이메일, 공인 IP, 사설 IP를 교체
chmod 600 .env

mkdir -p secrets
umask 077
openssl rand -hex 32 > secrets/turn_shared_secret
chmod 600 secrets/turn_shared_secret

chmod +x turn/start-coturn.sh scripts/*.sh
./scripts/preflight.sh
docker compose pull
docker compose up -d
docker compose ps
```

`docker compose ps`에서 PeerServer와 coturn이 모두 healthy인지 확인합니다. 그 다음 서버와 다른 외부 네트워크에서 아래 항목을 검증합니다.

```sh
curl -fsS https://signal.thevault73.com/healthz
curl -fsS https://signal.thevault73.com/peerjs
turnutils_stunclient -p 3478 turn.thevault73.com
```

추가로 짧은 수명의 시험 자격증명으로 `turnutils_uclient` allocation과 UDP relay를 검증합니다. 자격증명을 제3자 웹 진단 사이트에 붙여 넣지 않습니다. NCP ACG와 UFW에서 TCP/UDP 3478, UDP 49160-49200, TCP 80/443의 외부 도달 여부도 각각 확인합니다.

필요할 때만 서버 내부에서 1시간짜리 시험용 TURN 자격증명을 만듭니다.

```sh
./scripts/generate-turn-credential.sh qa-device
```

이 명령의 결과와 공유 비밀키는 커밋하거나 정적 웹 앱에 넣지 않습니다.

## 앱 연결 전 남은 작업

1. 보스의 유료 자원 생성 승인
2. NCP 전용 VPC, Subnet, ACG, Micro 서버, 공인 IP 생성
3. DNS A 레코드 연결과 인프라 검증
4. 기기 인증 또는 일회용 초대 기반 TURN 자격증명 API 설계
5. 인증 API에 속도 제한, 폐기, 감사 정책 적용
6. 그 뒤에만 앱의 PeerJS host와 `iceServers`를 운영 인프라로 전환
7. Android 두 대, Wi-Fi↔모바일망, TURN 강제 환경 회귀 시험

인증 API가 없으므로 현재 앱에는 TURN 자격증명을 배포하지 않습니다. coturn을 먼저 띄우더라도 관리자 시험 외에는 사용하지 않습니다. PeerServer의 `peerjs` key는 비밀키나 사용자 인증이 아니며, 동시 접속 제한만으로 공개 서비스 남용을 막을 수 없습니다. 인증과 서버 측 속도 제한이 준비될 때까지 이 스캐폴드는 외부 운영 배포 대상으로 승인하지 않습니다.
