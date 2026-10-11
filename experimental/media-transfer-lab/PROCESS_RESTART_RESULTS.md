# 별도 OS 프로세스 경계의 암호문 이어받기 검증

## 확인한 Linux 증거
- 실행: https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38153855816
- job:114512655737. 전체14초,job11초,시험 단계2초. 소스03c9cf8,workflow8efa5f8. lab-matrix-cleanup-followup만 사용.
- 직접 검사한 집계: **4 pass /0 fail /0 cancelled /0 skipped**. 기존 코드·정책 포함31개 소스 해시 guard 성공.
- 시험 후 전용 자식 프로세스 없음, fixture namespace 없음. 별도 always 정리 단계에서 같은 부재 확인 및 전체 임시 namespace 제거 확인. **강제 자식 정리0건**. 논리적 시험 자원 정리이며 물리적 삭제 아님.

## 시험별 경계
|시험|검증 내용|
|---|---|
|1|8MiB 암호문을 반쪽16개 청크까지 ACK한 실제 자식 정상 종료. 종료 관측 후 다른 PID로 실행하여 정확히16개 재개. 마지막 ACK 청크 중복 수신을 멱등 재전송으로 처리. 전체 암호문 해시 및 기대 평문8MiB 해시·길이 검증.|
|2|모든 기록 await가 끝난 ACK 유휴 경계에서 실제 SIGKILL. exit signal 확인 후 다른 PID로 재개·완료·검증 복호화. 쓰기 중 종료가 아님.|
|3|새 프로세스의 합성 권한 false로 initialize가 정확한 not_authorized 거부. 이후 accept/finish도 같은 코드,추가 ACK 및 평문 출력0.|
|4|합성 권한 true지만 bindingId가 변경된 manifest로 initialize가 정확한 manifest_changed 거부. 권한 거부와 구분,추가 ACK 및 평문 출력0.|

수신 manifest 및 모든 기존 청크의 해시,송신 원본 암호문을 독립 비교하여 보존 확인. 파일/폴더 owner0600/0700 확인. 청크256KiB,총32개,시험마다 독립 fixture. 자식의 전체 파일 해시 확인 후 검증된 스트리밍 복호화하며 평문/키 fixture 파일을 만들지 않음. descriptor/key는 부모 RAM에서 자식 RAM IPC로 전달하고 공개 로그에는 넣지 않음. stdout/stderr 버림,IPC는 고정 명령·응답 vocabulary와 시간 제한. 모든 이전 자식의 exit를 관측한 뒤 재실행,모든 자식 및 임시 roots 독립 정리. CI는 private marker/uid로 소유 fixture worker만 검사·필요시 정리.

## 명확한 제한
- **부모 시험 프로세스는 계속 살아 있으며 RAM의 키를 다시 전달한다.** 전체 앱/부모/runner 상실이나 영속 키 복원 시험이 아님.
- 실제 자식 프로세스 종료에 한정. ACK 유휴 SIGKILL은 중간 쓰기 손상,전원 손실,rename 디렉터리 fsync 내구성,파일시스템 복구를 증명하지 않음.
- 권한과 설명자는 **합성 fixture**. mock clock1000/expiry2000으로 실제 TTL/시계 복구도 미검증. 이전 실제 SDK 연결5/5(run38152247874)와 별도 결과이며 합쳐 실제 SDK 앱 재시작 보장으로 주장하지 않음.
- 실제 MXC/미디어/인터넷/Android/사용자기기/방/humanOOB,GB/RSS/용량,원자적 철회,backup,물리적 삭제,hard runner-loss 정리 미검증.
- 기존 receiver/stream/SDK/conversation/입장/기기 신뢰/ingress/broker 정책 구현 불변. main/Pages/앱/NCP/배포/비용/용량 변경 없음. 새 파일+실험 workflow만 추가.

## 검토와 실패 기록
독립 읽기 전용 검토에서 중대한 코드 문제 미발견. 외부 보안감사나 독립 runtime 재실행은 아님. Windows spawn 기반 보조 구문 검사 응답 없음으로 종료했으며 로컬 실행/구문 통과 주장 없음. Linux 첫 실행은4/4 성공. CI action 자체에 Node20 deprecation/Node24 강제 실행 경고가 있었으나 시험 Node22 단계 및 결과와 구분,경고 수정/운영 변경 없음. 이전 stock restart/cleanup/timeout 실패 기록 유지. 실제 집계와 정리 화면 증거 sessiontmp에 저장; 비밀 자료/원시 로그/프로필 업로드 없음.

이 한정 단계 완료. 결과·재개 상태 백업 후 종료,자동 다음 단계 체인 없음.
