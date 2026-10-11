# 자율 실험 창 최종 근거 색인

범위: 2026-10-12 01:10:45..04:15 Asia/Seoul, `lab-matrix-cleanup-followup`만. 이 문서 작성자는 기존 결과/체크포인트만 읽어 정리했고 새 CI·런타임 시험을 실행하지 않았다. 부모 워커는 허용된 실험 브랜치 문서 백업에만 독립 GitHub 브라우저를 사용한다. 아래는 당시 집계·정리 로그를 검사했다고 기록된 증거이며 이 문서 작성자가 독립 재실행한 결과가 아니다.

각 시험군은 별개다. 합계로 실제 SDK 프로세스 충돌/복구 통합 증명을 만들지 않는다. 기존 core/crypto/receiver/입장/ingress/기기 신뢰/보안 정책 불변, main/Pages/운영 앱/NCP/배포/비용/용량 변경 없음.

## 1. 실제 SDK → 보존형 Node 전송: 이전 기준선

- [run38152247874](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38152247874), job `114507916337`.
- source `8170fc9`, workflow `c8e81c9`, results `f3f084c` (체크포인트에 기록된 단축 ID).
- 서로 다른 집계: 실제 SDK 전송 **5 pass/0 fail**; mock receipt 단위 **4 pass/0 fail/0 skip**; 같은 driver의 기존 4KiB SDK descriptor **6 pass/0 fail**. SDK 두 집계의 cancel/skip 및 mock cancel은 인용 결과/체크포인트에 별도 숫자가 없으므로 0으로 추정하지 않는다.
- 28 source/policy pins. 실제 SDK/Rust receipt, BOTH 최신 native lease, 두 ACTIVE 불변 registry binding, SDK device/room/event 검사를 반복한다. 원자적 철회 증명은 아니다.
- 8MiB/256KiB, private in-process ciphertext files, receiver는 **같은 프로세스 내 객체 재생성**. 손상 COPY의 `HASH_MISMATCH`, 실제 SDK REDACTED/원래 native 철회의 `AUTHORIZATION_DENIED`, 평문 callback 0과 source/cache 보존. native 철회 fixture는 sender-key-loss 문맥을 공유하므로 native-only 독립 시험이 아니다.
- 독립 always 정리에서 private fixture/profile/build/runtime, named extraction 등 container 부재, private profile 표시 프로세스 부재 확인 기록. 임의 process-tree/hard crash/물리적 삭제 증명은 아니다. 당시 screenshot timeout은 실패로 유지.

## 2. 실제 자식 프로세스 ACK 유휴 재시작: mock 권한

- [run38153855816](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38153855816), job `114512655737`.
- source `03c9cf8`, workflow `8efa5f8`, results `15ff7ad` (단축 ID).
- **4 pass/0 fail/0 cancelled/0 skipped**, 31 pins.
- 정상 종료 또는 ACK 완료 유휴 경계 SIGKILL 후 exit 관측, 다른 PID, resume16/중복 retry/전체 hash 및 기대 평문 검증. `not_authorized`, `manifest_changed` 정확한 거부.
- source/committed cache 보존, 자식/namespace 부재, independent always cleanup, 강제 정리 0. 부모 생존, RAM 키 재주입, mock clock/권한. 쓰기 중 종료·전체 앱·영속 키 복원·전원 손실 증명이 아니다.

## 3. 제어된 pending-write 프로세스 종료: 새 6개

- [run38155290344](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38155290344), job `114516900781`.
- source `e55abce833b9b478c26c2e40d334c112aa12ac07`
- workflow `a22c8f69d7a75a5bdf95e5517619c77262adfd8a`
- results `fbc3cbb044f676fa92146e702dc84ba2934f08c1`
- **6 pass/0 fail/0 cancelled/0 skipped**, flat6/nested0, 34 pins.
- 8MiB/256KiB. 실제 pending 파일을 의도적으로 131072바이트만 기록한 경계와 262144바이트 synced/closed 후 rename 전 경계에서 실제 SIGKILL. OS가 생성한 short-write나 powerloss가 아니다.
- 두 경계별 authorized resume/retry/hash, fresh mock 권한 거부, manifest 변경 거부. 정확한 코드 `incomplete`, `not_authorized`, `manifest_changed`, 부모 `AUTHORIZATION_DENIED`. 부모 거부 시험 평문 callback/bytes 0; 자식은 decrypt 경로 없는 구조적 0 vocabulary로 독립 decrypt 계측이 아니다.
- **기존 initialize는 manifest equality 검사 전에 pending을 폐기한다.** 변경 manifest 거부 시험은 pending 삭제를 예상하고 committed manifest/chunks와 source만 불변 주장한다. 전체 cache 불변이 아니다. 권한 거부는 pending도 보존한다.
- 독립 cleanup identity 검토 finding 수정/재검토. owned worker/root 부재, 강제 정리 0, container 생성 0. 부모/RAM 생존, mock 권한뿐이며 전체 앱/runner 복원·repair·fsync 내구성은 미검증.

## 4. 영속 암호문 손상/충돌 재시도: 새 6개

- [run38156343209](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38156343209), job `114520000959`.
- source `3421bc8dfb831df235e780384f97334c1e87d5cd`
- workflow `e6aa9d93021f7a491f93530c623e92ac2bd8aea0`
- results `366768b77fb36c9d73f05d6e13931f3abea460d2`
- **6 pass/0 fail/0 cancelled/0 skipped**, flat6/nested0/exit0, 38 pre/post pins (34 기존 불변).
- 짧거나 긴 stored chunk: `invalid_stored_chunk`; 직접 stream decrypt `HASH_MISMATCH`, 진짜 평문 sink 0.
- 동일 길이 변조는 **length-only resume32를 통과**하지만 원 retry `conflicting_retry`, finalize `integrity_failed`, decrypt `HASH_MISMATCH`. 전체 hash/trusted descriptor gate 전 release 금지라는 제한을 기록한다.
- 유효 자체 hash를 가진 충돌 retry `conflicting_retry`, 원본 retry 멱등/양성 decrypt 대조군 성공. mock false 권한 `not_authorized` 및 stream `AUTHORIZATION_DENIED`. 다른 manifest initialize `manifest_changed`; 이후 모든 메서드 거부 주장은 하지 않는다.
- **bare receiver initialize 실패는 latched가 아니다.** 호출자가 gate해야 한다. core 변경은 제안/차단만 하고 수정하지 않았다.
- 손상 주입 후 source/cache names/length/mode/uid/hash 보존, repair 없음. 독립 always 정리 alive0/stopped0/children0/containers0/private namespace 부재. 이 군에는 자식 프로세스·실제 SDK 없음. 첫 Actions 발견 지연은 원 push가 나중에 확인된 것으로 중복 trigger나 런타임 timeout으로 바꾸지 않는다.

## 5. 합성 ciphertext-only IPC foundation: 새 6개

- [run38158717874](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38158717874), job `114526955635`.
- source `ca0ef1f9ea059137544b606e902f9d3809a476d0`
- workflow `ec3cf78e9fa439b830983b6c1e0e690d36402460`
- results `a082491db5227ca1293e7929e02907482e0383f2`
- **6 pass/0 fail/0 cancelled/0 skipped**, flat/exit0, 44 pre/post pins.
- 합성 authority callback만: 8MiB/256KiB, clean exit 후 다른 PID/resume16/retry/hash, 최소 env sentinel 부재. `not_authorized` 후 `SESSION_DENIED` latch, fieldfault/timeout/abort-aware unresolved callback의 `SESSION_CLOSED`와 exit, mutation `integrity_failed`/`conflicting_retry`.
- 실제 SDK/native lease/registry authority가 아니다. decrypt callback 자체가 없어 crypto zero-plaintext 증명 없음. arbitrary ignoring-AbortSignal callback 취소, 모든 replay/expiry/disconnect 조합도 미검증.
- 독립 read-only review 초기 timeout/latch/env/guardmode 문제 수정 후 PASS. owned worker/private namespace 부재, forced0/containers0. container teardown 증명은 없다.

## 6. 논리적 ciphertext 길이 예산: 별도 helper 6개

- [run38164502992](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38164502992), job `114544128863`.
- source `b959d12841b5bfed389dadc4632622fb7794260e`
- workflow `cee9b9029c0d15fc8483fa041d743d5b6340a504`
- results `752a1059d8865502fff47db4318f252c72961639`
- **6 pass/0 fail/0 cancelled/0 skipped**, flat/exit0, 39 pre/post pins.
- 8MiB source/256KiB chunks, complete source+cache 파일 길이 16MiB 경계, 한 바이트 초과 예상 `LOGICAL_BUDGET_EXCEEDED`, 충돌 retry `conflicting_retry`, 늘어난 cache `INVALID_CIPHERTEXT_LENGTH`, source/cache inventory 보존. 객체 재생성/recompute는 process restart가 아니다.
- receiver/SDK에 미연결. trusted single-owner 순차 application accounting이며 native quota/할당 blocks/동시성/보안 강제/repair/GB/RSS가 아니다. decrypt/release 시험 없음.
- parent가 posthoc signaling authority를 거부하여 ALL signals 제거, 독립 재검토 PASS. always 정리는 read-only fail-closed: alive0/stopped0/children0/containers0/private namespace 부재. unknown/live이면 root 보존, 물리적 삭제 아님.

## 7. pending peak 길이 projection: 별도 read-only helper 6개

- [run38165607526](https://github.com/hgs011809-cmyk/secure-mobile-messenger-mvp/actions/runs/38165607526), job `114547421454`.
- source `0cc2358a9585bb327c92ca35e523432f335d68d2`
- workflow `37c1fd5bfc36ff4a6d4f6d5486d8ced33e47952a`
- results `eb53edb7f33c5049bf2bfff874b25acb16302fc4`
- **6 pass/0 fail/0 cancelled/0 skipped**, flat/exit0, 44 pre/post pins.
- 8MiB/256KiB, half pending131072/full262144의 실제 파일 길이를 한 번씩 계수하고 남은 growth만 projection. 동일 retry 성장0; `LOGICAL_BUDGET_EXCEEDED`, `conflicting_retry`, `INVALID_CIPHERTEXT_LENGTH` 정확한 거부 및 inventory 불변.
- 쓰기/rename/unlink/repair 없는 독립 helper, receiver 미연결, process restart/SDK/security enforcement/native quota 증명 아님.
- independent always read-only cleanup alive0/stopped0/children0/containers0/private namespace 부재, signals 없음. source reviewer는 runtime 재실행하지 않았다.
- workflow 표시 이름이 이전 logical-budget 제목을 상속하지만 실제 `matrix-pending-budget-lab.yml`/jobpending-budget/위 workflow commit이 이 군을 식별한다.

## 실행하지 않은 실제 SDK → 자식 결합 후보

Authority/driver/live CI 후보는 source review만 PASS, **runtime0/newCI0/실제 결합 BLOCKED**. `SDK_CROSS_BINDING_BLOCKED` 및 초기 SDK/native key crossbinding finding 수정은 source 후보 수준이다. generic `SESSION_CLOSED`를 SDK redaction 성공으로 오인할 수 있어 redaction cause UNKNOWN/BLOCKED/not-counted 유지. 부모 plaintext integration, 1500ms deadline 실제 적합성 미검증.

Startup 정적 audit만 pins6/anchors10/order3 확인, runtime registered/executed/pass/fail/cancel/skip 모두0. 독립 source/static review PASS. 정확한 blocker:
- `CHILD_SPAWN_BEFORE_BIRTH_MARKER`
- `BROWSER_BIRTH_IDENTITY_UNAVAILABLE`
- `INDEPENDENT_CONTAINMENT_NOT_ESTABLISHED`

fork 이후 self marker, Playwright RAM context/posthoc profile scan은 persisted birth ownership/descendant containment가 아니다. cosmetic marker/unsafe signal/cleanup 약화로 우회하지 않았다. 기존 live CI planning expected1/executed0/skip1은 **계획 숫자**, 실행된 skipped test가 아니다. startup backup `72d37b5a2945f05cb0fbf4bf3da94409977a35f8`.

## 유지된 실패·한계와 종료

Windows nested spawn 보조 검사 hang/terminated, 직접 loader/require/구문 EPERM, PowerShell quoting 진단, 이전 stock restart/cleanup/timeout 및 screenshot 실패를 성공으로 덮지 않는다. generator/main-context unlinked syntax는 runtime pass가 아니다. CI action Node20 deprecation/forcedNode24 경고는 Node22 시험과 분리, 운영 upgrade 없음. source-only 독립 검토를 외부 보안감사나 독립 runtime 재실행으로 부르지 않는다.

실제 MXC는 ingress 때문에 계속 BLOCKED. Android/Internet/실사용자/실기기/humanOOB, GB/RSS/운영 용량, 원자적 권한 철회, cold recipient 재인증+8MiB 결합, whole-app/runner 상실, 영속 키 복구, powerloss 내구성, filesystem repair/backup/물리적 삭제는 증명하지 않았다. 합성/mock 군과 실제 SDK 기준선을 합쳐 이 주장을 만들지 않는다.

**다음 04:15 예정 실행은 기존 CI 완료·cleanup·독립 검토·브랜치 백업·체크포인트/최종 보고만. 새 단계 시작·자동 체인·13회 일정 연장 없음.** 이번 문서 단계의 실행 코드 구현·CI·런타임 신규 수는0이며 실제 종료/원격 backup 확인은 부모 checkpoint가 기록한다.

## 읽은 근거

- `TASK_STATE.json`, `AUTONOMOUS_WORK.json`, `RESUME.md`
- `matrix-client/TRANSPORT_RESULTS.md`, `matrix-client/sdk-process-RESULTS.md`, `matrix-client/SDK_PROCESS_STARTUP_OWNERSHIP.md`
- `media-transfer-lab/PROCESS_RESTART_RESULTS.md`, `PROCESS_WRITE_FAULT_RESULTS.md`, `PERSISTED_CORRUPTION_RESULTS.md`, `LOGICAL_BUDGET_RESULTS.md`, `PENDING_BUDGET_RESULTS.md`

pending 결과 문서의 초기 source-only/runtime0/pending 문구는 뒤의 Inspected Linux runtime proof와 checkpoint가 갱신한 이전 상태다. 여기서는 뒤의 Linux6/6 증거를 사용한다. 과거 SDK 집계의 별도 cancel/skip 미기재는 명시적으로 미기재로 남긴다.

## 이 색인의 독립 검토
작성 `114hsrEKu8A8hwn1`, 읽기 전용 검토 `IFMlLiJs99deyYVh`: PASS (문서 근거만, runtime 독립 재실행 아님). 인용 run/job/commit ID 불일치0, 933개 기존 파일 SHA256 변경0/누락0. 문서·체크포인트만 백업하며 새 workflow/CI/시험 실행 없음.
