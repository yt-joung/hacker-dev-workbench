# 버그 리포트: WebSquare 호환성 및 런타임 안정성 해결

**날짜**: 2026-04-27
**대상 사이트**: `https://pension.comwel.or.kr/` (WebSquare v5.0 기반)
**상태**: 해결 완료

## 1. 이슈: SES (Secure EcmaScript)에 의한 Intrinsics 제거
### 현상
- 콘솔 로그: `SES Removing unpermitted intrinsics`
- 확장 프로그램이 주입한 후킹 로직이 제거되거나, 초기화 중 보안 오류 발생.
### 원인
WebSquare는 환경 오염을 방지하기 위해 `Object`, `Array` 등 기본 객체의 속성을 동결하거나 비표준 속성을 제거하는 Lockdown 메커니즘을 사용합니다.
### 해결 방안
- `manifest.json`에서 주입 시점을 `document_start`로 변경하여 보안 스크립트보다 먼저 실행되도록 설정.
- `Object.defineProperty`, `Object.freeze`, `Object.getOwnPropertyDescriptor` 등을 후킹하여 보안 로직의 접근을 가로채고 우회하는 Stealth 모드 구현.

## 2. 이슈: ReferenceError (obfuscator_msg is not defined)
### 현상
- 콘솔 오류: `ReferenceError: obfuscator_msg is not defined at eval`
- 페이지가 흰 화면으로 남고 WebSquare 엔진이 부팅되지 않음.
### 원인
플러그인의 `window.eval` 후킹으로 인해 모든 `eval()` 호출이 **Indirect Eval**로 변경되었습니다. Indirect Eval은 전역 스코프에서 실행되므로 로컬 변수에 접근할 수 없습니다. WebSquare는 내부 난독화 해제 로직에서 로컬 스코프에 의존적인 `eval`을 사용하므로 오류가 발생했습니다.
### 해결 방안
- WebSquare와 같이 스코프에 민감한 환경을 위해 전역 `eval` 후킹을 비활성화하여 호환성 유지.

## 3. 이슈: TypeError (null의 'innerHTML' 속성을 설정할 수 없음)
### 현상
- 콘솔 오류: `TypeError: Cannot set properties of null (setting 'innerHTML') at scwin.notiCallList`
### 원인
이는 이슈 #2에 의한 2차 오류입니다. 엔진 초기화 스크립트가 실패하면서 UI 요소들이 정상적으로 렌더링되지 않았고, 이후 애플리케이션이 존재하지 않는 요소(`notiTITLE` 등)에 접근하려다 발생했습니다.
### 해결 방안
- `eval` 스코프 이슈(이슈 #2)를 해결함으로써 엔진 초기화 시퀀스가 복구되었고, 이에 따라 Null 참조 오류도 자동으로 해결됨.

## 4. 이슈: 확장 프로그램 컨텍스트 무효화 (Extension Context Invalidated)
### 현상
- 콘솔 오류: `Uncaught Error: Extension context invalidated`
- 확장 프로그램을 업데이트하거나 다시 로드한 후 페이지에서 이벤트 발생 시 발생.
### 원인
페이지에 남아있는 이전 버전의 컨텐트 스크립트 리스너가 재로드된 백그라운드 서비스 워커와 통신을 시도할 때 발생하는 Chrome 확장 프로그램의 보안 제약입니다.
### 해결 방안
- 메시지 전달 전 `chrome.runtime.id`의 존재 여부를 확인하는 로직 추가.
- `try-catch` 블록으로 메시지 전송부를 감싸서 무효화된 컨텍스트에 의한 예외가 사용자 콘솔에 노출되지 않도록 방어 코드 작성.

## 5. 최적화: 로그 발생 빈도 제어 (Log Throttling)
### 현상
- 빈번한 `innerHTML` 변경 및 이벤트 리스너 호출로 인한 과도한 메시지 전송 및 브라우저 성능 저하.
### 해결 방안
- `Set`과 `setTimeout`을 이용한 스로틀링 메커니즘 도입.
- 동일한 로그 내용에 대해 1초당 1회만 전송되도록 제한하여 성능 및 안정성 확보.

---
**HackerDev Workbench 개발 팀**
