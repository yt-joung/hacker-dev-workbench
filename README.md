# 🛠️ HackerDev Workbench (Advanced)

**HackerDev Workbench**는 전문 웹 취약점 진단원을 위해 설계된 고성능 크롬 확장 프로그램입니다. 기존의 단순한 정찰 도구를 넘어, HTTP 요청 조작, JWT 분석, 프레임워크 상태 추출 및 JS 소스 정밀 스캔 기능을 통합한 종합 펜테스팅 플랫폼입니다.

## 🌟 개편된 주요 기능 (Enhanced Features)

본 프로젝트는 더욱 정교한 진단 시나리오를 지원하기 위해 **2단계(2nd-Tier) 네비게이션** 구조로 개편되었습니다:

### ⚡ **SCAN (정적 분석 및 정찰)**
- **Recon & Forms**: DOM 구조 분석 및 폼 취약점 자동 탐색.
- **JS Viewer**: JS 소스 포맷팅 및 민감 키워드(API Key, Secret 등) 20여종 자동 스캔.
- **Framework Inspect**: Vue(Pinia/Vuex), React의 메모리 상태 데이터 즉시 탈취.

### 🌐 **NET (트래픽 분석)**
- **Network Log**: 실시간 통신 기록 캡처 및 분석 연동.
- **Request Repeater**: 페이지 컨텍스트 기반의 HTTP 요청 재전송 (CORS 우회 및 세션 유지).
- **JWT Inspector**: JWT 디코딩 및 공격 페이로드(`alg:none`, `exp` 변조 등) 자동 생성.

### ⚔️ **ATTACK (동적 공격 도구)**
- **Workbench**: 실시간 자바스크립트 인젝션 및 실행 결과 콘솔 피드백.
- **Storage Editor**: Cookie, Local/Session Storage 값의 실시간 강제 변조.
- **Live Event Hook**: `postMessage`, `eval` 등 런타임 이벤트 추적.

### 🛡️ **REPORT (자산 및 결과 관리)**
- **Vuln Findings**: 식별된 취약점의 증거(Evidence)와 조치 권고 사항 자동 문서화.
- **Library Manager**: 커스텀 페이로드 구축 및 JSON 파일 Import/Export 지원.

---

## 📖 상세 사용 방법
각 기능의 상세한 활용법과 진단 시나리오는 [USAGE.md](file:///d:/0x02-work/01_Security_Pentest/0x02-Pentest/0x02-chrome_extensions/hacker-dev-workbench/USAGE.md) 파일을 참조하십시오.

## 🚀 시작하기 (Getting Started)

1. 필요한 패키지 설치: `npm install`
2. 프로젝트 빌드: `npm run build`
3. 크롬 브라우저의 `chrome://extensions/`로 이동합니다.
4. **'개발자 모드'**를 활성화합니다.
5. **'압축해제된 확장 프로그램을 로드합니다(Load unpacked)'** 버튼을 클릭한 뒤, 프로젝트 폴더 내의 `dist` 디렉토리를 선택합니다.

---

## ⚠️ 면책 조항 (Disclaimer)
본 도구는 교육 및 화이트햇 해킹 자가 진단 목적으로 제작되었습니다. 허가받지 않은 시스템에 대한 공격은 불법이며, 모든 행위에 대한 책임은 사용자 본인에게 있습니다.

---
**Author**: Antigravity AI  
**Version**: 2.0.0 (Advanced Edition)
