# 🛠️ HackerDev Workbench

**Chrome DevTools for Hackers** 시리즈를 기반으로 제작된 웹 취약점 진단 및 리버싱 보조용 크롬 확장 프로그램입니다. 해커의 관점에서 웹 페이지를 정찰하고, 페이로드를 직접 수정하여 반복적으로 테스트할 수 있는 '반자동 작업대' 환경을 제공합니다.

## 🌟 주요 기능 (Key Features)

### 1. **Recon (정찰)**
- **시각적 가시화 (Visual Toggle)**: 페이지 내 숨겨진 요소(`type="hidden"`, `display:none` 등)를 강제로 노출시키며 시각적 테두리를 표시합니다.
- **상세 타켓 리스트**: Hidden Input, Disabled/Readonly 요소들을 자동으로 추출하여 목록화합니다.
- **원클릭 연동**: 목록에서 특정 요소를 클릭하면 해당 요소를 조작하는 코드가 작업대 에디터로 즉시 전송됩니다.

### 2. **Workbench (작업대)**
- **Live Script Editor**: 현재 탭의 컨텍스트에서 실행될 커스텀 자바스크립트 페이로드를 작성 및 수정할 수 있습니다.
- **Injection Engine**: 'Run Payload' 버튼을 통해 실시간으로 코드를 주입하고 실행 결과를 확인합니다.
- **Interactive Console**: 주입된 코드의 반환값과 에러를 전용 로그창에서 즉시 피드백 받으며 반복 작업할 수 있습니다.

### 3. **Library (페이로드 연구소)**
- **문서 기반 템플릿**: Ch 1~9 가이드 문서에서 다루는 핵심 페이로드(Unlocker, Fetch Hook, Admin Bypass 등)를 기본 제공합니다.
- **반복적 연구**: 템플릿을 불러와 현재 목표 사이트에 맞게 최적화하여 테스트할 수 있습니다.

## 🚀 시작하기 (Getting Started)

### 설치 방법 (Installation)
1. 이 저장소를 클론하거나 다운로드합니다.
2. 필요한 패키지를 설치합니다:
   ```bash
   npm install
   ```
3. 프로젝트를 빌드합니다:
   ```bash
   npm run build
   ```
4. 크롬 브라우저에서 `chrome://extensions/`로 이동합니다.
5. **'개발자 모드'**를 활성화합니다.
6. **'압축해제된 확장 프로그램을 로드합니다(Load unpacked)'** 버튼을 클릭한 뒤, 프로젝트 폴더 내의 `dist` 디렉토리를 선택합니다.

### 개발 모드 (Development)
```bash
npm run dev
```

## 🧠 해커의 마인드셋 (Hacker's Mindset)
> "클라이언트에 전달된 모든 코드는 공격자의 손안에 있다."

본 도구는 다음의 대원칙을 실천하기 위해 설계되었습니다:
- **개발자**는 코드를 고치는 법을 고민하지만, **해커**는 코드가 나를 어떻게 막고 있는지, 그 벽을 어떻게 부술지 고민합니다.
- UI가 막아둔 벽(Disabled, Hidden 등)을 넘어 메모리상의 변수와 함수를 직접 호출하세요.

## ⚠️ 면책 조항 (Disclaimer)
본 도구는 교육 및 화이트햇 해킹 자가 진단 목적으로 제작되었습니다. 허가받지 않은 시스템에 대한 공격은 불법이며, 모든 행위에 대한 책임은 사용자 본인에게 있습니다.

---
**Author**: Antigravity AI
**Source**: Chrome DevTools for Hackers (Chapter 1-9)
