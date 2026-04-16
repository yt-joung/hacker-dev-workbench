/**
 * 취약점 정의 데이터베이스
 * 각 취약점 유형에 대한 한글 설명, 심각도, 위협 개요, 조치 방법을 포함합니다.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface VulnDefinition {
  id: string;
  title: string;               // 취약점 이름 (한글)
  category: string;            // 취약점 분류
  severity: Severity;
  description: string;         // 취약점 설명 (한글)
  threat: string;              // 발생 가능한 보안 위협 (한글)
  recommendation: string;      // 조치 권고사항 (한글)
  owasp?: string;              // OWASP TOP 10 매핑
  cwe?: string;                // CWE 번호
}

export const VULN_DB: Record<string, VulnDefinition> = {

  // ─────────────── postMessage ───────────────
  postmessage_no_origin_check: {
    id: 'postmessage_no_origin_check',
    title: 'postMessage 출처(origin) 검증 미흡',
    category: 'postMessage / 메시지 통신 보안',
    severity: 'high',
    description:
      '페이지가 `window.addEventListener("message", ...)` 를 통해 메시지를 수신하고 있으나, ' +
      '수신 핸들러 내부에서 `event.origin` 값을 검증하지 않거나 와일드카드(*) 포함 불충분한 검증을 수행합니다. ' +
      '모든 출처로부터의 메시지를 무조건 신뢰하여 처리합니다.',
    threat:
      '공격자가 악성 사이트에서 피해 사이트로 위조 메시지를 전송하여 인증 우회, 데이터 탈취, ' +
      '또는 임의 함수 실행(DOM 기반 XSS)을 유발할 수 있습니다.',
    recommendation:
      '핸들러 내 첫 줄에서 `if (event.origin !== "https://신뢰하는도메인") return;` 검증을 추가하십시오. ' +
      '`postMessage` 전송 시에도 타겟 origin을 와일드카드(*) 대신 구체적인 값으로 지정하십시오.',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    cwe: 'CWE-346',
  },
  postmessage_data_injection: {
    id: 'postmessage_data_injection',
    title: 'postMessage 데이터 검증 없이 DOM 조작',
    category: 'postMessage / 메시지 통신 보안',
    severity: 'critical',
    description:
      '수신된 `event.data` 값을 `innerHTML`, `eval()`, `document.write()` 등 위험한 함수에 직접 삽입합니다. ' +
      '데이터에 대한 입력값 검증(sanitization)이 전혀 이루어지지 않습니다.',
    threat:
      '공격자가 조작한 HTML/JS 페이로드를 메시지로 주입하여 피해 사이트의 컨텍스트에서 ' +
      '임의 스크립트를 실행할 수 있습니다. (DOM 기반 XSS / 크로스 사이트 스크립팅)',
    recommendation:
      '`event.data` 를 HTML 삽입에 사용 전 반드시 DOMPurify 등의 라이브러리로 새니타이즈(sanitize)하십시오. ' +
      '가능하다면 textContent 를 사용하고 innerHTML 사용을 피하십시오.',
    owasp: 'A03:2021 - Injection',
    cwe: 'CWE-79',
  },

  // ─────────────── Storage ───────────────
  storage_sensitive_data: {
    id: 'storage_sensitive_data',
    title: 'Storage에 민감 정보 평문 저장',
    category: 'Storage 보안',
    severity: 'high',
    description:
      '`localStorage` 또는 `sessionStorage`에 비밀번호, 토큰, 개인정보 등 민감한 데이터가 ' +
      '암호화 없이 평문으로 저장되어 있습니다.',
    threat:
      'XSS 취약점이 존재하는 경우 공격자가 스크립트를 통해 모든 Storage 데이터를 탈취할 수 있습니다. ' +
      '또한 공용 PC나 브라우저 개발자 도구를 통해 직접 조회할 수 있습니다.',
    recommendation:
      '민감 정보는 브라우저 Storage에 저장하지 마십시오. 세션 쿠키(HttpOnly, Secure 속성)를 사용하고, ' +
      '저장이 불가피한 경우 암호화 후 저장하십시오.',
    owasp: 'A02:2021 - Cryptographic Failures',
    cwe: 'CWE-312',
  },
  cookie_missing_flags: {
    id: 'cookie_missing_flags',
    title: '쿠키 보안 속성 미설정',
    category: 'Storage 보안 / 쿠키',
    severity: 'high',
    description:
      '발견된 쿠키(Cookie)에서 보안 필수 속성인 `HttpOnly`, `Secure`, `SameSite` 중 ' +
      '하나 이상이 누락되어 있습니다.',
    threat:
      'HttpOnly 미설정 시 XSS를 통한 쿠키 탈취가 가능합니다. ' +
      'Secure 미설정 시 HTTPS가 아닌 환경에서도 쿠키가 전송됩니다. ' +
      'SameSite 미설정 시 CSRF 공격에 노출됩니다.',
    recommendation:
      '중요 세션 쿠키에 반드시 `HttpOnly; Secure; SameSite=Strict` (또는 Lax) 속성을 설정하십시오.',
    owasp: 'A05:2021 - Security Misconfiguration',
    cwe: 'CWE-614',
  },

  // ─────────────── Redirect ───────────────
  open_redirect: {
    id: 'open_redirect',
    title: '오픈 리다이렉트 (Open Redirect)',
    category: 'URL 리다이렉트 보안',
    severity: 'medium',
    description:
      '`location.href`, `location.assign()`, `location.replace()` 등을 통한 리다이렉트가 탐지되었으며, ' +
      '이동 대상 URL이 외부 파라미터 또는 사용자 입력값에서 직접 유래하고 있습니다.',
    threat:
      '공격자가 피싱 캠페인에 신뢰할 수 있는 도메인의 URL을 악용하여 악성 사이트로 사용자를 유도할 수 있습니다. ' +
      '특히 로그인 후 리다이렉트 파라미터(`?next=`, `?returnUrl=`)에서 자주 발생합니다.',
    recommendation:
      '리다이렉트 대상 URL을 화이트리스트로 검증하십시오. 상대 경로만 허용하거나, ' +
      '파라미터를 그대로 URL로 사용하지 말고 서버 측에서 허용 목록을 통해 매핑하십시오.',
    owasp: 'A01:2021 - Broken Access Control',
    cwe: 'CWE-601',
  },
  location_manipulation: {
    id: 'location_manipulation',
    title: '클라이언트 측 URL/경로 조작 감지',
    category: 'URL 리다이렉트 보안',
    severity: 'medium',
    description:
      '페이지에서 `location` 객체의 속성(`href`, `hash`, `search`, `pathname`)을 ' +
      '동적으로 변경하는 코드가 탐지되었습니다.',
    threat:
      '클라이언트 측에서만 접근 제어가 이루어지는 경우 공격자가 URL을 직접 조작하여 ' +
      '권한이 없는 기능이나 페이지에 접근할 수 있습니다.',
    recommendation:
      '접근 제어 로직은 반드시 서버 측에서 수행하십시오. 클라이언트 측 라우팅 제어는 ' +
      '방어의 보조 수단으로만 활용하십시오.',
    owasp: 'A01:2021 - Broken Access Control',
    cwe: 'CWE-862',
  },

  // ─────────────── DOM XSS Sinks ───────────────
  sink_innerhtml: {
    id: 'sink_innerhtml',
    title: 'XSS 위험 Sink 사용 - innerHTML / outerHTML',
    category: 'DOM 기반 XSS',
    severity: 'critical',
    description:
      '`element.innerHTML` 또는 `element.outerHTML`에 외부 입력값이 직접 삽입되고 있습니다. ' +
      '이 함수들은 HTML을 파싱하여 렌더링하므로 `<script>` 태그나 이벤트 핸들러가 포함된 경우 실행됩니다.',
    threat:
      '공격자가 XSS 페이로드를 주입하여 피해자의 브라우저에서 임의 스크립트를 실행할 수 있습니다. ' +
      '세션 쿠키 탈취, 키로거 삽입, 피싱 폼 삽입 등이 가능합니다.',
    recommendation:
      'innerHTML 대신 `textContent`를 사용하십시오. HTML 삽입이 불가피한 경우 ' +
      'DOMPurify를 사용하여 새니타이즈 후 삽입하십시오. `Trusted Types` 정책 도입을 검토하십시오.',
    owasp: 'A03:2021 - Injection',
    cwe: 'CWE-79',
  },
  sink_eval: {
    id: 'sink_eval',
    title: 'XSS 위험 Sink 사용 - eval()',
    category: 'DOM 기반 XSS',
    severity: 'critical',
    description:
      '`eval()` 함수 호출이 탐지되었습니다. eval은 문자열을 JavaScript 코드로 직접 실행하며 ' +
      '외부 입력값이 포함될 경우 임의코드 실행(RCE in browser context)으로 이어집니다.',
    threat:
      '공격자가 eval로 전달되는 데이터를 제어할 수 있는 경우 완전한 스크립트 실행 권한을 획득합니다.',
    recommendation:
      '`eval()` 사용을 제거하고 `JSON.parse()`, `Function` 생성자 대신 정적 데이터 처리 방식으로 전환하십시오. ' +
      'Content-Security-Policy(CSP) 헤더에 `script-src` 에서 `unsafe-eval` 을 제거하십시오.',
    owasp: 'A03:2021 - Injection',
    cwe: 'CWE-95',
  },
  sink_document_write: {
    id: 'sink_document_write',
    title: 'XSS 위험 Sink 사용 - document.write()',
    category: 'DOM 기반 XSS',
    severity: 'high',
    description:
      '`document.write()` 또는 `document.writeln()` 호출이 탐지되었습니다. ' +
      '이 함수는 외부 데이터를 포함 시 XSS 취약점을 유발하며 현대 웹에서 권장되지 않습니다.',
    threat:
      '외부 입력이 document.write에 전달되면 공격자 제어 하의 HTML/스크립트가 렌더링됩니다.',
    recommendation:
      '`document.write()` 대신 `createElement`, `appendChild`, `insertAdjacentHTML`(검증 후)을 사용하십시오.',
    owasp: 'A03:2021 - Injection',
    cwe: 'CWE-79',
  },
  sink_settimeout_string: {
    id: 'sink_settimeout_string',
    title: 'XSS 위험 Sink 사용 - setTimeout/setInterval (문자열 인자)',
    category: 'DOM 기반 XSS',
    severity: 'high',
    description:
      '`setTimeout()` 또는 `setInterval()`이 문자열 인자로 호출되고 있습니다. ' +
      '이 패턴은 eval()과 동일하게 문자열을 JS 코드로 실행합니다.',
    threat:
      '외부 데이터가 문자열로 전달되면 임의 코드 실행이 일어납니다.',
    recommendation:
      'setTimeout/setInterval 의 첫 번째 인자로 함수 레퍼런스를 전달하십시오. 문자열 전달 패턴을 제거하십시오.',
    owasp: 'A03:2021 - Injection',
    cwe: 'CWE-79',
  },

  // ─────────────── Secrets ───────────────
  exposed_api_key: {
    id: 'exposed_api_key',
    title: 'API 키 / 시크릿 클라이언트 측 노출',
    category: '민감 정보 노출 (Secret Exposure)',
    severity: 'critical',
    description:
      '페이지에서 로드된 JavaScript 파일 내에 API 키, Access Token, Secret Key 등의 ' +
      '민감한 자격증명(Credential) 문자열이 평문으로 포함되어 있습니다.',
    threat:
      '누구나 브라우저 개발자 도구로 해당 키를 조회하여 무단으로 API를 호출하거나 ' +
      '연관된 클라우드 서비스를 악용할 수 있습니다. 금전적 피해 및 데이터 침해로 이어질 수 있습니다.',
    recommendation:
      '클라이언트 측 코드에 API 키를 절대 포함하지 마십시오. 서버 측 프록시를 통해 API를 호출하고 ' +
      '노출된 키는 즉시 폐기(revoke) 후 재발급하십시오. 환경변수(.env)를 서버에서만 사용하십시오.',
    owasp: 'A02:2021 - Cryptographic Failures',
    cwe: 'CWE-798',
  },

  // ─────────────── Forms ───────────────
  form_no_csrf: {
    id: 'form_no_csrf',
    title: 'CSRF 토큰 없는 폼 (CSRF 취약점)',
    category: '폼 보안 / CSRF',
    severity: 'high',
    description:
      'HTML 폼에서 CSRF(Cross-Site Request Forgery) 방어 토큰이 발견되지 않았습니다. ' +
      '서버가 동일 출처 여부를 검증하지 않는 경우 취약합니다.',
    threat:
      '공격자의 악성 사이트를 방문한 피해자가 의도치 않게 인증된 상태로 위조 요청을 전송하게 됩니다. ' +
      '계정 정보 변경, 비밀번호 변경, 결제 등의 주요 기능이 공격 대상이 됩니다.',
    recommendation:
      '서버 측에서 Synchronizer Token Pattern(CSRF 토큰)을 구현하거나 ' +
      '`SameSite=Strict` 쿠키를 사용하십시오. 중요 기능에는 추가 인증(재인증, CAPTCHA)을 요구하십시오.',
    owasp: 'A01:2021 - Broken Access Control',
    cwe: 'CWE-352',
  },
  form_get_method: {
    id: 'form_get_method',
    title: '민감 데이터를 GET 방식으로 전송하는 폼',
    category: '폼 보안',
    severity: 'medium',
    description:
      '폼이 `method="GET"` 으로 설정되어 있어 폼의 입력 데이터가 URL 쿼리스트링으로 전송됩니다. ' +
      '비밀번호, 개인정보 등 민감한 필드가 포함된 경우 심각한 문제가 됩니다.',
    threat:
      '폼 데이터가 브라우저 히스토리, 서버 접근 로그, Referer 헤더, 프록시 로그에 기록되어 ' +
      '민감한 정보가 의도치 않게 노출될 수 있습니다.',
    recommendation:
      '민감한 데이터를 다루는 폼은 반드시 `method="POST"` 로 변경하십시오.',
    owasp: 'A02:2021 - Cryptographic Failures',
    cwe: 'CWE-598',
  },
  form_file_upload: {
    id: 'form_file_upload',
    title: '파일 업로드 기능 존재 (점검 필요)',
    category: '폼 보안 / 파일 업로드',
    severity: 'medium',
    description:
      '파일 업로드 `<input type="file">` 이 포함된 폼이 탐지되었습니다. ' +
      '서버 측에서 파일 타입, 크기, 내용 검증을 수행하지 않을 경우 취약합니다.',
    threat:
      '웹 쉘(Web Shell), 악성 스크립트 업로드를 통한 서버 측 코드 실행(RCE)이 가능합니다. ' +
      '또한 서비스 거부(DoS) 공격의 벡터로 활용될 수 있습니다.',
    recommendation:
      '서버 측에서 MIME 타입, 확장자, 파일 매직 바이트를 검증하십시오. ' +
      '업로드 파일을 웹 루트 외부에 저장하고, 파일명을 랜덤화하십시오. 최대 파일 크기제한을 적용하십시오.',
    owasp: 'A04:2021 - Insecure Design',
    cwe: 'CWE-434',
  },

  // ─────────────── Hidden Elements ───────────────
  hidden_input_found: {
    id: 'hidden_input_found',
    title: '숨겨진 입력 필드 (클라이언트 측 데이터 조작 위험)',
    category: '입력값 검증 / 클라이언트 측 신뢰',
    severity: 'medium',
    description:
      '`<input type="hidden">` 필드가 탐지되었습니다. 이 값들은 사용자에게는 보이지 않지만 ' +
      '브라우저 개발자 도구나 프록시 도구를 통해 쉽게 조회하고 변조할 수 있습니다.',
    threat:
      '서버가 hidden input 값을 검증 없이 신뢰할 경우, 공격자가 가격 조작, 권한 상승, ' +
      '상태 변조 등의 공격을 수행할 수 있습니다. (파라미터 변조 / Mass Assignment)',
    recommendation:
      '중요한 비즈니스 로직 값(가격, 권한, 사용자 ID 등)은 hidden field로 전달하지 마십시오. ' +
      '서버 측 세션이나 서버가 관리하는 상태값을 사용하십시오.',
    owasp: 'A01:2021 - Broken Access Control',
    cwe: 'CWE-472',
  },
};

export const getSeverityColor = (severity: Severity): string => {
  const map: Record<Severity, string> = {
    critical: '#ff0033',
    high:     '#ff6600',
    medium:   '#ffbb00',
    low:      '#00aaff',
    info:     '#8b949e',
  };
  return map[severity];
};

export const getSeverityLabel = (severity: Severity): string => {
  const map: Record<Severity, string> = {
    critical: '치명적',
    high:     '높음',
    medium:   '중간',
    low:      '낮음',
    info:     '정보',
  };
  return map[severity];
};
