/**
 * JS 소스 분석 유틸리티
 * - 난독화된 JS 코드 기본 포맷팅 (Beautify)
 * - 민감 키워드 탐색 및 하이라이팅
 */

/** 보안 진단 시 주목할 민감 키워드 목록 */
export const SENSITIVE_JS_KEYWORDS: { keyword: string; reason: string; severity: 'critical' | 'high' | 'medium' | 'low' }[] = [
  { keyword: 'token',         reason: '토큰 처리 로직',             severity: 'high' },
  { keyword: 'refresh',       reason: '토큰 갱신 함수',             severity: 'high' },
  { keyword: 'access_token',  reason: 'Access Token 직접 참조',    severity: 'critical' },
  { keyword: 'authorization', reason: 'Authorization 헤더 설정',   severity: 'high' },
  { keyword: 'Bearer',        reason: 'Bearer 토큰 전송',          severity: 'high' },
  { keyword: 'password',      reason: '비밀번호 처리 로직',         severity: 'critical' },
  { keyword: 'secret',        reason: '시크릿 키 참조',            severity: 'critical' },
  { keyword: 'api_key',       reason: 'API 키 하드코딩 가능성',    severity: 'critical' },
  { keyword: 'apiKey',        reason: 'API 키 하드코딩 가능성',    severity: 'critical' },
  { keyword: 'localStorage',  reason: 'localStorage 저장/조회',   severity: 'medium' },
  { keyword: 'sessionStorage', reason: 'sessionStorage 저장/조회', severity: 'medium' },
  { keyword: 'eval(',         reason: 'eval 호출 (XSS 위험)',      severity: 'critical' },
  { keyword: 'innerHTML',     reason: 'innerHTML 조작 (XSS 위험)', severity: 'critical' },
  { keyword: 'document.write', reason: 'document.write (XSS 위험)', severity: 'high' },
  { keyword: 'postMessage',   reason: 'postMessage 통신',         severity: 'medium' },
  { keyword: 'isAdmin',       reason: '관리자 권한 변수',          severity: 'high' },
  { keyword: 'role',          reason: '역할/권한 변수',           severity: 'medium' },
  { keyword: 'admin',         reason: '관리자 관련 로직',         severity: 'medium' },
  { keyword: 'bypass',        reason: '우회 로직 가능성',         severity: 'high' },
  { keyword: 'debug',         reason: '디버그 코드 잔류',         severity: 'low' },
  { keyword: 'console.log',   reason: '콘솔 로그 (정보 노출)',    severity: 'low' },
  { keyword: 'http://',       reason: 'HTTP(비암호화) 엔드포인트', severity: 'medium' },
  { keyword: '.env',          reason: '환경변수 파일 참조',       severity: 'high' },
];

export interface CodeSearchResult {
  lineNumber: number;
  lineContent: string;
  matchedKeyword: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  reason: string;
}


/** JS 소스에서 민감 키워드 위치 검색 */
export const searchSensitiveKeywords = (code: string): CodeSearchResult[] => {
  const lines = code.split('\n');
  const results: CodeSearchResult[] = [];

  lines.forEach((line, idx) => {
    const lowerLine = line.toLowerCase();
    SENSITIVE_JS_KEYWORDS.forEach(({ keyword, reason, severity }) => {
      if (lowerLine.includes(keyword.toLowerCase())) {
        results.push({
          lineNumber: idx + 1,
          lineContent: line.trim().substring(0, 200),
          matchedKeyword: keyword,
          severity,
          reason,
        });
      }
    });
  });

  return results;
};

/** 특정 키워드로 코드 검색 */
export const searchInCode = (
  code: string,
  query: string,
  caseSensitive = false
): { lineNumber: number; lineContent: string }[] => {
  if (!query.trim()) return [];
  const lines = code.split('\n');
  const q = caseSensitive ? query : query.toLowerCase();
  return lines
    .map((line, idx) => ({ lineNumber: idx + 1, lineContent: line }))
    .filter(({ lineContent }) =>
      (caseSensitive ? lineContent : lineContent.toLowerCase()).includes(q)
    )
    .slice(0, 200);
};

/**
 * JS 기본 Beautifier
 * 세미콜론, 중괄호 기준으로 줄바꿈 + 인덴트 적용
 * (jsbeautify 대안 - 추가 의존성 없음)
 */
export const beautifyJs = (code: string): string => {
  try {
    const TAB = '  ';
    let indent = 0;
    const output: string[] = [];

    // 기본 줄바꿈 삽입
    const normalized = code
      .replace(/;\s*/g, ';\n')
      .replace(/\{\s*/g, ' {\n')
      .replace(/\}\s*/g, '\n}\n')
      .replace(/,(?!\n)/g, ', ')
      .replace(/\n{3,}/g, '\n\n');

    const lines = normalized.split('\n');

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) { output.push(''); continue; }

      const closings = (line.match(/}/g) || []).length;
      const openings = (line.match(/{/g) || []).length;

      if (line.startsWith('}')) indent = Math.max(0, indent - 1);
      output.push(TAB.repeat(Math.max(0, indent)) + line);
      indent = Math.max(0, indent + openings - closings);
      if (line.startsWith('}') && openings <= 0) { /* already handled */ }
    }

    return output.join('\n');
  } catch {
    return code;
  }
};

/** 코드에서 특정 라인 주변 컨텍스트 추출 */
export const getLineContext = (
  code: string,
  lineNumber: number,
  contextLines = 3
): string => {
  const lines = code.split('\n');
  const start = Math.max(0, lineNumber - 1 - contextLines);
  const end = Math.min(lines.length, lineNumber + contextLines);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1}${start + i + 1 === lineNumber ? ' ▶' : '  '} ${l}`)
    .join('\n');
};
