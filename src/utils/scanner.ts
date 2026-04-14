import { VULN_PATTERNS } from '../config/patterns';

export interface ScanResult {
  type: string;
  value: string;
}

/**
 * 주어진 텍스트에서 VULN_PATTERNS에 정의된 시크릿/취약점 요소를 스캔합니다.
 * @param text 스캔할 원본 문자열 (JS/TS 소스코드, HTML 등)
 * @returns 찾은 시크릿 배열
 */
export const scanForSecrets = (text: string): ScanResult[] => {
  const matches: ScanResult[] = [];
  
  VULN_PATTERNS.forEach(pattern => {
    let match;
    // 상태를 가지는 정규식(global)이므로 lastIndex를 0으로 초기화 필요할 수 있음
    pattern.regex.lastIndex = 0; 
    
    while ((match = pattern.regex.exec(text)) !== null) {
      matches.push({ type: pattern.name, value: match[0] });
    }
  });

  return matches;
};

/**
 * 주어진 네트워크 URL의 리소스를 가져와서 시크릿을 스캔합니다.
 * @param url 스캔할 타겟 리소스 URL
 * @returns 에러 발생 시 null, 성공 시 결과 배열 반환
 */
export const scanNetworkResource = async (url: string): Promise<ScanResult[] | null> => {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const text = await response.text();
    return scanForSecrets(text);
  } catch (err) {
    console.warn(`[HackerDev] Failed to scan resource at ${url}:`, err);
    return null;
  }
};
