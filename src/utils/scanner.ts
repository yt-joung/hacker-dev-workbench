import { VULN_PATTERNS } from '../config/patterns';

export interface ScanResult {
  type: string;
  value: string;
}

/**
 * 주어진 텍스트에서 VULN_PATTERNS에 정의된 시크릿/취약점 요소를 스캔합니다.
 */
export const scanForSecrets = (text: string): ScanResult[] => {
  const matches: ScanResult[] = [];
  VULN_PATTERNS.forEach(pattern => {
    let match;
    pattern.regex.lastIndex = 0; 
    while ((match = pattern.regex.exec(text)) !== null) {
      matches.push({ type: pattern.name, value: match[0] });
    }
  });
  return matches;
};

/**
 * 주어진 네트워크 URL의 리소스를 가져와서 시크릿을 스캔합니다.
 */
export const scanNetworkResource = async (url: string): Promise<ScanResult[] | null> => {
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const text = await response.text();
    return scanForSecrets(text);
  } catch (err) {
    console.warn(`[HackerDev] Failed to scan resource at ${url}:`, err);
    return null;
  }
};

/**
 * 페이지 소스를 다시 fetch하여 유실될 수 있는 주석을 모두 추출합니다.
 */
export const getRawComments = async (url: string): Promise<{content: string, lineNumber: number}[]> => {
  try {
    const raw = await fetch(url).then(r => r.text());
    const regex = /<!--[\s\S]*?-->/g;
    let match;
    const comments = [];
    while ((match = regex.exec(raw)) !== null) {
      const lineNumber = raw.substring(0, match.index).split('\n').length;
      comments.push({ content: match[0], lineNumber: lineNumber });
    }
    return comments;
  } catch (e) {
    console.error("[HackerDev] getRawComments failed:", e);
    return [];
  }
};

export interface FormInfo {
  action: string;
  method: string;
  inputs: { name: string, type: string, value: string }[];
  issues: string[];
}

/**
 * 페이지 내 폼 엘리먼트들을 분석하여 보안 이슈를 도출합니다.
 */
export const analyzeForms = (doc: Document = document): FormInfo[] => {
  return Array.from(doc.querySelectorAll('form')).map((f: any) => {
    const inputs = Array.from(f.querySelectorAll('input, textarea, select')) as any[];
    const inputData = inputs.map(i => ({
      name: i.name || i.id || 'unnamed',
      type: i.type || i.tagName.toLowerCase(),
      value: i.value
    }));

    const issues: string[] = [];
    if (f.method.toUpperCase() === 'GET') issues.push('GET method used');
    if (!f.querySelector('input[type="hidden"][name*="csrf"], input[type="hidden"][name*="token"]')) {
      issues.push('No CSRF token found');
    }
    if (f.querySelector('input[type="file"]')) issues.push('File upload present');

    return {
      action: f.action,
      method: f.method,
      inputs: inputData,
      issues: issues
    };
  });
};

/**
 * 폼 데이터를 HTTP Raw Request 포맷으로 변환합니다.
 */
export const formToRawRequest = (form: FormInfo, host: string): string => {
  let raw = `${form.method.toUpperCase()} ${form.action} HTTP/1.1\nHost: ${host}\n`;
  raw += "User-Agent: HackerDev-Workbench/1.0\nContent-Type: application/x-www-form-urlencoded\n\n";
  const body = form.inputs
    .filter(i => i.name)
    .map(i => `${encodeURIComponent(i.name)}=${encodeURIComponent(i.value || 'test')}`)
    .join('&');
  raw += body;
  return raw;
};
