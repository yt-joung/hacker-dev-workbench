export interface Snippet {
  id: string;
  title: string;
  chapter: string;
  code: string;
}

export const DEFAULT_SNIPPETS: Snippet[] = [
  { 
    id: 'unlock', 
    title: '전체 잠금 해제 (Unlock)', 
    chapter: 'Ch 3',
    code: `// 모든 비활성화된 입력창과 버튼을 활성화\ndocument.querySelectorAll('[disabled], [readonly]').forEach(el => {\n  el.removeAttribute('disabled');\n  el.removeAttribute('readonly');\n  el.style.border = '2px solid #00ff9d';\n});\nconsole.log('Unlock completed.');` 
  },
  { 
    id: 'fetch_hook', 
    title: 'Fetch 통신 가로채기', 
    chapter: 'Ch 4',
    code: `// Fetch 요청과 응답을 콘솔에 기록\nconst originalFetch = window.fetch;\nwindow.fetch = async (...args) => {\n  console.log('🚀 API Request:', args[0]);\n  const response = await originalFetch(...args);\n  const cloned = response.clone();\n  cloned.json().then(data => console.log('📦 API Response:', data)).catch(() => {});\n  return response;\n};\nconsole.log('Fetch hook active.');` 
  },
  { 
    id: 'admin_bypass', 
    title: '관리자 권한 강제 주입', 
    chapter: 'Ch 4',
    code: `// isAdmin 변수를 항상 true로 반환하도록 조작\nObject.defineProperty(window, 'isAdmin', { get: () => true });\nconsole.log('isAdmin set to TRUE');` 
  },
  { 
    id: 'design_mode', 
    title: '디자인 모드 활성화', 
    chapter: 'Ch 4',
    code: `// 페이지의 모든 텍스트를 수정 가능하게 변경\ndocument.designMode = 'on';\nconsole.log('Design mode is ON');` 
  }
];
