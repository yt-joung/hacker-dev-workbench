import { useState, useEffect, useCallback } from 'react';
import { Shield, Play, Trash2, Eye, EyeOff, RefreshCw, Trash, Save, RotateCcw, Code2, Plus, Download, Upload, Edit } from 'lucide-react';
import { DEFAULT_SNIPPETS, type Snippet } from './config/payloads';
import { VULN_DB, getSeverityColor, getSeverityLabel, type VulnDefinition } from './config/vulnInfo';
import { scanNetworkResource, type ScanResult, type FormInfo, formToRawRequest } from './utils/scanner';
import { db, type ScanResultData } from './utils/db';
import { RepeaterPanel, JwtPanel, JsViewerPanel, FrameworkPanel } from './components/AdvancedPanels';

/** 발견된 취약점 인스턴스 */
interface VulnFinding {
  id: string;                 // 고유 인스턴스 ID
  vulnId: string;             // VULN_DB key
  location: string;           // 발견 위치 (URL, element, storage key 등)
  evidence: string;           // 증거 데이터 (캡처된 값)
  detail?: string;            // 부가 설명
  timeStamp: number;
}

type TabId = 'recon' | 'network' | 'live' | 'forms' | 'history' | 'workbench' | 'library' | 'storage' | 'vulns' | 'repeat' | 'jwt' | 'jsview' | 'inspect';
type MainTab = 'scan' | 'net' | 'attack' | 'report';

function App() {
  const [activeMainTab, setActiveMainTab] = useState<MainTab>('scan');
  const [activeSubTab, setActiveSubTab] = useState<Record<MainTab, TabId>>({
    scan: 'recon',
    net: 'network',
    attack: 'workbench',
    report: 'vulns'
  });

  const activeTab = activeSubTab[activeMainTab];

  const setActiveTab = (tabId: TabId) => {
    let main: MainTab = 'scan';
    if (['recon', 'forms', 'jsview', 'inspect'].includes(tabId)) main = 'scan';
    else if (['network', 'repeat', 'jwt'].includes(tabId)) main = 'net';
    else if (['workbench', 'storage', 'live'].includes(tabId)) main = 'attack';
    else if (['vulns', 'history', 'library'].includes(tabId)) main = 'report';

    setActiveMainTab(main);
    setActiveSubTab(prev => ({ ...prev, [main]: tabId }));
  };
  const [hiddenElements, setHiddenElements] = useState<any[]>([]);
  const [disabledElements, setDisabledElements] = useState<any[]>([]);
  const [logs, setLogs] = useState<string[]>(['[시스템] HackerDev Workbench 준비 완료.']);
  const [isVisualShown, setIsVisualShown] = useState(false);
  const [payload, setPayload] = useState('');
  const [currentOrigin, setCurrentOrigin] = useState<string>('');

  // Network & Secrets & Events State
  const [networkLogs, setNetworkLogs] = useState<any[]>([]);
  const [runtimeEvents, setRuntimeEvents] = useState<any[]>([]);
  const [foundSecrets, setFoundSecrets] = useState<ScanResult[]>([]);
  const [foundForms, setFoundForms] = useState<FormInfo[]>([]);
  const [history, setHistory] = useState<ScanResultData[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  // 취약점 발견 목록
  const [vulnFindings, setVulnFindings] = useState<VulnFinding[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<VulnFinding | null>(null);

  // 라이브러리 스니펫 상태
  const [snippets, setSnippets] = useState<Snippet[]>([]);
  const [editingSnippet, setEditingSnippet] = useState<Snippet | null>(null);

  // Storage 탭
  const [storageData, setStorageData] = useState<{ cookies: any[], local: [string,string][], session: [string,string][] }>({ cookies: [], local: [], session: [] });
  const [editKey, setEditKey] = useState('');
  const [editVal, setEditVal] = useState('');

  // Encoder
  const [encInput, setEncInput] = useState('');
  const [encOutput, setEncOutput] = useState('');

  const addLog = (msg: string) =>
    setLogs(prev => [...prev.slice(-99), `[${new Date().toLocaleTimeString()}] ${msg}`]);

  /** 취약점 발견 등록 */
  const addVuln = useCallback((vulnId: string, location: string, evidence: string, detail?: string) => {
    if (!VULN_DB[vulnId]) return;
    setVulnFindings(prev => {
      // 동일 vulnId + location 중복 방지
      const exists = prev.find(v => v.vulnId === vulnId && v.location === location);
      if (exists) return prev;
      const finding: VulnFinding = {
        id: `${vulnId}-${Date.now()}`,
        vulnId,
        location,
        evidence: evidence.substring(0, 300),
        detail,
        timeStamp: Date.now(),
      };
      addLog(`🚨 취약점 발견: [${VULN_DB[vulnId].title}] at ${location}`);
      return [finding, ...prev];
    });
  }, []);

  // ─── 실시간 로그 동기화 (Network + Live Events) ───
  useEffect(() => {
    const updateLogs = async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) return;

      let origin = '';
      try {
        origin = new URL(tab.url).origin;
        setCurrentOrigin(origin);
      } catch (e) { return; }

      chrome.storage.local.get(['networkLogs', 'runtimeEvents'], (result) => {
        const storedLogs = (result.networkLogs || {}) as Record<string, any[]>;
        const storedEvents = (result.runtimeEvents || {}) as Record<string, any[]>;
        setNetworkLogs(storedLogs[origin] || []);

        const events: any[] = storedEvents[origin] || [];
        setRuntimeEvents(events);

        // runtime events → 취약점 자동 등록
        events.forEach((ev: any) => {
          if (ev.vulnId && VULN_DB[ev.vulnId]) {
            addVuln(ev.vulnId, ev.location || origin, ev.content || JSON.stringify(ev).substring(0, 200), ev.type);
          }
          // postmessage_listener 처리
          if (ev.type === 'postmessage_listener' && ev.vulnId) {
            addVuln(ev.vulnId, origin, ev.listenerSnippet || '', `message 이벤트 핸들러에 origin 검증 없음`);
          }
        });
      });
    };

    updateLogs();
    const interval = setInterval(updateLogs, 2000);
    return () => clearInterval(interval);
  }, [addVuln]);

  // ─── History 로드 ───
  const loadHistory = async () => {
    if (!currentOrigin) return;
    try {
      const targetId = await db.getOrCreateTarget(currentOrigin);
      const scans = await db.getScansByTarget(targetId);
      setHistory(scans.reverse());
    } catch (e) { console.error(e); }
  };

  // ─── 라이브러리 로드 및 파일 처리 ───
  useEffect(() => {
    chrome.storage.local.get(['customSnippets'], (result) => {
      const customSnippets = result.customSnippets as Snippet[] | undefined;
      if (customSnippets && customSnippets.length > 0) {
        setSnippets(customSnippets);
      } else {
        setSnippets(DEFAULT_SNIPPETS);
      }
    });
  }, []);

  const saveSnippets = (newSnippets: Snippet[]) => {
    setSnippets(newSnippets);
    chrome.storage.local.set({ customSnippets: newSnippets });
  };

  const handleExportSnippets = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(snippets, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `hackerdev_payloads_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    addLog('📂 라이브러리 파일 내보내기 다운로드 완료');
  };

  const handleImportSnippets = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const imported = JSON.parse(event.target?.result as string);
        if (Array.isArray(imported)) {
          saveSnippets(imported);
          addLog(`📂 라이브러리 로드 성공: ${imported.length}개 페이로드 (덮어쓰기 완료)`);
        } else {
          addLog('❌ 올바른 JSON 페이로드 파일이 아닙니다.');
        }
      } catch (err: any) {
        addLog(`❌ JSON 파싱 오류: ${err.message}`);
      }
    };
    reader.readAsText(file);
    e.target.value = ''; 
  };

  const deleteSnippet = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm('정말로 이 페이로드를 삭제하시겠습니까?')) {
      saveSnippets(snippets.filter(s => s.id !== id));
      addLog('🗑️ 페이로드 삭제 완료');
    }
  };

  const handleSaveSnippet = () => {
    if (!editingSnippet) return;
    if (!editingSnippet.title || !editingSnippet.code) {
      alert('제목과 코드를 입력해주세요.');
      return;
    }
    const isNew = !snippets.find(s => s.id === editingSnippet.id);
    let updated;
    if (isNew) {
      updated = [...snippets, editingSnippet];
    } else {
      updated = snippets.map(s => s.id === editingSnippet.id ? editingSnippet : s);
    }
    saveSnippets(updated);
    setEditingSnippet(null);
    addLog(`💾 페이로드 저장 완료: ${editingSnippet.title}`);
  };

  useEffect(() => {
    if (activeTab === 'history') loadHistory();
  }, [activeTab, currentOrigin]);

  // ─── Storage 로드 ───
  const loadStorage = useCallback(async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          const local: [string, string][] = [];
          const session: [string, string][] = [];
          for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i)!;
            local.push([k, localStorage.getItem(k) || '']);
          }
          for (let i = 0; i < sessionStorage.length; i++) {
            const k = sessionStorage.key(i)!;
            session.push([k, sessionStorage.getItem(k) || '']);
          }
          return { local, session };
        }
      });
      const { local, session } = results[0].result as any;

      // Cookies
      const cookies = await chrome.cookies.getAll({ url: tab.url! });

      setStorageData({ cookies, local, session });

      // Storage 보안 분석
      const sensitivePatterns = /token|jwt|password|secret|key|auth|session/i;

      local.forEach(([k, v]: [string, string]) => {
        if (sensitivePatterns.test(k) || sensitivePatterns.test(v)) {
          addVuln('storage_sensitive_data', `localStorage[${k}]`, v.substring(0, 100), 'localStorage에 민감 정보 평문 저장');
        }
      });
      session.forEach(([k, v]: [string, string]) => {
        if (sensitivePatterns.test(k) || sensitivePatterns.test(v)) {
          addVuln('storage_sensitive_data', `sessionStorage[${k}]`, v.substring(0, 100), 'sessionStorage에 민감 정보 평문 저장');
        }
      });

      // Cookie 보안 속성 분석
      cookies.forEach((c: chrome.cookies.Cookie) => {
        const missing = [];
        if (!c.httpOnly) missing.push('HttpOnly');
        if (!c.secure) missing.push('Secure');
        if (!c.sameSite || c.sameSite === 'unspecified') missing.push('SameSite');
        if (missing.length > 0) {
          addVuln('cookie_missing_flags', `Cookie: ${c.name}`, `누락 속성: ${missing.join(', ')}`, `Domain: ${c.domain}`);
        }
      });

      addLog(`Storage 분석 완료: localStorage(${local.length}), sessionStorage(${session.length}), Cookie(${cookies.length})`);
    } catch (e: any) {
      addLog('⚠️ Storage 로드 실패: ' + e.message);
    }
  }, [addVuln]);

  useEffect(() => {
    if (activeTab === 'storage') loadStorage();
  }, [activeTab, loadStorage]);

  // ─── Storage 값 편집 ───
  const editStorage = async (type: 'local' | 'session', key: string, value: string) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: 'MAIN',
      func: (t: string, k: string, v: string) => {
        if (t === 'local') localStorage.setItem(k, v);
        else sessionStorage.setItem(k, v);
      },
      args: [type, key, value]
    });
    addLog(`Storage 수정: [${type}] ${key} = ${value}`);
    loadStorage();
  };

  // ─── Cookie 삭제 ───
  const deleteCookie = async (cookie: chrome.cookies.Cookie) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.cookies.remove({ url: tab.url!, name: cookie.name });
    addLog(`Cookie 삭제: ${cookie.name}`);
    loadStorage();
  };

  const clearSiteData = () => {
    if (!currentOrigin) return;
    chrome.storage.local.get(['networkLogs', 'runtimeEvents'], (result) => {
      const storedLogs = (result.networkLogs || {}) as Record<string, any[]>;
      const storedEvents = (result.runtimeEvents || {}) as Record<string, any[]>;
      delete storedLogs[currentOrigin];
      delete storedEvents[currentOrigin];
      chrome.storage.local.set({ networkLogs: storedLogs, runtimeEvents: storedEvents }, () => {
        setNetworkLogs([]);
        setRuntimeEvents([]);
        setFoundSecrets([]);
        setFoundForms([]);
        addLog(`사이트 데이터 초기화: ${currentOrigin}`);
      });
    });
  };

  // ─── Full Recon ───
  const handleScan = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const response: any = await chrome.tabs.sendMessage(tab.id, { action: 'SCAN_PAGE' });
      if (response) {
        setHiddenElements(response.hiddenInputs || []);
        setDisabledElements(response.disabledElements || []);

        // 폼 분석
        const formResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            return Array.from(document.querySelectorAll('form')).map((f: any) => {
              const inputData = Array.from(f.querySelectorAll('input, textarea, select')).map((i: any) => ({
                name: i.name || i.id || 'unnamed',
                type: i.type || i.tagName.toLowerCase(),
                value: i.value
              }));
              const issues = [];
              if (f.method.toUpperCase() === 'GET') issues.push('GET method used');
              if (!f.querySelector('input[type="hidden"][name*="csrf"], input[type="hidden"][name*="token"]')) issues.push('No CSRF token');
              if (f.querySelector('input[type="file"]')) issues.push('File upload present');
              return { action: f.action, method: f.method, inputs: inputData, issues };
            });
          }
        });
        const forms = formResults[0].result as FormInfo[];
        setFoundForms(forms);

        // 폼 → 취약점 등록
        forms.forEach((f, i) => {
          if (f.issues.includes('GET method used')) addVuln('form_get_method', `Form[${i}] ${f.action}`, `method=GET`);
          if (f.issues.includes('No CSRF token')) addVuln('form_no_csrf', `Form[${i}] ${f.action}`, 'CSRF 토큰 없음');
          if (f.issues.includes('File upload present')) addVuln('form_file_upload', `Form[${i}] ${f.action}`, '파일 업로드 필드 존재');
        });

        // 숨겨진 입력 → 취약점 등록
        (response.hiddenInputs || []).forEach((el: any) => {
          addVuln('hidden_input_found', `hidden input: ${el.name}`, `value=${el.value}`);
        });

        addLog(`Recon 완료: hidden(${response.hiddenInputs.length}) disabled(${response.disabledElements.length}) forms(${forms.length})`);
      }
    } catch (e: any) {
      addLog('⚠️ 오류: Content Script가 로드되지 않았습니다.');
      addLog('💡 팁: 페이지를 새로고침(F5)하거나 chrome:// 페이지에서는 동작하지 않습니다.');
    }
  };

  const handleSaveScan = async () => {
    if (!currentOrigin) return;
    try {
      const targetId = await db.getOrCreateTarget(currentOrigin);
      await db.saveScan(targetId, currentOrigin, {
        hidden: hiddenElements,
        disabled: disabledElements,
        secrets: foundSecrets,
        forms: foundForms,
        vulns: vulnFindings,
      });
      addLog('스캔 결과가 기록에 저장되었습니다.');
    } catch (e) { addLog('저장 실패.'); }
  };

  const handleNetworkScan = async (url: string) => {
    setIsScanning(true);
    addLog(`소스 스캔 중: ${url.split('/').pop()}`);
    const matches: ScanResult[] | null = await scanNetworkResource(url);
    if (matches && matches.length > 0) {
      setFoundSecrets(prev => [...matches, ...prev].slice(0, 50));
      matches.forEach(m => addVuln('exposed_api_key', url, m.value, m.type));
      addLog(`${url.split('/').pop()} 에서 ${matches.length} 개의 민감 정보 발견`);
    } else if (matches !== null) {
      addLog('민감 정보 없음.');
    }
    setIsScanning(false);
  };

  const toggleVisibility = async (shown: boolean) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    setIsVisualShown(shown);
    try {
      await chrome.tabs.sendMessage(tab.id, { action: 'TOGGLE_VISIBILITY', isVisible: shown });
      addLog(`시각적 요소 표시: ${shown ? 'ON' : 'OFF'}`);
    } catch (e: any) {
      addLog('⚠️ Content Script 접근 불가. 페이지를 새로고침 해주세요.');
    }
  };

  const runPayload = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    try {
      addLog('페이로드 실행 중...');
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: (code: string) => {
          try {
            const result = eval(code);
            return { success: true, result: JSON.stringify(result) };
          } catch (e: any) {
            return { success: false, error: e.message };
          }
        },
        args: [payload]
      });
      const execRes = results[0].result as any;
      addLog(execRes.success ? `결과: ${execRes.result}` : `오류: ${execRes.error}`);
    } catch (err: any) { addLog(`시스템 오류: ${err.message}`); }
  };

  // ─── Encoder 유틸 ───
  const encode = (mode: string) => {
    try {
      switch (mode) {
        case 'b64enc': setEncOutput(btoa(encInput)); break;
        case 'b64dec': setEncOutput(atob(encInput)); break;
        case 'urlenc': setEncOutput(encodeURIComponent(encInput)); break;
        case 'urldec': setEncOutput(decodeURIComponent(encInput)); break;
        case 'hex': setEncOutput(Array.from(encInput).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')); break;
        case 'htmlenc': {
          const el = document.createElement('div');
          el.textContent = encInput;
          setEncOutput(el.innerHTML);
          break;
        }
        default: break;
      }
    } catch (e: any) { setEncOutput('오류: ' + e.message); }
  };

  // 탭별 취약점 카운트
  const vulnCount = vulnFindings.length;
  const criticalCount = vulnFindings.filter(v => VULN_DB[v.vulnId]?.severity === 'critical').length;

  return (
    <div className="app-container">
      <header>
        <div className="logo"><Shield size={20} /> HackerDev</div>
        {currentOrigin && <div style={{ fontSize: 9, color: '#555', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{currentOrigin}</div>}
        <div style={{ display: 'flex', gap: 6 }}>
          {vulnCount > 0 && (
            <button className={`btn-vuln-badge ${criticalCount > 0 ? 'critical' : ''}`} onClick={() => setActiveTab('vulns')} title="취약점 목록">
              🚨 {vulnCount}
            </button>
          )}
          <button className="btn-secondary" onClick={handleSaveScan} title="기록 저장"><Save size={14} /></button>
          <button className="btn-primary" onClick={handleScan}><RefreshCw size={14} style={{ marginRight: 6 }} />Full Recon</button>
        </div>
      </header>

      <div className="nav-main">
        <button className={activeMainTab === 'scan' ? 'active' : ''} onClick={() => setActiveMainTab('scan')}>⚡ SCAN</button>
        <button className={activeMainTab === 'net' ? 'active' : ''} onClick={() => setActiveMainTab('net')}>🌐 NET</button>
        <button className={activeMainTab === 'attack' ? 'active' : ''} onClick={() => setActiveMainTab('attack')}>⚔️ ATTACK</button>
        <button className={`${activeMainTab === 'report' ? 'active' : ''} ${criticalCount > 0 ? 'tab-critical' : vulnCount > 0 ? 'tab-high' : ''}`} onClick={() => setActiveMainTab('report')}>
          🛡️ REPORT{vulnCount > 0 ? ` (${vulnCount})` : ''}
        </button>
      </div>

      <div className="nav-sub">
        {activeMainTab === 'scan' && (
          <>
            <button className={activeTab === 'recon' ? 'active' : ''} onClick={() => setActiveTab('recon')}>RECON</button>
            <button className={activeTab === 'forms' ? 'active' : ''} onClick={() => setActiveTab('forms')}>FORMS</button>
            <button className={activeTab === 'jsview' ? 'active' : ''} style={{ color: activeTab === 'jsview' ? '' : '#aa88ff' }} onClick={() => setActiveTab('jsview')}>JSVIEW</button>
            <button className={activeTab === 'inspect' ? 'active' : ''} style={{ color: activeTab === 'inspect' ? '' : '#00ffaa' }} onClick={() => setActiveTab('inspect')}>INSPECT</button>
          </>
        )}
        {activeMainTab === 'net' && (
          <>
            <button className={activeTab === 'network' ? 'active' : ''} onClick={() => setActiveTab('network')}>NET LOG</button>
            <button className={activeTab === 'repeat' ? 'active' : ''} style={{ color: activeTab === 'repeat' ? '' : '#00aaff' }} onClick={() => setActiveTab('repeat')}>REPEAT</button>
            <button className={activeTab === 'jwt' ? 'active' : ''} style={{ color: activeTab === 'jwt' ? '' : '#ffbb00' }} onClick={() => setActiveTab('jwt')}>JWT</button>
          </>
        )}
        {activeMainTab === 'attack' && (
          <>
            <button className={activeTab === 'workbench' ? 'active' : ''} onClick={() => setActiveTab('workbench')}>DEV</button>
            <button className={activeTab === 'storage' ? 'active' : ''} onClick={() => setActiveTab('storage')}>STORE</button>
            <button className={activeTab === 'live' ? 'active' : ''} onClick={() => setActiveTab('live')}>LIVE</button>
          </>
        )}
        {activeMainTab === 'report' && (
          <>
            <button className={activeTab === 'vulns' ? 'active' : ''} onClick={() => setActiveTab('vulns')}>VULNS</button>
            <button className={activeTab === 'history' ? 'active' : ''} onClick={() => setActiveTab('history')}>HISTORY</button>
            <button className={activeTab === 'library' ? 'active' : ''} onClick={() => setActiveTab('library')}>LIBRARY</button>
          </>
        )}
      </div>

      <div className="content-area">

        {/* ══════ RECON ══════ */}
        {activeTab === 'recon' && (
          <div className="tab-pane">
            {currentOrigin && (
              <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 10, display: 'flex', justifyContent: 'space-between' }}>
                <span>대상: {currentOrigin}</span>
                <span style={{ cursor: 'pointer', color: '#ff4444', textDecoration: 'underline' }} onClick={clearSiteData}>데이터 초기화</span>
              </div>
            )}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 13, fontWeight: 700 }}>숨겨진 요소 시각화</span>
                {isVisualShown
                  ? <Eye className="accent-color" style={{ cursor: 'pointer' }} onClick={() => toggleVisibility(false)} />
                  : <EyeOff style={{ cursor: 'pointer', color: '#666' }} onClick={() => toggleVisibility(true)} />}
              </div>
            </div>

            <SectionHeader title="숨겨진 입력 필드" count={hiddenElements.length} color="var(--accent-neon)" />
            <div className="card list-container">
              {hiddenElements.length === 0 ? <EmptyMsg /> : hiddenElements.map((el: any, n: number) => (
                <div key={n} className="list-item">
                  <div style={{ overflow: 'hidden', flex: 1 }}>
                    <div style={{ fontSize: 12 }}><span className="badge badge-hidden">HIDDEN</span> <strong>{el.name}</strong></div>
                    <div className="value-label">{el.value || '(empty)'}</div>
                  </div>
                  <Play size={12} className="accent-color" style={{ cursor: 'pointer' }}
                    onClick={() => { setPayload(`document.getElementsByName('${el.name}')[0].value = 'PAYLOAD';`); setActiveTab('workbench'); }} />
                </div>
              ))}
            </div>

            <SectionHeader title="민감 정보 (JS 소스)" count={foundSecrets.length} color="#ffbb00" />
            <div className="card list-container">
              {foundSecrets.length === 0 ? <EmptyMsg msg="NET 탭에서 JS 파일을 SCAN하면 탐지됩니다." /> : foundSecrets.map((s: any, n: number) => (
                <div key={n} className="list-item" style={{ borderLeft: '2px solid #ffbb00', paddingLeft: 8 }}>
                  <div>
                    <div style={{ fontSize: 11, color: '#ffbb00' }}>{s.type}</div>
                    <code style={{ fontSize: 10, display: 'block', background: '#000', padding: 2, wordBreak: 'break-all' }}>{s.value}</code>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══════ NETWORK ══════ */}
        {activeTab === 'network' && (
          <div className="tab-pane">
            {currentOrigin && (
              <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 5, display: 'flex', justifyContent: 'space-between' }}>
                <span>추적 중: {currentOrigin}</span>
                <Trash size={12} style={{ cursor: 'pointer' }} onClick={clearSiteData} />
              </div>
            )}
            <SectionHeader title="네트워크 리소스" count={networkLogs.length} color="var(--accent-secondary)" />
            <div className="card list-container" style={{ maxHeight: '400px' }}>
              {networkLogs.length === 0 ? <EmptyMsg msg="페이지를 새로고침하면 요청이 캡처됩니다." /> : networkLogs.map((log: any, n: number) => (
                <div key={n} className="list-item">
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <div style={{ fontSize: 11, whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>{log.url}</div>
                    <div style={{ fontSize: 9, color: '#8b949e' }}>{log.type?.toUpperCase()} | {log.method}</div>
                  </div>
                  {(log.type === 'script' || log.url?.includes('.js')) && (
                    <button className="badge-btn" onClick={() => handleNetworkScan(log.url)} disabled={isScanning}>SCAN</button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══════ LIVE ══════ */}
        {activeTab === 'live' && (
          <div className="tab-pane">
            <SectionHeader title="런타임 이벤트 (훅 감지)" count={runtimeEvents.length} color="#00ff9d" />
            <div className="card list-container" style={{ maxHeight: '450px' }}>
              {runtimeEvents.length === 0 ? <EmptyMsg msg="훅 이벤트 대기 중... (페이지를 새로고침하면 활성화됩니다)" /> : runtimeEvents.map((ev: any, n: number) => {
                const isSink = ev.type === 'sink_usage';
                const isPostMsg = ev.type === 'postmessage_listener';
                const isRedirect = ev.type === 'location_change';
                const color = isSink ? '#ff0033' : isRedirect ? '#ffaa00' : isPostMsg ? '#ff88ff' : '#00ff9d';
                const vulnDef = ev.vulnId ? VULN_DB[ev.vulnId] : null;
                return (
                  <div key={n} className="list-item" style={{ borderLeft: `2px solid ${color}`, paddingLeft: 8, flexDirection: 'column', alignItems: 'flex-start' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', marginBottom: 4 }}>
                      <span className="badge" style={{ background: color, color: '#000' }}>{ev.type?.toUpperCase()}</span>
                      <span style={{ fontSize: 9, color: '#8b949e' }}>{new Date(ev.timeStamp).toLocaleTimeString()}</span>
                    </div>
                    {vulnDef && (
                      <div style={{ fontSize: 10, color: getSeverityColor(vulnDef.severity), marginBottom: 2 }}>
                        ⚠️ {vulnDef.title}
                        <button className="badge-btn" style={{ marginLeft: 6, fontSize: 9 }}
                          onClick={() => { setActiveTab('vulns'); }}>상세보기</button>
                      </div>
                    )}
                    {ev.type === 'event_listener' && (
                      <div style={{ fontSize: 11 }}>
                        <div style={{ color: '#00ff9d' }}>{ev.eventType} on {ev.element}</div>
                        <code style={{ fontSize: 9, opacity: 0.7, display: 'block', marginTop: 2 }}>{ev.listener}</code>
                      </div>
                    )}
                    {(ev.type === 'dynamic_request' || ev.type === 'postmessage_listener') && (
                      <div style={{ fontSize: 11, wordBreak: 'break-all' }}>
                        <strong>{ev.method || ev.type}</strong>: {ev.url || ev.listenerSnippet?.substring(0, 80)}
                      </div>
                    )}
                    {isSink && (
                      <div style={{ fontSize: 11 }}>
                        <div style={{ color: '#ff0033' }}>Sink: {ev.type || 'unknown'}</div>
                        <code style={{ fontSize: 9, display: 'block', background: '#300', padding: 2, wordBreak: 'break-all' }}>{ev.content}</code>
                      </div>
                    )}
                    {isRedirect && (
                      <div style={{ fontSize: 11 }}>
                        <div style={{ color: '#ffaa00' }}>리다이렉트: {ev.method}</div>
                        <code style={{ fontSize: 9, display: 'block' }}>{ev.fromUrl} → {ev.toUrl}</code>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ══════ FORMS ══════ */}
        {activeTab === 'forms' && (
          <div className="tab-pane">
            <SectionHeader title="폼 분석" count={foundForms.length} color="#44ffaa" />
            <div className="card list-container">
              {foundForms.length === 0 ? <EmptyMsg msg="Full Recon 버튼을 눌러 폼을 분석하세요." /> : foundForms.map((f: any, n: number) => (
                <div key={n} className="card" style={{ marginBottom: 10, background: '#161b22' }}>
                  <div style={{ fontSize: 12, fontWeight: 'bold', color: '#44ffaa' }}>{f.method.toUpperCase()} {f.action}</div>
                  <div style={{ fontSize: 10, margin: '5px 0' }}>
                    {f.issues.map((iss: string, i: number) => (
                      <div key={i} style={{ color: '#ff4444' }}>⚠️ {iss}</div>
                    ))}
                    {f.issues.length === 0 && <div style={{ color: '#00ff9d' }}>✅ 취약점 없음</div>}
                  </div>
                  <div style={{ maxHeight: 100, overflow: 'auto', background: '#0d1117', padding: 5, borderRadius: 4 }}>
                    {f.inputs.map((inpt: any, i: number) => (
                      <div key={i} style={{ fontSize: 10, color: '#8b949e' }}>{inpt.name} ({inpt.type}) = {inpt.value}</div>
                    ))}
                  </div>
                  <button className="badge-btn" style={{ marginTop: 8, width: '100%' }} onClick={() => {
                    const raw = formToRawRequest(f, window.location.host);
                    setPayload(raw);
                    setActiveTab('workbench');
                  }}>Raw Request로 복사</button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══════ STORAGE ══════ */}
        {activeTab === 'storage' && (
          <div className="tab-pane">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <SectionHeader title="Storage 감사" count={storageData.local.length + storageData.session.length + storageData.cookies.length} color="#44aaff" />
              <button className="badge-btn" onClick={loadStorage}><RotateCcw size={10} style={{ marginRight: 4 }} />새로고침</button>
            </div>

            {/* Cookies */}
            <div style={{ marginBottom: 4, fontSize: 11, color: '#8b949e', fontWeight: 700 }}>🍪 COOKIES ({storageData.cookies.length})</div>
            <div className="card list-container" style={{ maxHeight: 150, marginBottom: 12 }}>
              {storageData.cookies.length === 0 ? <EmptyMsg msg="쿠키 없음" /> : storageData.cookies.map((c: chrome.cookies.Cookie, i) => {
                const missingFlags = [!c.httpOnly && 'HttpOnly', !c.secure && 'Secure', (!c.sameSite || c.sameSite === 'unspecified') && 'SameSite'].filter(Boolean);
                return (
                  <div key={i} className="list-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                      <strong style={{ fontSize: 11 }}>{c.name}</strong>
                      <Trash2 size={11} style={{ cursor: 'pointer', color: '#ff4444' }} onClick={() => deleteCookie(c)} />
                    </div>
                    <div style={{ fontSize: 9, color: '#555', wordBreak: 'break-all' }}>{c.value.substring(0, 60)}</div>
                    <div style={{ display: 'flex', gap: 4, marginTop: 2, flexWrap: 'wrap' }}>
                      {['httpOnly', 'secure', 'sameSite'].map(flag => (
                        <span key={flag} className="badge" style={{ background: (c as any)[flag] && (c as any)[flag] !== 'unspecified' ? '#1a3a1a' : '#3a1a1a', fontSize: 8 }}>
                          {flag === 'sameSite' ? `SameSite:${c.sameSite || 'none'}` : flag}
                          {!(c as any)[flag] || (c as any)[flag] === 'unspecified' ? ' ⚠️' : ' ✅'}
                        </span>
                      ))}
                    </div>
                    {missingFlags.length > 0 && (
                      <div style={{ fontSize: 9, color: '#ff6600', marginTop: 2 }}>누락 보안 속성: {missingFlags.join(', ')}</div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* LocalStorage */}
            <div style={{ marginBottom: 4, fontSize: 11, color: '#8b949e', fontWeight: 700 }}>📦 LocalStorage ({storageData.local.length})</div>
            <StorageEditor entries={storageData.local} type="local" onEdit={editStorage} />

            {/* SessionStorage */}
            <div style={{ marginBottom: 4, marginTop: 12, fontSize: 11, color: '#8b949e', fontWeight: 700 }}>📋 SessionStorage ({storageData.session.length})</div>
            <StorageEditor entries={storageData.session} type="session" onEdit={editStorage} />

            {/* 편집기 */}
            <div className="card" style={{ marginTop: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 6 }}>⚡ 값 강제 설정</div>
              <input className="storage-input" value={editKey} onChange={e => setEditKey(e.target.value)} placeholder="키(key)" />
              <input className="storage-input" value={editVal} onChange={e => setEditVal(e.target.value)} placeholder="값(value)" style={{ marginTop: 4 }} />
              <div style={{ display: 'flex', gap: 4, marginTop: 6 }}>
                <button className="badge-btn" style={{ flex: 1 }} onClick={() => editStorage('local', editKey, editVal)}>localStorage 설정</button>
                <button className="badge-btn" style={{ flex: 1 }} onClick={() => editStorage('session', editKey, editVal)}>sessionStorage 설정</button>
              </div>
            </div>
          </div>
        )}

        {/* ══════ VULNS ══════ */}
        {activeTab === 'vulns' && (
          <div className="tab-pane">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <SectionHeader title="발견된 취약점" count={vulnFindings.length} color="#ff0033" />
              {vulnFindings.length > 0 && (
                <button className="badge-btn" style={{ color: '#ff4444' }} onClick={() => { setVulnFindings([]); setSelectedVuln(null); }}>
                  <Trash2 size={10} /> 초기화
                </button>
              )}
            </div>

            {vulnFindings.length === 0 ? (
              <EmptyMsg msg="발견된 취약점이 없습니다. Full Recon, LIVE, STORE, NET 탭에서 분석을 진행하세요." />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {/* 취약점 목록 */}
                <div className="card list-container" style={{ maxHeight: selectedVuln ? 180 : 440 }}>
                  {vulnFindings.map((finding, i) => {
                    const def = VULN_DB[finding.vulnId];
                    if (!def) return null;
                    const col = getSeverityColor(def.severity);
                    const isSelected = selectedVuln?.id === finding.id;
                    return (
                      <div key={i} className="list-item"
                        style={{ borderLeft: `3px solid ${col}`, paddingLeft: 8, cursor: 'pointer', background: isSelected ? 'rgba(255,255,255,0.04)' : 'transparent' }}
                        onClick={() => setSelectedVuln(isSelected ? null : finding)}>
                        <div style={{ flex: 1, overflow: 'hidden' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                            <span className="badge" style={{ background: col, color: '#000', fontSize: 8, padding: '1px 5px' }}>{getSeverityLabel(def.severity)}</span>
                            <span style={{ fontSize: 11, fontWeight: 700, color: col }}>{def.title}</span>
                          </div>
                          <div style={{ fontSize: 9, color: '#8b949e', marginTop: 2 }}>
                            📍 {finding.location}
                          </div>
                        </div>
                        <span style={{ fontSize: 9, color: '#555' }}>{new Date(finding.timeStamp).toLocaleTimeString()}</span>
                      </div>
                    );
                  })}
                </div>

                {/* 선택 취약점 상세 카드 */}
                {selectedVuln && VULN_DB[selectedVuln.vulnId] && (
                  <VulnDetailCard finding={selectedVuln} def={VULN_DB[selectedVuln.vulnId]} onClose={() => setSelectedVuln(null)} />
                )}
              </div>
            )}
          </div>
        )}

        {/* ══════ DEV Workbench ══════ */}
        {activeTab === 'workbench' && (
          <div className="tab-pane" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
              <div style={{ fontSize: 11, color: '#8b949e', alignSelf: 'center', flex: 1 }}>JS 페이로드 실행기</div>
              <button className="badge-btn" onClick={() => setActiveTab('library')}>라이브러리</button>
            </div>
            <div className="editor-container">
              <div className="editor-header">EDITOR <Trash2 size={12} onClick={() => setPayload('')} style={{ cursor: 'pointer' }} /></div>
              <textarea className="editor-textarea" value={payload} onChange={(e) => setPayload(e.target.value)} placeholder="// 실행할 JS 코드를 입력하세요..." />
              <button className="btn-primary" style={{ borderRadius: 0 }} onClick={runPayload}>EXECUTE</button>
            </div>

            {/* Encoder/Decoder */}
            <div className="card" style={{ marginTop: 10 }}>
              <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
                <Code2 size={12} /> 인코더 / 디코더
              </div>
              <textarea className="editor-textarea" style={{ height: 50, marginBottom: 4 }}
                value={encInput} onChange={e => setEncInput(e.target.value)} placeholder="변환할 문자열 입력..." />
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
                {[['B64 인코딩', 'b64enc'], ['B64 디코딩', 'b64dec'], ['URL 인코딩', 'urlenc'], ['URL 디코딩', 'urldec'], ['HEX 변환', 'hex'], ['HTML 인코딩', 'htmlenc']].map(([label, mode]) => (
                  <button key={mode} className="badge-btn" onClick={() => encode(mode)}>{label}</button>
                ))}
              </div>
              {encOutput && (
                <div style={{ background: '#0d1117', padding: 6, borderRadius: 4, fontSize: 10, wordBreak: 'break-all', color: '#00ff9d', cursor: 'pointer' }}
                  onClick={() => setPayload(encOutput)} title="클릭하면 에디터로 복사">
                  {encOutput}
                </div>
              )}
            </div>

            <div className="console-output" style={{ flex: 1 }}>
              {logs.map((log: string, i: number) => <div key={i} className="log-line">{log}</div>)}
            </div>
          </div>
        )}

        {/* ══════ LIBRARY ══════ */}
        {activeTab === 'library' && (
          <div className="tab-pane">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <SectionHeader title="페이로드 라이브러리" count={snippets.length} color="#aa88ff" />
              <div style={{ display: 'flex', gap: 6 }}>
                <button className="badge-btn" onClick={handleExportSnippets} title="JSON 파일로 내보내기">
                  <Download size={11} style={{ marginRight: 4 }} /> Export
                </button>
                <label className="badge-btn" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center' }} title="JSON 파일에서 불러오기(덮어쓰기)">
                  <Upload size={11} style={{ marginRight: 4 }} /> Import
                  <input type="file" accept=".json" style={{ display: 'none' }} onChange={handleImportSnippets} />
                </label>
                <button className="btn-primary" style={{ padding: '4px 8px', fontSize: '10px' }} 
                  onClick={() => setEditingSnippet({ id: `custom_${Date.now()}`, title: '', chapter: 'Custom', code: '' })}>
                  <Plus size={11} style={{ marginRight: 4 }} /> 새 페이로드
                </button>
              </div>
            </div>

            {editingSnippet ? (
              <div className="card" style={{ borderLeft: '3px solid #aa88ff' }}>
                <div style={{ fontSize: 11, fontWeight: 800, marginBottom: 8, color: '#aa88ff' }}>
                  {snippets.find(s => s.id === editingSnippet.id) ? '페이로드 수정' : '새 페이로드 작성'}
                </div>
                <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                  <input className="storage-input" style={{ flex: 1 }} value={editingSnippet.title} 
                    onChange={e => setEditingSnippet({ ...editingSnippet, title: e.target.value })} placeholder="페이로드 제목 (예: 관리자 권한 탈취)" />
                  <input className="storage-input" style={{ width: 100 }} value={editingSnippet.chapter} 
                    onChange={e => setEditingSnippet({ ...editingSnippet, chapter: e.target.value })} placeholder="카테고리 (태그)" />
                </div>
                <textarea className="editor-textarea" style={{ height: 120, width: '100%', boxSizing: 'border-box', background: '#0d1117', borderRadius: 6, fontSize: 11, border: '1px solid rgba(255,255,255,0.1)' }}
                  value={editingSnippet.code} onChange={e => setEditingSnippet({ ...editingSnippet, code: e.target.value })} placeholder="JS 코드 입력..." />
                <div style={{ display: 'flex', gap: 6, marginTop: 8, justifyContent: 'flex-end' }}>
                  <button className="badge-btn" onClick={() => setEditingSnippet(null)}>취소</button>
                  <button className="btn-primary" style={{ padding: '6px 12px' }} onClick={handleSaveSnippet}>저장</button>
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {snippets.length === 0 ? <EmptyMsg msg="저장된 페이로드 없음" /> : snippets.map(snip => (
                  <div key={snip.id} className="card snippet-card" style={{ marginBottom: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <strong style={{ fontSize: 13 }}>{snip.title}</strong>
                        <span className="badge" style={{ background: '#333' }}>{snip.chapter}</span>
                      </div>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="badge-btn" style={{ color: '#00d4ff', borderColor: 'rgba(0, 212, 255, 0.3)' }}
                          onClick={() => { setPayload(snip.code); setActiveMainTab('attack'); setActiveTab('workbench'); }}>
                          <Play size={10} style={{ marginRight: 4 }} /> 적용
                        </button>
                        <button className="badge-btn" onClick={() => setEditingSnippet({ ...snip })}><Edit size={10} /></button>
                        <button className="badge-btn" onClick={(e) => deleteSnippet(snip.id, e)}><Trash2 size={10} color="#ff4444" /></button>
                      </div>
                    </div>
                    <pre style={{ margin: 0, padding: 6, background: 'rgba(0,0,0,0.3)', borderRadius: 4, color: '#aaa', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {snip.code.split('\n')[0].substring(0, 100)}...
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ══════ HISTORY ══════ */}
        {activeTab === 'history' && (
          <div className="tab-pane">
            <SectionHeader title="저장된 스캔 기록" count={history.length} color="#8b949e" />
            <div className="card list-container">
              {history.length === 0 ? <EmptyMsg msg="저장된 스캔 없음." /> : history.map((h: any, n: number) => (
                <div key={n} className="list-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                    <strong style={{ fontSize: 12 }}>{h.url}</strong>
                    <Trash2 size={12} style={{ cursor: 'pointer', color: '#ff4444' }} onClick={async () => { await db.deleteScan(h.id!); loadHistory(); }} />
                  </div>
                  <div style={{ fontSize: 10, color: '#8b949e' }}>{new Date(h.timestamp).toLocaleString()}</div>
                  <button className="badge-btn" style={{ marginTop: 5 }} onClick={() => {
                    setHiddenElements(h.data.hidden || []);
                    setDisabledElements(h.data.disabled || []);
                    setFoundSecrets(h.data.secrets || []);
                    setFoundForms(h.data.forms || []);
                    if (h.data.vulns) setVulnFindings(h.data.vulns);
                    setActiveTab('recon');
                    addLog(`스캔 로드: ${new Date(h.timestamp).toLocaleTimeString()}`);
                  }}>데이터 불러오기</button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══════ REPEAT (Request Repeater) ══════ */}
        {activeTab === 'repeat' && (
          <RepeaterPanel
            networkLogs={networkLogs}
            addLog={addLog}
            addVuln={addVuln}
            currentOrigin={currentOrigin}
          />
        )}

        {/* ══════ JWT Inspector ══════ */}
        {activeTab === 'jwt' && (
          <JwtPanel
            networkLogs={networkLogs}
            addLog={addLog}
            addVuln={addVuln}
            currentOrigin={currentOrigin}
          />
        )}

        {/* ══════ JS Viewer ══════ */}
        {activeTab === 'jsview' && (
          <JsViewerPanel
            networkLogs={networkLogs}
            addLog={addLog}
            addVuln={addVuln}
            currentOrigin={currentOrigin}
          />
        )}

        {/* ══════ Framework Inspector ══════ */}
        {activeTab === 'inspect' && (
          <FrameworkPanel
            networkLogs={networkLogs}
            addLog={addLog}
            addVuln={addVuln}
            currentOrigin={currentOrigin}
          />
        )}
      </div>
    </div>
  );
}

// ─────────── 취약점 상세 카드 ───────────
function VulnDetailCard({ finding, def, onClose }: { finding: VulnFinding; def: VulnDefinition; onClose: () => void }) {
  const col = getSeverityColor(def.severity);
  return (
    <div className="vuln-detail-card" style={{ borderLeft: `3px solid ${col}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
        <div>
          <span className="badge" style={{ background: col, color: '#000', fontSize: 9 }}>{getSeverityLabel(def.severity)}</span>
          {def.owasp && <span className="badge" style={{ background: '#1a2a3a', fontSize: 9, marginLeft: 4 }}>{def.owasp.split(' ')[0]}</span>}
          {def.cwe && <span className="badge" style={{ background: '#1a1a2a', fontSize: 9, marginLeft: 4 }}>{def.cwe}</span>}
        </div>
        <button className="badge-btn" onClick={onClose} style={{ fontSize: 9 }}>닫기</button>
      </div>
      <div style={{ fontSize: 12, fontWeight: 800, color: col, marginBottom: 4 }}>{def.title}</div>
      <div style={{ fontSize: 9, color: '#44aaff', marginBottom: 6 }}>📂 분류: {def.category}</div>

      <VulnSection icon="📍" label="발견 위치" color="#8b949e">
        <code style={{ fontSize: 9, wordBreak: 'break-all' }}>{finding.location}</code>
        {finding.detail && <div style={{ fontSize: 9, color: '#8b949e', marginTop: 2 }}>{finding.detail}</div>}
      </VulnSection>

      <VulnSection icon="🔬" label="증거 (Evidence)" color="#8b949e">
        <code style={{ fontSize: 9, wordBreak: 'break-all', display: 'block', background: '#000', padding: 3, borderRadius: 3 }}>
          {finding.evidence || '(없음)'}
        </code>
      </VulnSection>

      <VulnSection icon="📋" label="취약점 설명" color="#ccc">
        <p style={{ fontSize: 10, lineHeight: 1.6, margin: 0 }}>{def.description}</p>
      </VulnSection>

      <VulnSection icon="⚡" label="보안 위협" color="#ff6600">
        <p style={{ fontSize: 10, lineHeight: 1.6, margin: 0, color: '#ffaa66' }}>{def.threat}</p>
      </VulnSection>

      <VulnSection icon="🛡️" label="조치 권고사항" color="#00ff9d">
        <p style={{ fontSize: 10, lineHeight: 1.6, margin: 0, color: '#aaffcc' }}>{def.recommendation}</p>
      </VulnSection>
    </div>
  );
}

function VulnSection({ icon, label, color, children }: { icon: string; label: string; color: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 9, fontWeight: 700, color, textTransform: 'uppercase', marginBottom: 3 }}>{icon} {label}</div>
      <div style={{ paddingLeft: 8 }}>{children}</div>
    </div>
  );
}

function StorageEditor({ entries, type, onEdit }: { entries: [string, string][]; type: 'local' | 'session'; onEdit: (t: 'local' | 'session', k: string, v: string) => void }) {
  const [editing, setEditing] = useState<string | null>(null);
  const [val, setVal] = useState('');
  const sensitivePatterns = /token|jwt|password|secret|key|auth|session/i;

  return (
    <div className="card list-container" style={{ maxHeight: 130, marginBottom: 4 }}>
      {entries.length === 0 ? <EmptyMsg msg="데이터 없음" /> : entries.map(([k, v], i) => {
        const isSensitive = sensitivePatterns.test(k) || sensitivePatterns.test(v);
        return (
          <div key={i} className="list-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: isSensitive ? '#ff6600' : '#ccc' }}>
                {isSensitive ? '⚠️ ' : ''}{k}
              </span>
              <button className="badge-btn" style={{ fontSize: 8 }} onClick={() => { setEditing(k); setVal(v); }}>수정</button>
            </div>
            {editing === k ? (
              <div style={{ display: 'flex', gap: 4, width: '100%', marginTop: 3 }}>
                <input className="storage-input" style={{ flex: 1 }} value={val} onChange={e => setVal(e.target.value)} />
                <button className="badge-btn" onClick={() => { onEdit(type, k, val); setEditing(null); }}>저장</button>
                <button className="badge-btn" onClick={() => setEditing(null)}>취소</button>
              </div>
            ) : (
              <div style={{ fontSize: 9, color: '#555', wordBreak: 'break-all' }}>{v.substring(0, 80)}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─────────── 공통 컴포넌트 ───────────
const SectionHeader = ({ title, count, color }: any) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '15px 0 5px 5px' }}>
    <div style={{ width: 3, height: 14, background: color }}></div>
    <span style={{ fontSize: 12, fontWeight: 800, color: '#eee' }}>{title.toUpperCase()} ({count})</span>
  </div>
);

const EmptyMsg = ({ msg = '아직 데이터가 없습니다.' }: { msg?: string }) => (
  <p style={{ fontSize: 11, color: '#666', textAlign: 'center', margin: '20px 0' }}>{msg}</p>
);

export default App;
