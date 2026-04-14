import { useState, useEffect } from 'react';
import { Shield, Play, Trash2, Eye, EyeOff, RefreshCw, Trash, Save } from 'lucide-react';
import { DEFAULT_SNIPPETS } from './config/payloads';
import { scanNetworkResource, type ScanResult, type FormInfo, formToRawRequest } from './utils/scanner';
import { db, type ScanResultData } from './utils/db';

function App() {
  const [activeTab, setActiveTab] = useState<'recon' | 'network' | 'live' | 'forms' | 'history' | 'workbench' | 'library'>('recon');
  const [hiddenElements, setHiddenElements] = useState<any[]>([]);
  const [disabledElements, setDisabledElements] = useState<any[]>([]);
  const [logs, setLogs] = useState<string[]>(['[System] Workbench Ready.']);
  const [isVisualShown, setIsVisualShown] = useState(false);
  const [payload, setPayload] = useState('');
  const [currentOrigin, setCurrentOrigin] = useState<string>('');
  
  // Network & Secrets & Events State
  const [networkLogs, setNetworkLogs] = useState<any[]>([]);
  const [runtimeEvents, setRuntimeEvents] = useState<any[]>([]);
  const [foundSecrets, setFoundSecrets] = useState<any[]>([]);
  const [foundForms, setFoundForms] = useState<FormInfo[]>([]);
  const [history, setHistory] = useState<ScanResultData[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const addLog = (msg: string) => {
    setLogs((prev: string[]) => [...prev.slice(-49), `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  // 실시간 로그 동기화 (Network + Live Events)
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
        setRuntimeEvents(storedEvents[origin] || []);
      });
    };

    updateLogs();
    const interval = setInterval(updateLogs, 2000);
    return () => clearInterval(interval);
  }, []);

  const loadHistory = async () => {
    if (!currentOrigin) return;
    try {
       const targetId = await db.getOrCreateTarget(currentOrigin);
       const scans = await db.getScansByTarget(targetId);
       setHistory(scans.reverse());
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    if (activeTab === 'history') loadHistory();
  }, [activeTab, currentOrigin]);

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
        addLog(`Cleared data for site: ${currentOrigin}`);
      });
    });
  };

  const handleScan = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
      const response: any = await chrome.tabs.sendMessage(tab.id, { action: 'SCAN_PAGE' });
      if (response) {
        setHiddenElements(response.hiddenInputs || []);
        setDisabledElements(response.disabledElements || []);
        
        // 폼 분석 추가
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
               return { action: f.action, method: f.method, inputs: inputData, issues };
             });
          }
        });
        setFoundForms(formResults[0].result as FormInfo[]);

        addLog(`Recon complete: ${response.hiddenInputs.length} hidden, ${response.disabledElements.length} disabled, ${formResults[0].result ? (formResults[0].result as any[]).length : 0} forms.`);
      }
    } catch (e: any) {
      addLog('⚠️ Error: Content script not loaded.');
      addLog('💡 Tip: Try refreshing the web page (F5), or ensure you are not on a chrome:// page.');
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
        forms: foundForms
      });
      addLog('Scan results saved to history.');
    } catch (e) {
      addLog('Failed to save to history.');
    }
  };

  const handleNetworkScan = async (url: string) => {
    setIsScanning(true);
    addLog(`Scanning source: ${url.split('/').pop()}`);
    
    const matches: ScanResult[] | null = await scanNetworkResource(url);
    
    if (matches && matches.length > 0) {
        // 기존 시크릿과 합치되 50개 유지 (Set을 사용해 중복 검증도 가능)
        setFoundSecrets((prev: any[]) => [...matches, ...prev].slice(0, 50));
        addLog(`Found ${matches.length} secrets in ${url.split('/').pop()}`);
    } else if (matches !== null) {
        addLog('No sensitive information found in this file.');
    }
    
    setIsScanning(false);
  };

  const toggleVisibility = async (shown: boolean) => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    setIsVisualShown(shown);
    try {
      await chrome.tabs.sendMessage(tab.id, { action: 'TOGGLE_VISIBILITY', isVisible: shown });
      addLog(`Visual visibility: ${shown ? 'ON' : 'OFF'}`);
    } catch (e: any) {
      addLog('⚠️ Error: Content script unreachable.');
      addLog('💡 Tip: Try refreshing the web page (F5), or ensure you are not on a chrome:// page.');
    }
  };

  const runPayload = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    try {
      addLog('Injecting payload...');
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
      addLog(execRes.success ? `Result: ${execRes.result}` : `Error: ${execRes.error}`);
    } catch (err: any) { addLog(`System Error: ${err.message}`); }
  };

  return (
    <div className="app-container">
      <header>
        <div className="logo"><Shield size={20} /> HackerDev</div>
        <div style={{display: 'flex', gap: 8}}>
            <button className="btn-secondary" onClick={handleSaveScan} title="Save to History"><Save size={14} /></button>
            <button className="btn-primary" onClick={handleScan}><RefreshCw size={14} style={{marginRight: 6}} /> Full Recon</button>
        </div>
      </header>
      
      <nav>
        <button className={activeTab === 'recon' ? 'active' : ''} onClick={() => setActiveTab('recon')}>RECON</button>
        <button className={activeTab === 'network' ? 'active' : ''} onClick={() => setActiveTab('network')}>NET</button>
        <button className={activeTab === 'live' ? 'active' : ''} onClick={() => setActiveTab('live')}>LIVE</button>
        <button className={activeTab === 'forms' ? 'active' : ''} onClick={() => setActiveTab('forms')}>FORMS</button>
        <button className={activeTab === 'history' ? 'active' : ''} onClick={() => setActiveTab('history')}>HIST</button>
        <button className={activeTab === 'workbench' ? 'active' : ''} onClick={() => setActiveTab('workbench')}>DEV</button>
        <button className={activeTab === 'library' ? 'active' : ''} onClick={() => setActiveTab('library')}>LIB</button>
      </nav>

      <div className="content-area">
        {activeTab === 'recon' && (
          <div className="tab-pane">
            {currentOrigin && (
                <div style={{fontSize: 10, color: '#8b949e', marginBottom: 10, display: 'flex', justifyContent: 'space-between'}}>
                   <span>Target: {currentOrigin}</span>
                   <span style={{cursor: 'pointer', color: '#ff4444', textDecoration: 'underline'}} onClick={clearSiteData}>Clear Site Data</span>
                </div>
            )}
            <div className="card">
              <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                <span style={{fontSize: 13, fontWeight: 700}}>Reveal Hidden Elements</span>
                {isVisualShown ? 
                  <Eye className="accent-color" style={{cursor: 'pointer'}} onClick={() => toggleVisibility(false)} /> : 
                  <EyeOff style={{cursor: 'pointer', color: '#666'}} onClick={() => toggleVisibility(true)} />
                }
              </div>
            </div>

            <SectionHeader title="Hidden Inputs" count={hiddenElements.length} color="var(--accent-neon)" />
            <div className="card list-container">
              {hiddenElements.length === 0 ? <EmptyMsg /> : hiddenElements.map((el: any, n: number) => (
                <div key={n} className="list-item">
                  <div style={{overflow: 'hidden'}}>
                    <div style={{fontSize: 12}}><span className="badge badge-hidden">HIDDEN</span> <strong>{el.name}</strong></div>
                    <div className="value-label">{el.value || '(empty)'}</div>
                  </div>
                  <Play size={12} className="accent-color" style={{cursor: 'pointer'}} onClick={() => {setPayload(`document.getElementsByName('${el.name}')[0].value = 'HACKED';`); setActiveTab('workbench');}} />
                </div>
              ))}
            </div>

            <SectionHeader title="Secrets Found" count={foundSecrets.length} color="#ffbb00" />
            <div className="card list-container">
               {foundSecrets.length === 0 ? <EmptyMsg msg="Scan network resources to find secrets." /> : foundSecrets.map((s: any, n: number) => (
                 <div key={n} className="list-item" style={{borderLeft: '2px solid #ffbb00', paddingLeft: 8}}>
                    <div>
                      <div style={{fontSize: 11, color: '#ffbb00'}}>{s.type}</div>
                      <code style={{fontSize: 10, display: 'block', background: '#000', padding: 2, wordBreak: 'break-all'}}>{s.value}</code>
                    </div>
                 </div>
               ))}
            </div>
          </div>
        )}

        {activeTab === 'network' && (
          <div className="tab-pane">
             {currentOrigin && (
                <div style={{fontSize: 10, color: '#8b949e', marginBottom: 5, display: 'flex', justifyContent: 'space-between'}}>
                   <span>Tracking Site: {currentOrigin}</span>
                   <Trash size={12} style={{cursor: 'pointer'}} onClick={clearSiteData} />
                </div>
            )}
            <SectionHeader title="Network Resources (Site)" count={networkLogs.length} color="var(--accent-secondary)" />
            <div className="card list-container" style={{maxHeight: '400px'}}>
              {networkLogs.length === 0 ? <EmptyMsg msg="Refresh page to capture requests." /> : networkLogs.map((log: any, n: number) => (
                <div key={n} className="list-item">
                  <div style={{flex: 1, overflow: 'hidden'}}>
                    <div style={{fontSize: 11, whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden'}}>{log.url}</div>
                    <div style={{fontSize: 9, color: '#8b949e'}}>{log.type.toUpperCase()} | {log.method}</div>
                  </div>
                  {(log.type === 'script' || log.url.includes('.js')) && (
                    <button 
                      className="badge-btn" 
                      onClick={() => handleNetworkScan(log.url)}
                      disabled={isScanning}
                    >
                      SCAN
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'live' && (
          <div className="tab-pane">
            <SectionHeader title="Runtime Events (Hooked)" count={runtimeEvents.length} color="#00ff9d" />
            <div className="card list-container" style={{maxHeight: '450px'}}>
              {runtimeEvents.length === 0 ? <EmptyMsg msg="Waiting for hooked events..." /> : runtimeEvents.map((ev: any, n: number) => (
                <div key={n} className="list-item" style={{borderLeft: `2px solid ${ev.type === 'sink_usage' ? '#ff00ff' : '#00ff9d'}`, paddingLeft: 8, flexDirection: 'column', alignItems: 'flex-start'}}>
                   <div style={{display: 'flex', justifyContent: 'space-between', width: '100%', marginBottom: 4}}>
                      <span className="badge" style={{background: ev.type === 'sink_usage' ? '#ff00ff' : '#21262d'}}>{ev.type.toUpperCase()}</span>
                      <span style={{fontSize: 9, color: '#8b949e'}}>{new Date(ev.timeStamp).toLocaleTimeString()}</span>
                   </div>
                   {ev.type === 'event_listener' && (
                     <div style={{fontSize: 11}}>
                        <div style={{color: '#00ff9d'}}>{ev.eventType} on {ev.element}</div>
                        <code style={{fontSize: 9, opacity: 0.7, display: 'block', marginTop: 2}}>{ev.listener}</code>
                     </div>
                   )}
                   {ev.type === 'dynamic_request' && (
                     <div style={{fontSize: 11, wordBreak: 'break-all'}}>
                        <strong>{ev.method}</strong>: {ev.url}
                     </div>
                   )}
                   {ev.type === 'sink_usage' && (
                     <div style={{fontSize: 11}}>
                        <div style={{color: '#ff00ff'}}>Sink Call: {ev.data?.type || 'unknown'}</div>
                        <code style={{fontSize: 9, display: 'block', background: '#300', padding: 2}}>{ev.content}</code>
                     </div>
                   )}
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'forms' && (
           <div className="tab-pane">
              <SectionHeader title="Forms Analysis" count={foundForms.length} color="#44ffaa" />
              <div className="card list-container">
                 {foundForms.length === 0 ? <EmptyMsg msg="Run Recon to find forms." /> : foundForms.map((f: any, n: number) => (
                   <div key={n} className="card" style={{marginBottom: 10, background: '#161b22'}}>
                      <div style={{fontSize: 12, fontWeight: 'bold', color: '#44ffaa'}}>{f.method.toUpperCase()} {f.action}</div>
                      <div style={{fontSize: 10, margin: '5px 0'}}>
                         {f.issues.map((iss: string, i: number) => (
                           <div key={i} style={{color: '#ff4444'}}>⚠️ {iss}</div>
                         ))}
                      </div>
                      <div style={{maxHeight: 100, overflow: 'auto', background: '#0d1117', padding: 5, borderRadius: 4}}>
                         {f.inputs.map((inpt: any, i: number) => (
                           <div key={i} style={{fontSize: 10, color: '#8b949e'}}>{inpt.name} ({inpt.type}) = {inpt.value}</div>
                         ))}
                      </div>
                      <button className="badge-btn" style={{marginTop: 8, width: '100%'}} onClick={() => {
                        const raw = formToRawRequest(f, window.location.host);
                        setPayload(raw);
                        setActiveTab('workbench');
                      }}>Copy as Raw Request</button>
                   </div>
                 ))}
              </div>
           </div>
        )}

        {activeTab === 'history' && (
          <div className="tab-pane">
             <SectionHeader title="Saved Scans" count={history.length} color="#8b949e" />
             <div className="card list-container">
                {history.length === 0 ? <EmptyMsg msg="No saved scans yet." /> : history.map((h: any, n: number) => (
                  <div key={n} className="list-item" style={{flexDirection: 'column', alignItems: 'flex-start'}}>
                     <div style={{display: 'flex', justifyContent: 'space-between', width: '100%'}}>
                        <strong style={{fontSize: 12}}>{h.url}</strong>
                        <Trash2 size={12} style={{cursor: 'pointer', color: '#ff4444'}} onClick={async () => { await db.deleteScan(h.id!); loadHistory(); }} />
                     </div>
                     <div style={{fontSize: 10, color: '#8b949e'}}>{new Date(h.timestamp).toLocaleString()}</div>
                     <button className="badge-btn" style={{marginTop: 5}} onClick={() => {
                        setHiddenElements(h.data.hidden || []);
                        setDisabledElements(h.data.disabled || []);
                        setFoundSecrets(h.data.secrets || []);
                        setFoundForms(h.data.forms || []);
                        setActiveTab('recon');
                        addLog(`Loaded scan from ${new Date(h.timestamp).toLocaleTimeString()}`);
                     }}>LOAD DATA</button>
                  </div>
                ))}
             </div>
          </div>
        )}

        {activeTab === 'workbench' && (
          <div className="tab-pane" style={{display: 'flex', flexDirection: 'column', height: '100%'}}>
            <div className="editor-container">
              <div className="editor-header">EDITOR <Trash2 size={12} onClick={() => setPayload('')} style={{cursor: 'pointer'}} /></div>
              <textarea className="editor-textarea" value={payload} onChange={(e) => setPayload(e.target.value)} placeholder="// Payload..."/>
              <button className="btn-primary" style={{borderRadius: 0}} onClick={runPayload}>EXECUTE</button>
            </div>
            <div className="console-output">
              {logs.map((log: string, i: number) => <div key={i} className="log-line">{log}</div>)}
            </div>
          </div>
        )}

        {activeTab === 'library' && (
          <div className="tab-pane">
            {DEFAULT_SNIPPETS.map(snip => (
              <div key={snip.id} className="card snippet-card" onClick={() => { setPayload(snip.code); setActiveTab('workbench'); }}>
                <div style={{display: 'flex', justifyContent: 'space-between'}}>
                  <strong>{snip.title}</strong>
                  <span className="badge">{snip.chapter}</span>
                </div>
                <pre>{snip.code.substring(0, 60)}...</pre>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

const SectionHeader = ({title, count, color}: any) => (
  <div style={{display: 'flex', alignItems: 'center', gap: 8, margin: '15px 0 5px 5px'}}>
    <div style={{width: 3, height: 14, background: color}}></div>
    <span style={{fontSize: 12, fontWeight: 800, color: '#eee'}}>{title.toUpperCase()} ({count})</span>
  </div>
);

const EmptyMsg = ({msg = 'Nothing found yet.'}: {msg?: string}) => (
  <p style={{fontSize: 11, color: '#666', textAlign: 'center', margin: '20px 0'}}>{msg}</p>
);

export default App;
