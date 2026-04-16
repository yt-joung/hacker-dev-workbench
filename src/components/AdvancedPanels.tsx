/**
 * 고급 진단 패널 컴포넌트 모음
 * - RepeaterPanel  : HTTP 요청 인터셉트/재전송 + JWT 자동 감지
 * - JwtPanel       : JWT 디코딩 / 조작 / 공격 페이로드 생성
 * - JsViewerPanel  : JS 소스 뷰어 + 민감 키워드 탐색
 * - FrameworkPanel : Vue.js / React 내부 상태 탐색기
 */

import { useState } from 'react';
import { Send, Copy, Search, Zap, ChevronDown, ChevronRight } from 'lucide-react';
import {
  decodeJwt, isJwtLike, buildAlgNoneJwt, tamperExp, tamperRole,
  buildModifiedJwt, summarizeJwt,
  type JwtDecoded
} from '../utils/jwt';
import { beautifyJs, searchInCode, searchSensitiveKeywords, type CodeSearchResult } from '../utils/beautify';

// ─────────────────────────────────────────────────────────
//  공통 타입
// ─────────────────────────────────────────────────────────
interface PanelProps {
  networkLogs: any[];
  addLog: (msg: string) => void;
  addVuln?: (id: string, loc: string, ev: string, detail?: string) => void;
  currentOrigin?: string;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ff0033', high: '#ff6600', medium: '#ffbb00', low: '#8b949e',
};

// ─────────────────────────────────────────────────────────
//  1. Request Repeater Panel
// ─────────────────────────────────────────────────────────
interface RepResponse {
  status?: number; statusText?: string;
  headers?: Record<string, string>; body?: string;
  time?: number; error?: string;
}

export function RepeaterPanel({ networkLogs, addLog, addVuln }: PanelProps) {
  const [reqUrl, setReqUrl] = useState('');
  const [method, setMethod] = useState('POST');
  const [headersText, setHeadersText] = useState(
    'Content-Type: application/json\nAccept: application/json, */*'
  );
  const [body, setBody] = useState('');
  const [resp, setResp] = useState<RepResponse | null>(null);
  const [sending, setSending] = useState(false);
  const [detectedJwt, setDetectedJwt] = useState('');
  const [subTab, setSubTab] = useState<'req' | 'resp'>('req');
  const [respCount, setRespCount] = useState(0);            // history counter

  const loadFromLog = (log: any) => {
    setReqUrl(log.url);
    setMethod(log.method || 'GET');
    addLog(`Repeater: ${log.url} 로드됨`);
  };

  /** 페이지 컨텍스트에서 fetch 실행 (same-origin CORS 우회, 세션 쿠키 포함) */
  const sendRequest = async () => {
    if (!reqUrl) return;
    setSending(true);
    const t0 = Date.now();
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) { addLog('❌ 활성 탭 없음'); return; }

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: async (url: string, meth: string, hdrsStr: string, bodyStr: string) => {
          try {
            const hdrs: Record<string, string> = {};
            hdrsStr.split('\n').forEach(line => {
              const idx = line.indexOf(':');
              if (idx > 0) hdrs[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
            });
            const opts: RequestInit = { method: meth, headers: hdrs, credentials: 'include' };
            if (!['GET', 'HEAD'].includes(meth) && bodyStr) opts.body = bodyStr;
            const r = await fetch(url, opts);
            const text = await r.text();
            const rh: Record<string, string> = {};
            r.headers.forEach((v: string, key: string) => { rh[key] = v; });
            return { status: r.status, statusText: r.statusText, headers: rh, body: text };
          } catch (e: any) { return { error: e.message }; }
        },
        args: [reqUrl, method, headersText, body],
      });

      const elapsed = Date.now() - t0;
      const result = { ...(results[0].result as RepResponse), time: elapsed };
      setResp(result);
      setRespCount(c => c + 1);
      setSubTab('resp');
      addLog(`Repeater: ${method} ${reqUrl} → ${result.status ?? 'ERR'} (${elapsed}ms)`);

      // JWT 자동 감지
      const allText =
        (result.body || '') +
        Object.values(result.headers || {}).join(' ');
      const matches = allText.match(/eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/g);
      if (matches?.[0]) {
        setDetectedJwt(matches[0]);
        addLog('🔑 JWT 토큰이 응답에서 감지되었습니다! JWT 탭에서 분석하세요.');
      }

      // 401 취약점 기록
      if (result.status === 401 && addVuln) {
        addVuln(
          'postmessage_no_origin_check',
          reqUrl,
          `401 응답. 토큰 재사용/변조 테스트 필요.`,
          `Repeater 전송 결과`
        );
      }
    } catch (e: any) {
      setResp({ error: e.message, time: Date.now() - t0 });
      addLog(`❌ Repeater 오류: ${e.message}`);
    } finally { setSending(false); }
  };

  const statusColor = (s?: number) =>
    !s ? '#8b949e' : s < 300 ? '#00ff9d' : s < 400 ? '#ffbb00' : '#ff4444';

  return (
    <div className="tab-pane">
      {/* Sub-tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 10 }}>
        {(['req', 'resp'] as const).map(t => (
          <button key={t} className="badge-btn"
            style={{ flex: 1, background: subTab === t ? 'rgba(0,255,157,0.15)' : '' }}
            onClick={() => setSubTab(t)}>
            {t === 'req' ? '📤 요청 편집' : `📥 응답 ${respCount > 0 ? `(${respCount})` : ''}`}
          </button>
        ))}
      </div>

      {/* ─── REQUEST EDITOR ─── */}
      {subTab === 'req' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {/* 네트워크 로그에서 불러오기 */}
          {networkLogs.length > 0 && (
            <>
              <div style={{ fontSize: 10, color: '#8b949e' }}>🔗 NET 로그에서 불러오기</div>
              <select className="storage-input"
                onChange={e => { const l = networkLogs[+e.target.value]; if (l) loadFromLog(l); }}>
                <option value="">-- 캡처된 요청 선택 --</option>
                {networkLogs.slice(0, 40).map((log, i) => (
                  <option key={i} value={i}>{log.method} {log.url.substring(0, 70)}</option>
                ))}
              </select>
            </>
          )}

          {/* Method + URL */}
          <div style={{ display: 'flex', gap: 6 }}>
            <select className="storage-input" style={{ width: 90, flexShrink: 0 }}
              value={method} onChange={e => setMethod(e.target.value)}>
              {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].map(m => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <input className="storage-input" style={{ flex: 1 }} value={reqUrl}
              onChange={e => setReqUrl(e.target.value)}
              placeholder="https://portal.kosha.or.kr/api/compn24/auth/token/refresh" />
          </div>

          {/* Headers */}
          <div>
            <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 3 }}>헤더 (Header)</div>
            <textarea className="editor-textarea"
              style={{ height: 80, width: '100%', boxSizing: 'border-box', background: '#0d1117', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)', padding: 8, fontSize: 11 }}
              value={headersText} onChange={e => setHeadersText(e.target.value)}
              placeholder="Content-Type: application/json&#10;Authorization: Bearer eyJ..." />
          </div>

          {/* Body */}
          {!['GET', 'HEAD'].includes(method) && (
            <div>
              <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 3 }}>바디 (Body / Payload)</div>
              <textarea className="editor-textarea"
                style={{ height: 90, width: '100%', boxSizing: 'border-box', background: '#0d1117', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)', padding: 8, fontSize: 11 }}
                value={body} onChange={e => setBody(e.target.value)}
                placeholder='{"refreshToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI..."}' />
            </div>
          )}

          <button className="btn-primary" style={{ marginTop: 4 }} onClick={sendRequest} disabled={sending || !reqUrl}>
            <Send size={13} style={{ marginRight: 6 }} />
            {sending ? '전송 중...' : '요청 전송 (페이지 세션 포함)'}
          </button>
          <div style={{ fontSize: 9, color: '#444', textAlign: 'center' }}>
            ℹ️ 페이지 컨텍스트에서 실행 → 동일 Origin CORS 우회, 쿠키 자동 포함
          </div>

          {detectedJwt && (
            <div className="card" style={{ padding: '8px 12px', borderLeft: '3px solid #ffbb00' }}>
              <div style={{ fontSize: 10, color: '#ffbb00', marginBottom: 4 }}>🔑 이전 응답에서 JWT 감지!</div>
              <code style={{ fontSize: 8, wordBreak: 'break-all', color: '#ccc' }}>{detectedJwt.substring(0, 60)}...</code>
            </div>
          )}
        </div>
      )}

      {/* ─── RESPONSE VIEWER ─── */}
      {subTab === 'resp' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {!resp ? (
            <p style={{ textAlign: 'center', color: '#555', fontSize: 11, marginTop: 30 }}>
              요청 탭에서 전송하면 여기에 응답이 표시됩니다.
            </p>
          ) : resp.error ? (
            <div className="card" style={{ borderLeft: '3px solid #ff4444' }}>
              <div style={{ color: '#ff4444', fontSize: 11 }}>⚠️ {resp.error}</div>
              <div style={{ fontSize: 9, color: '#555', marginTop: 4 }}>({resp.time}ms)</div>
            </div>
          ) : (
            <>
              {/* 상태 코드 */}
              <div className="card" style={{ padding: '8px 14px', borderLeft: `3px solid ${statusColor(resp.status)}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 20, fontWeight: 800, color: statusColor(resp.status) }}>
                    {resp.status} {resp.statusText}
                  </span>
                  <span style={{ fontSize: 10, color: '#555' }}>{resp.time}ms</span>
                </div>
                {resp.status === 401 && (
                  <div style={{ fontSize: 10, color: '#ffaa00', marginTop: 4 }}>
                    ⚠️ 진단 포인트: 토큰 재사용/변조/IDOR 테스트 권장 → 요청을 수정하세요
                  </div>
                )}
              </div>

              {/* 응답 헤더 */}
              {resp.headers && (
                <details>
                  <summary style={{ fontSize: 10, color: '#8b949e', cursor: 'pointer', userSelect: 'none' }}>
                    응답 헤더 ({Object.keys(resp.headers).length}개)
                  </summary>
                  <div className="card" style={{ marginTop: 4, padding: '6px 10px' }}>
                    {Object.entries(resp.headers).map(([k, v]) => (
                      <div key={k} style={{ fontSize: 9, padding: '1px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <span style={{ color: '#00d4ff' }}>{k}:</span> {v}
                      </div>
                    ))}
                  </div>
                </details>
              )}

              {/* 응답 바디 */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <div style={{ fontSize: 10, color: '#8b949e', fontWeight: 700 }}>응답 바디</div>
                  <button className="badge-btn" style={{ fontSize: 8 }}
                    onClick={() => navigator.clipboard.writeText(resp.body || '')}>
                    <Copy size={9} /> 복사
                  </button>
                </div>
                <pre style={{
                  background: '#0d1117', padding: 10, borderRadius: 6, fontSize: 10,
                  color: '#ccc', overflow: 'auto', maxHeight: 260, margin: 0,
                  whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  border: '1px solid rgba(255,255,255,0.08)'
                }}>
                  {(() => { try { return JSON.stringify(JSON.parse(resp.body || ''), null, 2); } catch { return resp.body || '(비어 있음)'; } })()}
                </pre>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────
//  2. JWT Inspector Panel
// ─────────────────────────────────────────────────────────
export function JwtPanel({ addLog, addVuln }: PanelProps) {
  const [input, setInput] = useState('');
  const [decoded, setDecoded] = useState<JwtDecoded | null>(null);
  const [headerEdit, setHeaderEdit] = useState('');
  const [payloadEdit, setPayloadEdit] = useState('');
  const [output, setOutput] = useState<{ label: string; value: string }[]>([]);

  const analyze = (token: string) => {
    const d = decodeJwt(token.trim());
    setDecoded(d);
    if (d) {
      setHeaderEdit(JSON.stringify(d.header, null, 2));
      setPayloadEdit(JSON.stringify(d.payload, null, 2));
      const s = summarizeJwt(d);
      if (s.isExpired) addLog(`🔴 JWT 만료됨: ${s.expiry}`);
      else addLog(`🟢 JWT 유효: 만료까지 ${Math.floor(s.secsLeft / 3600)}시간`);
    }
  };

  const push = (label: string, value: string) => {
    setOutput(o => [{ label, value }, ...o].slice(0, 10));
    navigator.clipboard.writeText(value);
    addLog(`✅ ${label} 생성 및 클립보드 복사 완료`);
    if (addVuln) {
      addVuln('sink_eval', `JWT 공격: ${label}`, value.substring(0, 80), '조작된 JWT 생성');
    }
  };

  const doAlgNone = () => {
    if (!decoded) return;
    const variants = buildAlgNoneJwt(decoded);
    push('alg:none 공격 JWT (4가지 변형)', variants.join(',\n'));
    addLog('⚔️ alg:none 공격 페이로드 생성 - 서버가 서명 없는 JWT를 수락하는지 테스트하세요');
  };

  const doTamperExp = () => {
    if (!decoded) return;
    push('만료시간 연장 JWT (+1년, 원본 서명 유지)', tamperExp(decoded));
    addLog('⏰ 만료시간 연장 JWT 생성 - 서버가 exp를 재검증하는지 테스트하세요');
  };

  const doTamperRole = () => {
    if (!decoded) return;
    push('권한 상승 JWT (role=admin, isAdmin=true)', tamperRole(decoded));
    addLog('🔑 권한 상승 JWT 생성 - 서버가 payload를 신뢰하는지 테스트하세요');
  };

  const doBuildModified = () => {
    try {
      const h = JSON.parse(headerEdit);
      const p = JSON.parse(payloadEdit);
      push('수동 편집 JWT (서명 제거)', buildModifiedJwt(h, p));
    } catch (e: any) { addLog('⚠️ JSON 파싱 오류: ' + e.message); }
  };

  const summary = decoded ? summarizeJwt(decoded) : null;

  return (
    <div className="tab-pane">
      <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 4 }}>JWT 토큰 입력 (Bearer eyJ... 포함 가능)</div>
      <textarea className="editor-textarea"
        style={{ height: 55, width: '100%', boxSizing: 'border-box', background: '#0d1117', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)', padding: 8, fontSize: 10 }}
        value={input}
        onChange={e => { setInput(e.target.value); analyze(e.target.value); }}
        placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature" />

      {!decoded && input.length > 10 && (
        <div style={{ fontSize: 10, color: '#ff4444', marginTop: 4 }}>⚠️ JWT 형식이 아닙니다 (헤더.페이로드.서명 형식 필요)</div>
      )}

      {summary && (
        <>
          {/* 요약 카드 */}
          <div className="card" style={{ marginTop: 10, padding: '8px 12px', borderLeft: `3px solid ${summary.isExpired ? '#ff4444' : '#00ff9d'}` }}>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', fontSize: 10 }}>
              <span>알고리즘: <strong style={{ color: summary.alg === 'none' ? '#ff0033' : '#00d4ff' }}>{summary.alg}</strong></span>
              {summary.sub && <span>Subject: <strong>{summary.sub}</strong></span>}
              {summary.iss && <span>Issuer: <strong>{summary.iss}</strong></span>}
              {summary.role && <span style={{ color: '#ff00ff' }}>Role: <strong>{summary.role}</strong></span>}
              {summary.expiry && (
                <span style={{ color: summary.isExpired ? '#ff4444' : '#00ff9d' }}>
                  만료: {summary.expiry} {summary.isExpired ? '🔴 만료됨' : `🟢 (${Math.floor(summary.secsLeft / 3600)}h 남음)`}
                </span>
              )}
            </div>
          </div>

          {/* Header Edit */}
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 10, color: '#00d4ff', fontWeight: 700, marginBottom: 3 }}>헤더 (Header) - 편집 가능</div>
            <textarea className="editor-textarea"
              style={{ height: 65, width: '100%', boxSizing: 'border-box', background: '#0d1117', borderRadius: 6, border: '1px solid rgba(0,212,255,0.3)', padding: 8, fontSize: 10 }}
              value={headerEdit} onChange={e => setHeaderEdit(e.target.value)} />
          </div>

          {/* Payload Edit */}
          <div style={{ marginTop: 6 }}>
            <div style={{ fontSize: 10, color: '#00ff9d', fontWeight: 700, marginBottom: 3 }}>페이로드 (Payload) - 편집 가능</div>
            <textarea className="editor-textarea"
              style={{ height: 100, width: '100%', boxSizing: 'border-box', background: '#0d1117', borderRadius: 6, border: '1px solid rgba(0,255,157,0.3)', padding: 8, fontSize: 10 }}
              value={payloadEdit} onChange={e => setPayloadEdit(e.target.value)} />
          </div>

          {/* Attack Buttons */}
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>
            <button className="badge-btn" style={{ background: 'rgba(255,0,0,0.1)', borderColor: '#ff0033', color: '#ff0033', flex: 1 }}
              onClick={doAlgNone}>⚔️ alg:none</button>
            <button className="badge-btn" style={{ borderColor: '#ffbb00', color: '#ffbb00', flex: 1 }}
              onClick={doTamperExp}>⏰ exp 연장</button>
            <button className="badge-btn" style={{ borderColor: '#ff00ff', color: '#ff00ff', flex: 1 }}
              onClick={doTamperRole}>👑 권한 상승</button>
            <button className="badge-btn" style={{ flex: 1 }}
              onClick={doBuildModified}>🔧 수동 편집 재생성</button>
          </div>

          {/* 생성된 페이로드 목록 */}
          {output.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 10, color: '#8b949e', fontWeight: 700, marginBottom: 5 }}>생성된 공격 페이로드 (클릭하여 복사)</div>
              {output.map((o, i) => (
                <div key={i} className="card" style={{ padding: '6px 10px', marginBottom: 6, cursor: 'pointer', borderLeft: '2px solid #ff4444' }}
                  onClick={() => navigator.clipboard.writeText(o.value)}>
                  <div style={{ fontSize: 9, color: '#ff6600', marginBottom: 3 }}>{o.label}</div>
                  <code style={{ fontSize: 8, wordBreak: 'break-all', color: '#ccc' }}>{o.value.substring(0, 120)}...</code>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────
//  3. JS Source Viewer Panel
// ─────────────────────────────────────────────────────────
export function JsViewerPanel({ networkLogs, addLog, addVuln }: PanelProps) {
  const [url, setUrl] = useState('');
  const [, setRawCode] = useState('');
  const [fmtCode, setFmtCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<{ lineNumber: number; lineContent: string }[]>([]);
  const [sensitiveResults, setSensitiveResults] = useState<CodeSearchResult[]>([]);
  const [viewMode, setViewMode] = useState<'code' | 'sensitive' | 'search'>('sensitive');

  const fetchSource = async (targetUrl: string) => {
    if (!targetUrl) return;
    setLoading(true);
    setRawCode(''); setFmtCode(''); setSensitiveResults([]); setSearchResults([]);

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: async (u: string) => {
          try {
            const r = await fetch(u, { credentials: 'include' });
            return await r.text();
          } catch (e: any) { return `ERROR: ${e.message}`; }
        },
        args: [targetUrl],
      });

      const code = results[0].result as string;
      if (code.startsWith('ERROR:')) {
        addLog(`❌ 소스 가져오기 실패: ${code}`);
        setLoading(false); return;
      }

      setRawCode(code);
      const formatted = beautifyJs(code);
      setFmtCode(formatted);

      // 민감 키워드 자동 스캔
      const sensitive = searchSensitiveKeywords(formatted);
      setSensitiveResults(sensitive);

      addLog(`📄 JS 소스 로드: ${targetUrl.split('/').pop()} (${(code.length / 1024).toFixed(1)}KB, 민감 키워드 ${sensitive.length}개)`);

      sensitive
        .filter(r => r.severity === 'critical')
        .slice(0, 5)
        .forEach(r => {
          if (addVuln) addVuln('exposed_api_key', `${targetUrl}:L${r.lineNumber}`, r.lineContent, r.reason);
        });

      setViewMode('sensitive');
    } catch (e: any) {
      addLog(`❌ JS 뷰어 오류: ${e.message}`);
    } finally { setLoading(false); }
  };

  const doSearch = () => {
    if (!searchQuery || !fmtCode) return;
    const results = searchInCode(fmtCode, searchQuery, false);
    setSearchResults(results);
    setViewMode('search');
    addLog(`🔍 "${searchQuery}" 검색: ${results.length}개 결과`);
  };

  const jsNetLogs = networkLogs.filter(l => l.url?.includes('.js'));

  return (
    <div className="tab-pane">
      {/* URL 입력 */}
      <div style={{ marginBottom: 8 }}>
        {jsNetLogs.length > 0 && (
          <select className="storage-input" style={{ marginBottom: 6 }}
            onChange={e => { if (e.target.value) { setUrl(e.target.value); fetchSource(e.target.value); } }}>
            <option value="">-- NET 로그에서 JS 파일 선택 --</option>
            {jsNetLogs.slice(0, 30).map((l, i) => (
              <option key={i} value={l.url}>{l.url.split('/').pop()?.substring(0, 60)}</option>
            ))}
          </select>
        )}
        <div style={{ display: 'flex', gap: 6 }}>
          <input className="storage-input" style={{ flex: 1 }} value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://example.com/assets/index-CEG0pUJD.js" />
          <button className="badge-btn" style={{ flexShrink: 0 }} onClick={() => fetchSource(url)} disabled={loading}>
            {loading ? '로드 중...' : '📥 가져오기'}
          </button>
        </div>
      </div>

      {fmtCode && (
        <>
          {/* 검색 */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
            <input className="storage-input" style={{ flex: 1 }} value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && doSearch()}
              placeholder="refresh, token, admin, eval... (Enter)" />
            <button className="badge-btn" onClick={doSearch}><Search size={11} /></button>
          </div>

          {/* 뷰 모드 탭 */}
          <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
            {(['sensitive', 'search', 'code'] as const).map(m => (
              <button key={m} className="badge-btn"
                style={{ flex: 1, background: viewMode === m ? 'rgba(0,255,157,0.15)' : '' }}
                onClick={() => setViewMode(m)}>
                {m === 'sensitive' ? `⚠️ 민감 키워드 (${sensitiveResults.length})` : m === 'search' ? `🔍 검색결과 (${searchResults.length})` : '📝 전체 소스'}
              </button>
            ))}
          </div>

          {/* 민감 키워드 결과 */}
          {viewMode === 'sensitive' && (
            <div className="card list-container" style={{ maxHeight: 420 }}>
              {sensitiveResults.length === 0 ? (
                <p style={{ textAlign: 'center', color: '#555', fontSize: 11, margin: '20px 0' }}>민감 키워드 없음</p>
              ) : sensitiveResults.map((r, i) => (
                <div key={i} className="list-item" style={{ flexDirection: 'column', alignItems: 'flex-start', borderLeft: `2px solid ${SEVERITY_COLOR[r.severity]}`, paddingLeft: 8 }}>
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center', width: '100%', justifyContent: 'space-between' }}>
                    <span className="badge" style={{ background: SEVERITY_COLOR[r.severity], color: '#000', fontSize: 8 }}>{r.severity}</span>
                    <span style={{ fontSize: 9, color: '#00d4ff' }}>L{r.lineNumber}</span>
                    <span style={{ fontSize: 9, color: '#8b949e', flex: 1 }}>{r.reason}</span>
                  </div>
                  <code style={{ fontSize: 9, color: '#ccc', wordBreak: 'break-all', marginTop: 3, display: 'block', background: '#000', padding: '2px 6px', borderRadius: 3, width: '100%', boxSizing: 'border-box' }}>
                    {r.lineContent}
                  </code>
                </div>
              ))}
            </div>
          )}

          {/* 검색 결과 */}
          {viewMode === 'search' && (
            <div className="card list-container" style={{ maxHeight: 420 }}>
              {searchResults.length === 0 ? (
                <p style={{ textAlign: 'center', color: '#555', fontSize: 11, margin: '20px 0' }}>결과 없음</p>
              ) : searchResults.map((r, i) => (
                <div key={i} className="list-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                  <span style={{ fontSize: 9, color: '#00d4ff', marginBottom: 2 }}>L{r.lineNumber}</span>
                  <code style={{ fontSize: 9, color: '#ccc', wordBreak: 'break-all', background: '#000', padding: '2px 6px', borderRadius: 3, width: '100%', boxSizing: 'border-box' }}>
                    {r.lineContent.replace(new RegExp(searchQuery, 'gi'), m => `【${m}】`)}
                  </code>
                </div>
              ))}
            </div>
          )}

          {/* 전체 소스 */}
          {viewMode === 'code' && (
            <pre style={{ background: '#0d1117', padding: 10, borderRadius: 6, fontSize: 9, color: '#ccc', overflow: 'auto', maxHeight: 420, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', border: '1px solid rgba(255,255,255,0.08)' }}>
              {fmtCode}
            </pre>
          )}
        </>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────
//  4. Framework State Inspector (Vue / React)
// ─────────────────────────────────────────────────────────
interface FrameworkState {
  framework: 'vue' | 'react' | 'angular' | 'unknown';
  version?: string;
  stores: { name: string; data: any }[];
  globalVars: { name: string; value: any }[];
}

export function FrameworkPanel({ addLog, addVuln }: PanelProps) {
  const [result, setResult] = useState<FrameworkState | null>(null);
  const [scanning, setScanning] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const scan = async () => {
    setScanning(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          const w = window as any;
          const stores: { name: string; data: any }[] = [];
          let framework: string = 'unknown';
          let version: string | undefined;

          // ── Vue 3 감지 ──
          if (w.__vue_app__) {
            framework = 'vue';
            try { version = w.__vue_app__.version; } catch {}
            // Pinia store 탐색
            try {
              const pinia = w.__pinia;
              if (pinia?.state?.value) {
                Object.entries(pinia.state.value).forEach(([name, data]) => {
                  stores.push({ name: `Pinia: ${name}`, data });
                });
              }
            } catch {}
            // vuex store
            try {
              const vuex = w.__vue_app__.config?.globalProperties?.$store;
              if (vuex?.state) stores.push({ name: 'Vuex Store', data: vuex.state });
            } catch {}
            // app globals
            try {
              const globals = w.__vue_app__.config?.globalProperties;
              if (globals) {
                const safe: any = {};
                Object.keys(globals).forEach(k => {
                  if (!k.startsWith('$') || ['$route', '$router', '$store', '$t'].includes(k)) return;
                  try { safe[k] = typeof globals[k] === 'function' ? '[Function]' : globals[k]; } catch {}
                });
                if (Object.keys(safe).length) stores.push({ name: 'Vue Global Properties', data: safe });
              }
            } catch {}
          }

          // ── Vue 2 감지 ──
          if (framework === 'unknown') {
            const vueEl = document.querySelector('[data-v-app], [data-v]') as any;
            if (vueEl?.__vue__) {
              framework = 'vue';
              try { stores.push({ name: 'Vue 2 Root Instance', data: vueEl.__vue__.$data }); } catch {}
            }
          }

          // ── React 감지 ──
          if (framework === 'unknown') {
            const reactEl = document.querySelector('[data-reactroot]') ||
              Array.from(document.querySelectorAll('*')).find((el: any) => el._reactRootContainer || el.__reactFiber);
            if (reactEl) {
              framework = 'react';
              try {
                const fiber = (reactEl as any).__reactFiber || (reactEl as any)._reactInternals;
                if (fiber?.memoizedState) {
                  stores.push({ name: 'React Root State', data: JSON.parse(JSON.stringify(fiber.memoizedState, (_k: any, v: any) => typeof v === 'function' ? '[Function]' : v, 2)) });
                }
              } catch {}
            }
          }

          // 전역 변수 탐색 (보안 관련)
          const sensitiveKeys = ['token', 'user', 'auth', 'session', 'isAdmin', 'currentUser', 'userInfo', 'accessToken', 'refreshToken', 'role'];
          const globalVars: { name: string; value: any }[] = [];
          sensitiveKeys.forEach(key => {
            if (key in w && w[key] !== undefined && w[key] !== null) {
              try {
                globalVars.push({
                  name: key,
                  value: typeof w[key] === 'object' ? JSON.parse(JSON.stringify(w[key])) : w[key]
                });
              } catch {
                globalVars.push({ name: key, value: '[Circular/Unserializable]' });
              }
            }
          });

          return { framework, version, stores, globalVars };
        },
      });

      const state = results[0].result as FrameworkState;
      setResult(state);
      addLog(`🔍 프레임워크 감지: ${state.framework.toUpperCase()}${state.version ? ` v${state.version}` : ''}, Store ${state.stores.length}개, 전역변수 ${state.globalVars.length}개`);

      // 민감 전역변수 → 취약점 등록
      state.globalVars.forEach(g => {
        if (addVuln) addVuln('storage_sensitive_data', `window.${g.name}`, JSON.stringify(g.value).substring(0, 100), `${state.framework} 전역 변수에 민감 정보 노출`);
      });

      // Pinia/Vuex 토큰 탐색
      state.stores.forEach(s => {
        const str = JSON.stringify(s.data);
        if (/token|jwt|auth|password/i.test(str) && addVuln) {
          addVuln('storage_sensitive_data', `${s.name}`, str.substring(0, 100), '프레임워크 Store에 민감 정보 포함 가능');
        }
      });

    } catch (e: any) {
      addLog(`❌ 프레임워크 탐색 오류: ${e.message}`);
    } finally { setScanning(false); }
  };

  const toggle = (key: string) => setExpanded(e => ({ ...e, [key]: !e[key] }));

  const JsonView = ({ data, depth = 0 }: { data: any; depth?: number }) => {
    if (depth > 4) return <span style={{ color: '#555' }}>[...]</span>;
    if (data === null) return <span style={{ color: '#8b949e' }}>null</span>;
    if (typeof data === 'boolean') return <span style={{ color: '#ff6600' }}>{String(data)}</span>;
    if (typeof data === 'number') return <span style={{ color: '#00d4ff' }}>{data}</span>;
    if (typeof data === 'string') {
      const isToken = isJwtLike(data) || data.length > 30;
      return <span style={{ color: isToken ? '#ffbb00' : '#00ff9d' }}>"{data.substring(0, 80)}{data.length > 80 ? '...' : ''}"</span>;
    }
    if (typeof data === 'object') {
      const entries = Object.entries(data);
      if (entries.length === 0) return <span style={{ color: '#555' }}>{'{}'}</span>;
      return (
        <div style={{ marginLeft: 12 }}>
          {entries.map(([k, v]) => (
            <div key={k} style={{ marginBottom: 1 }}>
              <span style={{ color: '#8b949e', fontSize: 9 }}>{k}: </span>
              <JsonView data={v} depth={depth + 1} />
            </div>
          ))}
        </div>
      );
    }
    return <span style={{ color: '#ccc' }}>{String(data)}</span>;
  };

  return (
    <div className="tab-pane">
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
        <button className="btn-primary" style={{ flex: 1 }} onClick={scan} disabled={scanning}>
          <Zap size={13} style={{ marginRight: 6 }} />
          {scanning ? '탐색 중...' : '프레임워크 상태 탐색 시작'}
        </button>
      </div>
      <div style={{ fontSize: 9, color: '#444', marginBottom: 10, textAlign: 'center' }}>
        Vue.js Pinia/Vuex · React State · 전역 인증 변수 자동 탐색
      </div>

      {result && (
        <>
          {/* 프레임워크 배지 */}
          <div className="card" style={{ padding: '8px 12px', marginBottom: 10, borderLeft: `3px solid ${result.framework === 'unknown' ? '#555' : '#00ff9d'}` }}>
            <div style={{ fontSize: 13, fontWeight: 800, color: '#00ff9d' }}>
              {result.framework === 'vue' ? '🟢 Vue.js' : result.framework === 'react' ? '🔵 React' : result.framework === 'angular' ? '🔴 Angular' : '⚪ 알 수 없음'}
              {result.version && ` v${result.version}`}
            </div>
            <div style={{ fontSize: 10, color: '#8b949e', marginTop: 2 }}>
              Store {result.stores.length}개 | 전역변수 {result.globalVars.length}개 감지
            </div>
          </div>

          {/* 전역 인증 변수 */}
          {result.globalVars.length > 0 && (
            <>
              <div style={{ fontSize: 10, color: '#ff6600', fontWeight: 700, marginBottom: 5 }}>
                ⚠️ 전역 민감 변수 (window.*)
              </div>
              {result.globalVars.map((g, i) => (
                <div key={i} className="card" style={{ marginBottom: 6, padding: '8px 12px', borderLeft: '2px solid #ff6600' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <strong style={{ fontSize: 11, color: '#ff6600' }}>window.{g.name}</strong>
                    <button className="badge-btn" style={{ fontSize: 8 }}
                      onClick={() => navigator.clipboard.writeText(JSON.stringify(g.value))}>복사</button>
                  </div>
                  <div style={{ marginTop: 4, fontSize: 10 }}><JsonView data={g.value} /></div>
                </div>
              ))}
            </>
          )}

          {/* Store 상태 */}
          {result.stores.length > 0 && (
            <>
              <div style={{ fontSize: 10, color: '#8b949e', fontWeight: 700, marginTop: 10, marginBottom: 5 }}>
                📦 Store / 상태 ({result.stores.length})
              </div>
              {result.stores.map((s, i) => {
                const key = `store-${i}`;
                return (
                  <div key={i} className="card" style={{ marginBottom: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }} onClick={() => toggle(key)}>
                      <strong style={{ fontSize: 11 }}>
                        {expanded[key] ? <ChevronDown size={11} /> : <ChevronRight size={11} />} {s.name}
                      </strong>
                      <button className="badge-btn" style={{ fontSize: 8 }}
                        onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(JSON.stringify(s.data, null, 2)); }}>복사</button>
                    </div>
                    {expanded[key] && (
                      <div style={{ marginTop: 8, paddingLeft: 4, fontSize: 10 }}>
                        <JsonView data={s.data} />
                      </div>
                    )}
                  </div>
                );
              })}
            </>
          )}

          {result.stores.length === 0 && result.globalVars.length === 0 && (
            <p style={{ textAlign: 'center', color: '#555', fontSize: 11 }}>
              탐색된 데이터가 없습니다. 로그인 상태에서 재시도하세요.
            </p>
          )}
        </>
      )}
    </div>
  );
}
