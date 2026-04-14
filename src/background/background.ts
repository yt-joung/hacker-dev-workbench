import { SETTINGS } from '../config/settings';

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true })
    .catch((error) => console.error('[Background] Setup Error:', error));
  
  console.log('[HackerDev] Extension Ready - Click the icon to open sidepanel');
  
  chrome.storage.local.set({ networkLogs: {} });
});

// URL에서 origin (도메인) 추출
const getOrigin = (urlStr: string) => {
  try {
    return new URL(urlStr).origin;
  } catch (e) {
    return 'unknown_origin';
  }
};

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId <= 0) return;

    const { url, type, method, tabId, timeStamp, initiator } = details;
    
    if (['script', 'xmlhttprequest', 'other'].includes(type) || url.includes('.js') || url.includes('.ts')) {
      chrome.tabs.get(tabId, (tab) => {
        // 내부 chrome 탭 등인 경우 예외처리
        if (chrome.runtime.lastError || !tab.url || tab.url.startsWith('chrome://')) return;
        
        // 현재 탭의 URL 기반으로 Origin 계산
        const siteOrigin = getOrigin(tab.url);
        
        chrome.storage.local.get(['networkLogs'], (result) => {
          const logs = (result.networkLogs || {}) as Record<string, any[]>;
          if (!logs[siteOrigin]) logs[siteOrigin] = [];
          
          let shouldAdd = true;
          if (SETTINGS.EXCLUDE_DUPLICATE_URLS) {
            // 중복 방지 - 동일 URL이 이미 스캔 대상 목록에 있는지 확인
            shouldAdd = !logs[siteOrigin].find((l: any) => l.url === url);
          }
          
          if (shouldAdd) {
            logs[siteOrigin].unshift({ url, type, method, timeStamp, initiator });
            
            // 제한값 초과 시 오래된 로그 제거
            if (logs[siteOrigin].length > SETTINGS.MAX_NETWORK_LOGS_PER_SITE) {
              logs[siteOrigin].pop();
            }
            chrome.storage.local.set({ networkLogs: logs });
          }
        });
      });
    }
  },
  { urls: ["<all_urls>"] }
);

// Listen for Runtime Events (from Hook -> Content Script -> Background)
chrome.runtime.onMessage.addListener((request, sender) => {
  if (request.action === 'RUNTIME_EVENT') {
    const tabId = sender.tab?.id;
    const tabUrl = sender.tab?.url;
    
    if (tabId && tabUrl && !tabUrl.startsWith('chrome://')) {
      const siteOrigin = getOrigin(tabUrl);
      
      chrome.storage.local.get(['runtimeEvents'], (result) => {
        const events = (result.runtimeEvents || {}) as Record<string, any[]>;
        if (!events[siteOrigin]) events[siteOrigin] = [];
        
        events[siteOrigin].unshift({
          ...request.data,
          timeStamp: Date.now()
        });

        // Limit event logs
        if (events[siteOrigin].length > 100) {
          events[siteOrigin].pop();
        }
        
        chrome.storage.local.set({ runtimeEvents: events });
      });
    }
  }
  return true;
});

// 참고: 사용자 피드백에 따라 데이터를 탭 단위가 아닌 Site(Origin) 단위로 저장.
// 따라서 탭 종료 시 데이터를 날리지 않고 계속 유지합니다.
// chrome.tabs.onRemoved 리스너는 제거되었습니다.
