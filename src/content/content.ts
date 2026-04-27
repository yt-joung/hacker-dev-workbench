// [HackerDev] Content script listener
import hookUrl from './hook?script';

if (!(window as any).hackerDevLoaded) {
  (window as any).hackerDevLoaded = true;

  // CSS Animations Inject
  const style = document.createElement('style');
  style.id = 'hacker-dev-styles';
  style.textContent = `
    @keyframes hackerPulse {
      0% { box-shadow: 0 0 5px #ff00ff, inset 0 0 5px #ff00ff; border-color: #ff00ff; }
      50% { box-shadow: 0 0 20px #ff00ff, inset 0 0 10px #ff00ff; border-color: #ff00ff; }
      100% { box-shadow: 0 0 5px #ff00ff, inset 0 0 5px #ff00ff; border-color: #ff00ff; }
    }
    @keyframes hackerPulseGreen {
      0% { box-shadow: 0 0 5px #00ff9d, inset 0 0 5px #00ff9d; border-color: #00ff9d; }
      50% { box-shadow: 0 0 20px #00ff9d, inset 0 0 10px #00ff9d; border-color: #00ff9d; }
      100% { box-shadow: 0 0 5px #00ff9d, inset 0 0 5px #00ff9d; border-color: #00ff9d; }
    }
    .hacker-label {
      position: absolute;
      background: #ff00ff;
      color: white;
      font-family: monospace;
      font-size: 10px;
      font-weight: bold;
      padding: 2px 6px;
      border-radius: 0 0 4px 4px;
      z-index: 2147483647;
      pointer-events: none;
      text-transform: uppercase;
      box-shadow: 0 2px 10px rgba(0,0,0,0.5);
    }
    .hacker-label-green { background: #00ff9d; color: #000; }
    .hacker-reveal-active { animation: hackerPulse 1.5s infinite !important; transition: all 0.3s ease !important; z-index: 2147483646 !important; }
    .hacker-reveal-green-active { animation: hackerPulseGreen 1.5s infinite !important; transition: all 0.3s ease !important; z-index: 2147483646 !important; }
  `;
  (document.head || document.documentElement).appendChild(style);

  // 1. Inject Hook Script
  const injectHook = () => {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL(hookUrl);
      script.onload = function (this: any) {
        this.remove();
      };
      (document.head || document.documentElement).appendChild(script);
    } catch (e) {
      console.error("[HackerDev] Hook injection failed:", e);
    }
  };
  injectHook();

  // 2. Relay Hook Messages to Background
  window.addEventListener("message", (event) => {
    // 컨텍스트가 무효화되었는지 확인 (확장 프로그램 재로드/업데이트 시)
    if (!chrome.runtime || !chrome.runtime.id) return;
    
    if (event.source !== window || !event.data) return;
    
    const isHackerDevMessage = 
      event.data.type === "HACKERDEV_HOOK" || 
      (typeof event.data.type === 'string' && event.data.type.startsWith("HACKERDEV_EVENT_"));

    if (!isHackerDevMessage) return;
    
    try {
      // Relay to background script
      chrome.runtime.sendMessage({
        action: "RUNTIME_EVENT",
        data: event.data.payload
      }).catch(() => {
          // Ignore errors when background is not ready
      });
    } catch (e) {
      // "Extension context invalidated" 등의 오류 방지
    }
  });

  const createLabel = (el: HTMLElement, text: string, type: 'pink' | 'green' = 'pink') => {
    const rect = el.getBoundingClientRect();
    const label = document.createElement('div');
    label.className = `hacker-label ${type === 'green' ? 'hacker-label-green' : ''} hacker-dev-element`;
    label.textContent = text;
    label.style.top = `${window.scrollY + rect.top - 18}px`;
    label.style.left = `${window.scrollX + rect.left}px`;
    document.body.appendChild(label);
    return label;
  };

  const removeLabels = () => {
    document.querySelectorAll('.hacker-dev-element').forEach(el => el.remove());
  };

  chrome.runtime.onMessage.addListener((request: any, _sender: chrome.runtime.MessageSender, sendResponse: (response?: any) => void) => {
    if (request.action === 'SCAN_PAGE') {
      const hiddenInputs = Array.from(document.querySelectorAll('input[type="hidden"]')).map((el: any) => ({
        name: el.name || 'unnamed',
        id: el.id || 'no-id',
        value: el.value,
        type: 'hidden'
      }));

      const disabledElements = Array.from(document.querySelectorAll('[disabled], [readonly]')).map((el: any) => ({
        tag: el.tagName,
        id: el.id || 'no-id',
        name: el.name || 'unnamed',
        type: el.hasAttribute('disabled') ? 'disabled' : 'readonly'
      }));

      sendResponse({ hiddenInputs, disabledElements });
    }

    if (request.action === 'TOGGLE_VISIBILITY') {
      const isVisible = request.isVisible;
      removeLabels();

      document.querySelectorAll('input[type="hidden"]').forEach((el: any) => {
        if (isVisible) {
          if (!el.dataset.oldType) el.dataset.oldType = el.type;
          el.type = 'text';
          el.classList.add('hacker-reveal-active');
          el.style.backgroundColor = 'rgba(255, 0, 255, 0.1)';
          el.style.color = '#ff00ff';
          el.style.padding = '4px';
          createLabel(el, `HIDDEN: ${el.name || 'unnamed'}`, 'pink');
        } else {
          el.type = el.dataset.oldType || 'hidden';
          el.classList.remove('hacker-reveal-active');
          el.style.backgroundColor = '';
          el.style.color = '';
        }
      });
      
      const cssHiddenSelectors = '[style*="display: none"], [style*="visibility: hidden"], [disabled], [readonly]';
      document.querySelectorAll(cssHiddenSelectors).forEach((el: any) => {
          if (isVisible) {
              if (el.style.display === 'none') {
                  el.dataset.oldDisplay = el.style.display;
                  el.style.display = 'block';
              }
              el.classList.add('hacker-reveal-green-active');
              createLabel(el, `${el.tagName}: ${el.hasAttribute('disabled') ? 'DISABLED' : 'REVEALED'}`, 'green');
          } else {
              if (el.dataset.oldDisplay) el.style.display = el.dataset.oldDisplay;
              el.classList.remove('hacker-reveal-green-active');
          }
      });
    }
    return true; 
  });
}
