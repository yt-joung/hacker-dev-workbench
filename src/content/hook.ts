/**
 * Main World Hook Script
 * 페이지의 메인 컨텍스트(Main World)에서 실행되어
 * 이벤트 리스너, 네트워크 요청, 보안 위협이 있는 함수들을 모니터링합니다.
 *
 * 2025-04 확장:
 *  - postMessage 수신 핸들러 origin 검증 여부 감지
 *  - innerHTML / outerHTML / insertAdjacentHTML sink 감지
 *  - setTimeout / setInterval 문자열 인자 감지
 *  - location 변경 감지 (오픈 리다이렉트)
 */

(function () {
    // ─────────── 유틸 ───────────
    function notify(type: string, data: any) {
        window.postMessage({
            type: "HACKERDEV_HOOK",
            payload: { type, data }
        }, "*");
    }

    // ─────────── 1. Event Listener Hooking ───────────
    const oldAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (this: EventTarget, type: string, listener: any, options?: any) {
        if (['click', 'submit', 'change', 'input', 'mouseover'].includes(type)) {
            try {
                const elementInfo = this instanceof Element
                    ? this.tagName.toLowerCase() + (this.id ? '#' + this.id : '') + (this.className ? '.' + String(this.className).split(' ').join('.') : '')
                    : 'window/document';

                const listenerStr = typeof listener === 'function'
                    ? listener.toString().substring(0, 150) + '...'
                    : '[Object Listener]';

                notify('event_listener', {
                    eventType: type,
                    element: elementInfo,
                    listener: listenerStr
                });
            } catch (e) { }
        }

        // ── postMessage 핸들러 origin 검증 여부 탐지 ──
        if (type === 'message') {
            try {
                const listenerSource = typeof listener === 'function' ? listener.toString() : '';
                const hasOriginCheck = /event\.origin|e\.origin|msg\.origin|message\.origin/.test(listenerSource);
                notify('postmessage_listener', {
                    element: this instanceof Element ? this.tagName : 'window/document',
                    listenerSnippet: listenerSource.substring(0, 300),
                    hasOriginCheck,
                    vulnId: hasOriginCheck ? null : 'postmessage_no_origin_check',
                    severity: hasOriginCheck ? 'info' : 'high'
                });
            } catch (e) { }
        }

        return oldAddEventListener.call(this, type, listener, options);
    };

    // ─────────── 2. Fetch API Hooking ───────────
    const oldFetch = window.fetch;
    window.fetch = function (this: Window, ...args: any[]) {
        try {
            const url = args[0] instanceof Request ? args[0].url : String(args[0]);
            const method = args[1]?.method || (args[0] instanceof Request ? args[0].method : 'GET');
            notify('dynamic_request', { type: 'fetch', url, method });
        } catch (e) { }
        return (oldFetch as any)(...args);
    };

    // ─────────── 3. XMLHttpRequest Hooking ───────────
    const oldXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (this: XMLHttpRequest, method: string, url: string | URL, ...args: any[]) {
        try {
            notify('dynamic_request', { type: 'xhr', url: String(url), method });
        } catch (e) { }
        return (oldXHROpen as any).apply(this, [method, url, ...args]);
    } as any;

    // ─────────── 4. Security Sinks Hooking ───────────

    // eval
    const oldEval = window.eval;
    window.eval = function (this: any, str: string) {
        notify('sink_usage', {
            vulnId: 'sink_eval',
            type: 'eval',
            content: typeof str === 'string' ? str.substring(0, 200) : '[Non-string eval]',
            location: document.location.href
        });
        return oldEval.call(this, str);
    };

    // document.write
    const oldWrite = document.write.bind(document);
    document.write = function (this: Document, ...args: any[]) {
        notify('sink_usage', {
            vulnId: 'sink_document_write',
            type: 'document.write',
            content: args.join('').substring(0, 200),
            location: document.location.href
        });
        return oldWrite(...args);
    };

    // innerHTML / outerHTML setter
    try {
        const injectHTMLSinkHook = (propName: 'innerHTML' | 'outerHTML') => {
            const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, propName);
            if (!descriptor || !descriptor.set) return;
            const originalSetter = descriptor.set;
            Object.defineProperty(Element.prototype, propName, {
                set(value: string) {
                    if (typeof value === 'string' && value.trim().length > 0) {
                        notify('sink_usage', {
                            vulnId: 'sink_innerhtml',
                            type: propName,
                            content: value.substring(0, 200),
                            element: this.tagName + (this.id ? '#' + this.id : ''),
                            location: document.location.href
                        });
                    }
                    return originalSetter.call(this, value);
                },
                get: descriptor.get,
                configurable: true,
            });
        };
        injectHTMLSinkHook('innerHTML');
        injectHTMLSinkHook('outerHTML');
    } catch (e) { }

    // insertAdjacentHTML
    try {
        const oldInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function (position: any, text: string) {
            notify('sink_usage', {
                vulnId: 'sink_innerhtml',
                type: 'insertAdjacentHTML',
                content: text.substring(0, 200),
                element: this.tagName + (this.id ? '#' + this.id : ''),
                location: document.location.href
            });
            return oldInsertAdjacentHTML.call(this, position, text);
        };
    } catch (e) { }

    // setTimeout / setInterval (문자열 인자)
    const _setTimeout = window.setTimeout;
    (window as any).setTimeout = function (handler: any, delay?: number, ...args: any[]) {
        if (typeof handler === 'string') {
            notify('sink_usage', {
                vulnId: 'sink_settimeout_string',
                type: 'setTimeout (string)',
                content: handler.substring(0, 200),
                location: document.location.href
            });
        }
        return _setTimeout(handler as any, delay, ...args);
    };
    const _setInterval = window.setInterval;
    (window as any).setInterval = function (handler: any, delay?: number, ...args: any[]) {
        if (typeof handler === 'string') {
            notify('sink_usage', {
                vulnId: 'sink_settimeout_string',
                type: 'setInterval (string)',
                content: handler.substring(0, 200),
                location: document.location.href
            });
        }
        return _setInterval(handler as any, delay, ...args);
    };

    // ─────────── 5. Location Change (Open Redirect) Hooking ───────────
    try {
    // history.pushState / replaceState
        const hookLocationMethod = (methodName: 'assign' | 'replace') => {
            const original = location[methodName].bind(location);
            (location as any)[methodName] = function (url: string) {
                notify('location_change', {
                    vulnId: 'open_redirect',
                    method: `location.${methodName}`,
                    toUrl: url,
                    fromUrl: location.href
                });
                return original(url);
            };
        };
        hookLocationMethod('assign');
        hookLocationMethod('replace');

        // location.href setter 후킹
        const locDescriptor = Object.getOwnPropertyDescriptor(window.location, 'href');
        if (locDescriptor && locDescriptor.set) {
            // location.href 는 보안 제약으로 재정의가 어려우므로 Proxy를 통해 감시
            // 대신 pushState / replaceState 를 후킹하여 SPA 라우팅 변화를 탐지
        }

        // history.pushState / replaceState
        const hookHistoryMethod = (methodName: 'pushState' | 'replaceState') => {
            const original = history[methodName].bind(history);
            (history as any)[methodName] = function (state: any, unused: string, url?: string | URL) {
                if (url) {
                    notify('location_change', {
                        vulnId: 'location_manipulation',
                        method: `history.${methodName}`,
                        toUrl: String(url),
                        fromUrl: location.href
                    });
                }
                return original(state, unused, url);
            };
        };
        hookHistoryMethod('pushState');
        hookHistoryMethod('replaceState');
    } catch (e) { }

    // ─────────── 6. postMessage 전송 후킹 (wildcard 탐지) ───────────
    const oldPostMessage = window.postMessage.bind(window);
    (window as any).postMessage = function (message: any, targetOrigin: string, ...rest: any[]) {
        // 내부 HackerDev 메시지는 무시
        if (message && message.type === 'HACKERDEV_HOOK') {
            return oldPostMessage(message, targetOrigin, ...rest);
        }
        if (targetOrigin === '*') {
            notify('sink_usage', {
                vulnId: 'postmessage_no_origin_check',
                type: 'postMessage (wildcard *)',
                content: JSON.stringify(message).substring(0, 200),
                location: document.location.href
            });
        }
        return oldPostMessage(message, targetOrigin, ...rest);
    };

    console.log("[HackerDev] Runtime Hooks Installed (v2 - Extended).");
})();
