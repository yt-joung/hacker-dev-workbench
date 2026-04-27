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
    // ─────────── 0. Configuration & Utils ───────────
    const MSG_TYPE = "HACKERDEV_EVENT_" + Math.random().toString(36).substring(2, 10);
    
    // 네이티브 함수인 척 위장하기 (toString 우회)
    const originalToString = Function.prototype.toString;
    const fakeToString = function(this: any) {
        if (typeof this === 'function' && this.__hacker_original_name) {
            return `function ${this.__hacker_original_name}() { [native code] }`;
        }
        return originalToString.call(this);
    };
    
    function makeNative(fn: any, name: string) {
        try {
            Object.defineProperty(fn, '__hacker_original_name', { value: name, configurable: true });
            Object.defineProperty(fn, 'name', { value: name, configurable: true });
            if (Function.prototype.toString !== fakeToString) {
                Function.prototype.toString = fakeToString;
            }
        } catch(e) {}
        return fn;
    }

    // 알림 스로틀링 (너무 많은 메시지 방지)
    const recentLogs = new Set();
    function notify(type: string, data: any) {
        try {
            const logKey = `${type}:${JSON.stringify(data).substring(0, 100)}`;
            if (recentLogs.has(logKey)) return;
            recentLogs.add(logKey);
            setTimeout(() => recentLogs.delete(logKey), 1000);

            window.postMessage({
                type: MSG_TYPE,
                payload: { type, data }
            }, "*");
        } catch (e) {}
    }

    // ─────────── 0.1 SES/Lockdown Bypass ───────────
    // SES lockdown()이 실행되기 전에 주요 메서드들을 고정하거나 감시합니다.
    const oldDefineProperty = Object.defineProperty;
    const oldFreeze = Object.freeze;
    
    // 일부 사이트에서 lockdown() 시 프로토타입 수정을 차단하려고 할 때 우회
    (Object as any).defineProperty = makeNative(function(obj: any, prop: string, descriptor: PropertyDescriptor) {
        // SES가 우리가 설정한 configurable: true를 false로 바꾸려 할 때 등의 감지용
        return oldDefineProperty.call(Object, obj, prop, descriptor);
    }, 'defineProperty');

    (Object as any).freeze = makeNative(function(obj: any) {
        // SES가 특정 프로토타입을 얼리려 할 때 로그를 남기거나 무시할 수 있음 (현재는 통과)
        return oldFreeze.call(Object, obj);
    }, 'freeze');

    const oldGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    (Object as any).getOwnPropertyDescriptor = makeNative(function(obj: any, prop: string) {
        const desc = oldGetOwnPropertyDescriptor.call(Object, obj, prop);
        // SES나 다른 보안 스크립트가 우리 훅의 descriptor를 검사할 때 속임수
        if (desc && (obj === EventTarget.prototype || obj === window || obj === XMLHttpRequest.prototype)) {
             // 훅이 걸린 함수를 네이티브처럼 보이게 하거나 descriptor 위장 가능
        }
        return desc;
    }, 'getOwnPropertyDescriptor');

    // 통신 식별자를 전역에 살짝 남겨 content.ts가 읽게 함
    (window as any).__HACKERDEV_ID = MSG_TYPE;

    // ─────────── 1. Event Listener Hooking ───────────
    const oldAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = makeNative(function (this: EventTarget, type: string, listener: any, options?: any) {
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
    }, 'addEventListener');

    // ─────────── 2. Fetch API Hooking ───────────
    const oldFetch = window.fetch;
    window.fetch = makeNative(function (this: Window, ...args: any[]) {
        try {
            const url = args[0] instanceof Request ? args[0].url : String(args[0]);
            const method = args[1]?.method || (args[0] instanceof Request ? args[0].method : 'GET');
            notify('dynamic_request', { type: 'fetch', url, method });
        } catch (e) { }
        return (oldFetch as any)(...args);
    }, 'fetch');

    // ─────────── 3. XMLHttpRequest Hooking ───────────
    const oldXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = makeNative(function (this: XMLHttpRequest, method: string, url: string | URL, ...args: any[]) {
        try {
            notify('dynamic_request', { type: 'xhr', url: String(url), method });
        } catch (e) { }
        return (oldXHROpen as any).apply(this, [method, url, ...args]);
    }, 'open') as any;

    // ─────────── 4. Security Sinks Hooking ───────────

    // eval - WebSquare 등에서 local scope eval을 사용하는 경우를 위해 비활성화 권장
    // (indirect eval로 동작하게 되어 local scope 변수 접근 불가 오류 발생 가능)
    /*
    const oldEval = window.eval;
    (window as any).eval = makeNative(function (this: any, str: string) {
        if (typeof str === 'string') {
            notify('sink_usage', {
                vulnId: 'sink_eval',
                type: 'eval',
                content: str.substring(0, 200),
                location: document.location.href
            });
        }
        return oldEval(str);
    }, 'eval');
    */

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
            const proto = Element.prototype;
            const descriptor = Object.getOwnPropertyDescriptor(proto, propName);
            if (!descriptor || !descriptor.set) return;
            const originalSetter = descriptor.set;
            
            Object.defineProperty(proto, propName, {
                set: makeNative(function(this: Element, value: string) {
                    if (typeof value === 'string' && value.trim().length > 0) {
                        // 너무 빈번한 호출 방지
                        if (value.length > 5) {
                            notify('sink_usage', {
                                vulnId: 'sink_innerhtml',
                                type: propName,
                                content: value.substring(0, 200),
                                element: this.tagName + (this.id ? '#' + this.id : ''),
                                location: document.location.href
                            });
                        }
                    }
                    return originalSetter.call(this, value);
                }, 'set'),
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
        Element.prototype.insertAdjacentHTML = makeNative(function (this: Element, position: any, text: string) {
            notify('sink_usage', {
                vulnId: 'sink_innerhtml',
                type: 'insertAdjacentHTML',
                content: text.substring(0, 200),
                element: this.tagName + (this.id ? '#' + this.id : ''),
                location: document.location.href
            });
            return oldInsertAdjacentHTML.call(this, position, text);
        }, 'insertAdjacentHTML');
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
    (window as any).postMessage = makeNative(function (message: any, targetOrigin: string, ...rest: any[]) {
        // 내부 HackerDev 메시지는 무시
        if (message && (message.type === 'HACKERDEV_HOOK' || message.type === MSG_TYPE)) {
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
    }, 'postMessage');

    console.log("[HackerDev] Runtime Hooks Installed (v2 - Extended).");
})();
