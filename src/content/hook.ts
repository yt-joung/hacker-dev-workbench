/**
 * Main World Hook Script
 * 이 스크립트는 페이지의 메인 컨텍스트(Main World)에서 실행되어
 * 이벤트 리스너, 네트워크 요청, 그리고 잠재적 보안 위협이 있는 함수들을 모니터링합니다.
 */

(function () {
    // 메시지 데이터 전송 유틸리티
    function notify(type: string, data: any) {
        window.postMessage({
            type: "HACKERDEV_HOOK",
            payload: { type, data }
        }, "*");
    }

    // 1. Event Listener Hooking
    const oldAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (this: EventTarget, type: string, listener: any, options?: any) {
        if (['click', 'submit', 'change', 'input', 'mouseover'].includes(type)) {
            try {
                const elementInfo = this instanceof Element 
                    ? this.tagName.toLowerCase() + (this.id ? '#' + this.id : '') + (this.className ? '.' + this.className.split(' ').join('.') : '')
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
        return oldAddEventListener.call(this, type, listener, options);
    };

    // 2. Fetch API Hooking
    const oldFetch = window.fetch;
    window.fetch = function (this: Window, ...args: any[]) {
        try {
            const url = args[0] instanceof Request ? args[0].url : String(args[0]);
            const method = args[1]?.method || (args[0] instanceof Request ? args[0].method : 'GET');
            
            notify('dynamic_request', { 
                type: 'fetch', 
                url: url,
                method: method 
            });
        } catch (e) { }
        return (oldFetch as any)(...args);
    };

    // 3. XMLHttpRequest Hooking
    const oldXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (this: XMLHttpRequest, method: string, url: string | URL, ...args: any[]) {
        try {
            notify('dynamic_request', { 
                type: 'xhr', 
                url: String(url),
                method: method 
            });
        } catch (e) { }
        return (oldXHROpen as any).apply(this, [method, url, ...args]);
    } as any;

    // 4. Security Sinks Hooking (XSS candidates)
    
    // eval Hooking
    const oldEval = window.eval;
    window.eval = function (this: any, str: string) {
        notify('sink_usage', { 
            type: 'eval', 
            content: typeof str === 'string' ? str.substring(0, 150) : '[Non-string eval]' 
        });
        return oldEval.call(this, str);
    };

    // document.write Hooking
    const oldWrite = document.write;
    document.write = function (this: Document, ...args: any[]) {
        notify('sink_usage', { 
            type: 'document.write', 
            content: args.join('').substring(0, 150) 
        });
        return oldWrite.apply(this, args);
    };

    console.log("[HackerDev] Runtime Hooks Installed.");
})();
