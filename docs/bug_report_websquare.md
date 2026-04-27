# Bug Report: WebSquare Compatibility & Runtime Stability

**Date**: 2026-04-27
**Target Site**: `https://pension.comwel.or.kr/` (WebSquare v5.0)
**Status**: Resolved

## 1. Issue: SES (Secure EcmaScript) Intrinsics Removal
### Symptoms
- Console log: `SES Removing unpermitted intrinsics`
- Extension hooks were being stripped or causing security errors during initialization.
### Root Cause
WebSquare uses a lockdown mechanism that freezes or removes non-standard properties on intrinsics (`Object`, `Array`, etc.) to prevent environment pollution.
### Solution
- Moved injection timing to `document_start` in `manifest.json`.
- Implemented a stealth proxy for `Object.defineProperty`, `Object.freeze`, and `Object.getOwnPropertyDescriptor` to intercept and bypass lockdown attempts while maintaining original functionality.

## 2. Issue: ReferenceError (obfuscator_msg is not defined)
### Symptoms
- Console error: `ReferenceError: obfuscator_msg is not defined at eval`
- Page displayed a white screen as the engine failed to boot.
### Root Cause
Our `window.eval` hook transformed direct `eval()` calls into **Indirect Eval**. Indirect eval executes in the global scope, losing access to local variables. WebSquare relies heavily on scope-sensitive evals for its internal "obfuscator" logic.
### Solution
- Disabled the global `eval` hook for WebSquare-like environments to preserve the scope sensitivity required by the engine.

## 3. Issue: TypeError (Cannot set properties of null 'innerHTML')
### Symptoms
- Console error: `TypeError: Cannot set properties of null (setting 'innerHTML') at scwin.notiCallList`
### Root Cause
This was a secondary error caused by the engine's boot failure (Issue #2). Since the initialization script crashed, the UI elements were never rendered, leading to null pointer exceptions when the application tried to update them.
### Solution
- Resolving the `eval` scope issue (Issue #2) restored the engine's initialization sequence, thereby fixing the null reference errors.

## 4. Issue: Extension Context Invalidated
### Symptoms
- Console error: `Uncaught Error: Extension context invalidated`
- Occurred after updating/reloading the extension while a page was open.
### Root Cause
Old content script listeners remained active on the page and tried to call `chrome.runtime.sendMessage` after the extension was reloaded, which is prohibited.
### Solution
- Added a check for `chrome.runtime.id` before any message relay.
- Wrapped message sending in `try-catch` blocks to gracefully handle stale content scripts.

## 5. Optimization: Log Throttling
### Symptoms
- High CPU usage and browser lag due to excessive message passing from frequent `innerHTML` changes and event listeners.
### Solution
- Implemented a throttling mechanism using a `Set` of recent logs and `setTimeout`.
- Duplicate logs within a 1-second window are suppressed to reduce the communication overhead between the page and the background script.

---
**HackerDev Workbench Team**
