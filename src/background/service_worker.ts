// 가장 깔끔한 배경 설정: 리스너 대신 브라우저의 전역 설정을 사용합니다.
// 이 방식은 아이콘 클릭 시 즉시 사이드 패널을 열어주는 Manifest V3의 가장 신뢰할 수 있는 방식입니다.

chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch((error: any) => console.error('[HackerDev] Failed to set panel behavior:', error));

chrome.runtime.onInstalled.addListener(() => {
  console.log('[HackerDev Workbench] Extension Re-installed. Side panel behavior set to AUTO-OPEN.');
});
