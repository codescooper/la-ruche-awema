'use strict';
(() => {
  const params = new URLSearchParams(location.hash.slice(1));
  window.awemaLaunch = {invite:params.get('invite') || '', telegramInitData:params.get('tgWebAppData') || ''};
  // The Telegram SDK must never persist invitations or signed identity proofs.
  try { sessionStorage.removeItem('__telegram__initParams'); } catch {}
  const publicParams = new URLSearchParams();
  for (const key of ['tgWebAppVersion','tgWebAppPlatform','tgWebAppThemeParams']) {
    if(params.has(key)) publicParams.set(key,params.get(key));
  }
  history.replaceState(null,'',location.pathname+location.search+(publicParams.size?'#'+publicParams.toString():''));
})();
