/**
 * Lock & Key Extension - Background Script
 * Gere comunicação entre content scripts e popup.
 * Deteta credenciais submetidas e armazena para o popup guardar.
 */

'use strict';

// Receber mensagens dos content scripts e popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CREDENTIALS_DETECTED') {
    handleDetectedCredentials(message.data, sender.tab);
    return;
  }

  if (message.type === 'GET_ENTRIES_FOR_DOMAIN') {
    browser.storage.local.get('lk_session').then(data => {
      sendResponse({ session: data.lk_session });
    });
    return true; // Async response
  }

  if (message.type === 'SHOW_POPUP') {
    // browserAction.openPopup() exige gesto do utilizador; encapsular em try
    try { browser.browserAction.openPopup?.(); } catch {}
    return;
  }

  // Compensar o facto de browserAction.onClicked NÃO disparar quando há default_popup
  if (message.type === 'CLEAR_BADGE') {
    browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
      const tabId = tabs[0]?.id;
      if (tabId !== undefined) browser.browserAction.setBadgeText({ text: '', tabId });
    });
    return;
  }
});

async function handleDetectedCredentials(data, tab) {
  const { username, password, url } = data;

  if (!username || !password) return;

  let domain = '';
  try { domain = new URL(url).hostname.replace('www.', ''); }
  catch {}

  // Guardar temporariamente para o popup oferecer para guardar
  await browser.storage.local.set({
    pendingCredential: { username, password, url, domain, timestamp: Date.now() }
  });

  // Mostrar notificação
  browser.notifications.create('save-cred', {
    type:    'basic',
    iconUrl: browser.runtime.getURL('assets/icon.svg'),
    title:   'Lock & Key',
    message: `Guardar credenciais para ${domain}? Clica no ícone Lock & Key.`,
  });

  // Atualizar badge
  if (tab?.id !== undefined) {
    browser.browserAction.setBadgeText({ text: '!', tabId: tab.id });
    browser.browserAction.setBadgeBackgroundColor({ color: '#3b82f6' });
  }
}

// ============================================================
// LIMPEZA DE CREDENCIAIS PENDENTES (mais de 5 min)
// ============================================================
// IMPORTANTE: setInterval não é fiável em event-pages MV2 — o browser pode
// suspender o script e o timer não dispara. Usamos browser.alarms que persiste.

const CLEAN_ALARM = 'lk_clean_pending';
const PENDING_TTL_MS = 300000; // 5 minutos

browser.alarms.create(CLEAN_ALARM, { periodInMinutes: 1 });

browser.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== CLEAN_ALARM) return;
  try {
    const data = await browser.storage.local.get('pendingCredential');
    if (data.pendingCredential) {
      const age = Date.now() - (data.pendingCredential.timestamp || 0);
      if (age > PENDING_TTL_MS) {
        await browser.storage.local.remove('pendingCredential');
      }
    }
  } catch (err) {
    console.warn('[Lock&Key] alarm cleanup failed:', err);
  }
});
