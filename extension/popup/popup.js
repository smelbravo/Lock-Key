/**
 * Lock & Key Extension - Popup Principal
 * Gere o estado do popup, login, lista de entradas e comunicação com o background.
 */

'use strict';

// URL base da API (deve corresponder ao servidor local)
const API_BASE = 'http://localhost/Lock%26Key/backend/api';

// Módulo de criptografia adaptado para a extensão
const ExtCrypto = {
  async deriveKeys(masterPassword, email, salt, iterations = 200000) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(masterPassword),
      'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: new TextEncoder().encode(salt + email.toLowerCase()), iterations, hash: 'SHA-256' },
      keyMaterial, 512
    );
    const authKey = Array.from(new Uint8Array(bits.slice(0, 32)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    // Guardar os bytes raw ANTES de importar (chave não-extraível não pode ser exportada depois)
    const rawKeyBytes = Array.from(new Uint8Array(bits.slice(32)));
    const encKey = await crypto.subtle.importKey(
      'raw', new Uint8Array(rawKeyBytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
    return { authKey, encKey, rawKeyBytes };
  },

  async decryptField(ciphertextB64, ivB64, key) {
    if (!ciphertextB64 || !ivB64 || !key) return '';
    try {
      const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
      const iv         = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
      const plaintext  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
      return new TextDecoder().decode(plaintext);
    } catch { return ''; }
  },

  async decryptEntry(encEntry, key) {
    const iv = encEntry.iv;
    return {
      uuid:     encEntry.uuid,
      title:    await this.decryptField(encEntry.title_enc,    iv, key),
      url:      await this.decryptField(encEntry.url_enc,      iv, key),
      username: await this.decryptField(encEntry.username_enc, iv, key),
      password: await this.decryptField(encEntry.password_enc, iv, key),
      category: await this.decryptField(encEntry.category_enc, iv, key),
      strength_score: encEntry.strength_score,
    };
  },

  async encryptEntry(entry, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ivB64 = btoa(String.fromCharCode(...iv));

    const encField = async (val) => {
      if (!val) return null;
      const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, key, new TextEncoder().encode(String(val))
      );
      return btoa(String.fromCharCode(...new Uint8Array(ct)));
    };

    return {
      title_enc:    await encField(entry.title),
      url_enc:      await encField(entry.url),
      username_enc: await encField(entry.username),
      password_enc: await encField(entry.password),
      iv: ivB64,
      strength_score: 0,
      is_favourite: false,
    };
  }
};

// Estado do popup
const State = {
  accessToken:   null,
  encKey:        null,
  user:          null,
  entries:       [],
  filteredEntries: [],
  currentTab:    'all',
  currentDomain: '',
  searchQuery:   '',
  pendingCredential: null, // credenciais pendentes para guardar
};

// ============================================================
// INICIALIZAÇÃO
// ============================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Verificar sessão guardada
  const session = await getStoredSession();

  // Verificar se há sessão guardada com rawKey (chave armazenada como array de bytes)
  if (session?.accessToken && session?.rawKey) {
    State.accessToken = session.accessToken;
    State.user        = session.user;
    // Reimportar chave a partir dos bytes raw guardados em storage
    try {
      State.encKey = await crypto.subtle.importKey(
        'raw', new Uint8Array(session.rawKey), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
      );
      await showMainScreen();
    } catch {
      await clearSession();
      showLoginScreen();
    }
  } else {
    showLoginScreen();
  }

  // Obter domínio atual
  getCurrentTab().then(tab => {
    if (tab?.url) {
      try {
        State.currentDomain = new URL(tab.url).hostname.replace('www.', '');
        updateSiteBar();
      } catch {}
    }
  });

  // Verificar se há credencial pendente para guardar
  browser.storage.local.get('pendingCredential').then(data => {
    if (data.pendingCredential) {
      State.pendingCredential = data.pendingCredential;
      showSaveBar(data.pendingCredential);
    }
  });

  initEvents();
});

// ============================================================
// ECRÃS
// ============================================================

function showLoginScreen() {
  hideAll();
  document.getElementById('screen-login').classList.remove('hidden');
}

function showLockedScreen() {
  hideAll();
  document.getElementById('screen-locked').classList.remove('hidden');
}

async function showMainScreen() {
  hideAll();
  document.getElementById('screen-main').classList.remove('hidden');
  updateUserInfo();
  await loadEntries();
}

function hideAll() {
  ['screen-login', 'screen-main', 'screen-locked'].forEach(id => {
    document.getElementById(id).classList.add('hidden');
  });
}

// ============================================================
// LOGIN
// ============================================================

document.getElementById('login-btn').addEventListener('click', handleLogin);
document.getElementById('login-password').addEventListener('keydown', e => {
  if (e.key === 'Enter') handleLogin();
});

async function handleLogin() {
  const email    = document.getElementById('login-email').value.trim().toLowerCase();
  const password = document.getElementById('login-password').value;
  const btn      = document.getElementById('login-btn');
  const errorEl  = document.getElementById('login-error');
  const derivingEl = document.getElementById('deriving-notice');

  errorEl.classList.add('hidden');

  if (!email || !password) {
    showLoginError('Preenche todos os campos.');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'A autenticar...';
  derivingEl.classList.remove('hidden');

  try {
    // Obter salt do servidor
    const saltRes = await apiRequest('/auth/get_salt.php', 'POST', { email });
    const { salt, iterations } = saltRes.data;

    // Derivar chaves (rawKeyBytes já vem calculado, sem precisar de exportar depois)
    const { authKey, encKey, rawKeyBytes } = await ExtCrypto.deriveKeys(password, email, salt, iterations);

    // Login
    const loginRes = await apiRequest('/auth/login.php', 'POST', {
      email, auth_key: authKey, is_extension: true
    });

    const { access_token, refresh_token, user } = loginRes.data;

    State.accessToken = access_token;
    State.encKey      = encKey;
    State.user        = user;

    // Guardar sessão (usar rawKeyBytes já calculado — não é necessário exportar a chave)
    await saveSession({
      accessToken: access_token,
      refreshToken: refresh_token,
      user,
      rawKey: rawKeyBytes,
    });

    await showMainScreen();

  } catch (err) {
    showLoginError(err.message || 'Erro ao iniciar sessão.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Iniciar Sessão';
    derivingEl.classList.add('hidden');
  }
}

function showLoginError(msg) {
  const el = document.getElementById('login-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

// ============================================================
// CARREGAR ENTRADAS
// ============================================================

async function loadEntries() {
  const listEl = document.getElementById('entries-list');
  listEl.innerHTML = '<div class="loading"><svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> A carregar...</div>';

  try {
    const res = await apiRequest('/vault/entries.php', 'GET');
    const encEntries = res.data?.entries || [];

    // Desencriptar em paralelo
    State.entries = await Promise.all(
      encEntries.map(e => ExtCrypto.decryptEntry(e, State.encKey))
    );

    applyFilter();
  } catch (err) {
    listEl.innerHTML = `<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/></svg><span>${err.message}</span></div>`;
  }
}

function applyFilter() {
  const q    = State.searchQuery.toLowerCase();
  const tab  = State.currentTab;
  let result = [...State.entries];

  if (tab === 'site' && State.currentDomain) {
    result = result.filter(e => {
      try { return new URL(e.url || '').hostname.includes(State.currentDomain); }
      catch { return (e.url || '').includes(State.currentDomain); }
    });
  } else if (tab === 'recent') {
    // Ordenar por last_used (não temos em tempo real, mostrar todos)
    result = result.slice(0, 10);
  }

  if (q) {
    result = result.filter(e =>
      (e.title || '').toLowerCase().includes(q) ||
      (e.username || '').toLowerCase().includes(q) ||
      (e.url || '').toLowerCase().includes(q)
    );
  }

  State.filteredEntries = result;
  renderEntries();
}

function renderEntries() {
  const listEl = document.getElementById('entries-list');

  if (State.filteredEntries.length === 0) {
    listEl.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span>${State.searchQuery ? 'Sem resultados para "' + State.searchQuery + '"' : 'Nenhuma entrada'}</span>
      </div>
    `;
    return;
  }

  listEl.innerHTML = State.filteredEntries.map(entry => {
    const initial = (entry.title || '?')[0].toUpperCase();
    const isMatch = State.currentDomain && entry.url
      ? entry.url.includes(State.currentDomain)
      : false;

    return `
      <div class="entry-item ${isMatch ? 'autofill-match' : ''}" data-uuid="${entry.uuid}">
        <div class="entry-item-icon">
          <span>${escapeHtml(initial)}</span>
        </div>
        <div class="entry-item-info">
          <div class="entry-item-title">${escapeHtml(entry.title || 'Sem título')}</div>
          <div class="entry-item-sub">${escapeHtml(entry.username || entry.url || '—')}</div>
        </div>
        <div class="entry-item-actions">
          ${isMatch ? `
          <div class="action-btn fill-btn" data-uuid="${entry.uuid}" title="Preencher formulário">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="5 12 10 17 20 7"/>
            </svg>
          </div>` : ''}
          <div class="action-btn copy-user-btn" data-uuid="${entry.uuid}" title="Copiar utilizador">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
              <circle cx="12" cy="7" r="4"/>
            </svg>
          </div>
          <div class="action-btn copy-pass-btn" data-uuid="${entry.uuid}" title="Copiar password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
        </div>
      </div>
    `;
  }).join('');

  attachEntryEvents();
}

function attachEntryEvents() {
  // Preencher formulário (autofill)
  document.querySelectorAll('.fill-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const entry = State.filteredEntries.find(e => e.uuid === btn.dataset.uuid);
      if (entry) autofillEntry(entry);
    });
  });

  // Copiar utilizador
  document.querySelectorAll('.copy-user-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const entry = State.filteredEntries.find(e => e.uuid === btn.dataset.uuid);
      if (entry?.username) copyToClipboard(entry.username, 'Utilizador copiado!');
    });
  });

  // Copiar password
  document.querySelectorAll('.copy-pass-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const entry = State.filteredEntries.find(e => e.uuid === btn.dataset.uuid);
      if (entry?.password) copyToClipboard(entry.password, 'Password copiada!');
    });
  });
}

// ============================================================
// AUTOFILL
// ============================================================

async function autofillEntry(entry) {
  const tab = await getCurrentTab();
  if (!tab?.id) return;

  browser.tabs.sendMessage(tab.id, {
    type: 'AUTOFILL',
    data: { username: entry.username, password: entry.password }
  }).then(() => {
    window.close(); // Fechar popup após autofill
  }).catch(err => {
    showNotification('Não foi possível preencher o formulário nesta página.');
  });
}

// ============================================================
// GUARDAR CREDENCIAIS
// ============================================================

function showSaveBar(credential) {
  const bar = document.getElementById('save-credential-bar');
  document.getElementById('save-bar-domain').textContent = credential.domain || '';
  bar.classList.remove('hidden');
}

async function saveNewCredential() {
  const cred = State.pendingCredential;
  if (!cred || !State.encKey) return;

  try {
    const encEntry = await ExtCrypto.encryptEntry({
      title:    cred.domain || 'Nova Entrada',
      url:      cred.url || '',
      username: cred.username || '',
      password: cred.password || '',
    }, State.encKey);

    await apiRequest('/vault/create.php', 'POST', encEntry);

    browser.storage.local.remove('pendingCredential');
    document.getElementById('save-credential-bar').classList.add('hidden');
    State.pendingCredential = null;

    await loadEntries();
    showNotification('Credenciais guardadas com sucesso!');
  } catch (err) {
    showNotification('Erro ao guardar: ' + err.message);
  }
}

// ============================================================
// EVENTS
// ============================================================

function initEvents() {
  // Pesquisa
  document.getElementById('search-input').addEventListener('input', (e) => {
    State.searchQuery = e.target.value.trim();
    applyFilter();
  });

  // Tabs
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      State.currentTab = tab.dataset.tab;
      applyFilter();
    });
  });

  // Sync
  document.getElementById('sync-btn').addEventListener('click', async () => {
    document.getElementById('sync-btn').querySelector('svg').classList.add('spin');
    await loadEntries();
    setTimeout(() => {
      document.getElementById('sync-btn').querySelector('svg').classList.remove('spin');
    }, 500);
  });

  // Logout
  document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
      await apiRequest('/auth/logout.php', 'POST', {});
    } finally {
      await clearSession();
      State.accessToken = null;
      State.encKey = null;
      State.user = null;
      State.entries = [];
      showLoginScreen();
    }
  });

  // Autofill no site bar
  document.getElementById('autofill-all-btn').addEventListener('click', () => {
    const match = State.entries.find(e => {
      try { return new URL(e.url || '').hostname.includes(State.currentDomain); }
      catch { return false; }
    });
    if (match) autofillEntry(match);
  });

  // Guardar credencial pendente
  document.getElementById('save-credential-btn')?.addEventListener('click', saveNewCredential);
  document.getElementById('dismiss-save-btn')?.addEventListener('click', () => {
    browser.storage.local.remove('pendingCredential');
    document.getElementById('save-credential-bar').classList.add('hidden');
  });

  // Unlock
  document.getElementById('unlock-btn')?.addEventListener('click', async () => {
    const pass = document.getElementById('unlock-password').value;
    const session = await getStoredSession();
    if (!session?.user || !pass) return;
    try {
      const saltRes = await apiRequest('/auth/get_salt.php', 'POST', { email: session.user.email });
      const { authKey, encKey } = await ExtCrypto.deriveKeys(
        pass, session.user.email, saltRes.data.salt, saltRes.data.iterations
      );
      State.encKey = encKey;
      await showMainScreen();
    } catch {
      document.getElementById('unlock-password').style.borderColor = '#ef4444';
    }
  });

  document.getElementById('unlock-logout-btn')?.addEventListener('click', async () => {
    await clearSession();
    showLoginScreen();
  });

  // Toggle password no login
  document.getElementById('toggle-login-pass')?.addEventListener('click', () => {
    const input = document.getElementById('login-password');
    input.type = input.type === 'password' ? 'text' : 'password';
  });
}

// ============================================================
// UTILITÁRIOS
// ============================================================

async function apiRequest(endpoint, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };

  if (State.accessToken) {
    opts.headers['Authorization'] = `Bearer ${State.accessToken}`;
  }

  if (body && method !== 'GET') {
    opts.body = JSON.stringify(body);
  }

  const res  = await fetch(`${API_BASE}${endpoint}`, opts);
  const data = await res.json();

  if (!res.ok) throw new Error(data.message || `Erro ${res.status}`);
  return data;
}

function updateUserInfo() {
  const el = document.getElementById('user-info');
  if (el && State.user) {
    el.textContent = State.user.username || State.user.email || 'Utilizador';
  }
}

function updateSiteBar() {
  if (!State.currentDomain) return;
  const bar = document.getElementById('current-site-bar');
  const domain = document.getElementById('current-domain');
  domain.textContent = State.currentDomain;
  bar.classList.remove('hidden');
}

function copyToClipboard(text, msg = 'Copiado!') {
  navigator.clipboard.writeText(text).then(() => {
    showNotification(msg);
  });
}

function showNotification(message) {
  browser.notifications.create({
    type: 'basic',
    iconUrl: '../assets/icon-48.png',
    title: 'Lock & Key',
    message,
  });
}

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  }[c]));
}

async function getCurrentTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

// Storage da sessão
async function saveSession(data) {
  await browser.storage.local.set({ lk_session: data });
}

async function getStoredSession() {
  const data = await browser.storage.local.get('lk_session');
  return data.lk_session || null;
}

async function clearSession() {
  await browser.storage.local.remove('lk_session');
}

