/**
 * Lock & Key - Utilitários Globais
 * Funções reutilizáveis em todo o frontend.
 */

'use strict';

// ============================================================
// NOTIFICAÇÕES TOAST
// ============================================================

const LKToast = (() => {
  let container;

  function getContainer() {
    if (!container) {
      container = document.getElementById('toast-container');
      if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
      }
    }
    return container;
  }

  /**
   * Mostrar uma notificação toast.
   * @param {string} message   - Mensagem a mostrar
   * @param {'success'|'error'|'warning'|'info'} type - Tipo
   * @param {number} duration  - Duração em ms (padrão: 4000)
   */
  function show(message, type = 'info', duration = 4000) {
    const icons = {
      success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--success)"><circle cx="12" cy="12" r="10"/><polyline points="20 6 9 17 4 12"/></svg>',
      error:   '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--danger)"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
      warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--warning)"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
      info:    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--info)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] || icons.info}</span>
      <span class="toast-msg">${LKUtils.escapeHtml(message)}</span>
      <button class="toast-close" onclick="this.closest('.toast').remove()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
      </button>
    `;

    getContainer().appendChild(toast);

    // Auto-remover após duração
    const timer = setTimeout(() => {
      toast.classList.add('hide');
      setTimeout(() => toast.remove(), 300);
    }, duration);

    // Pausar timer ao passar o rato
    toast.addEventListener('mouseenter', () => clearTimeout(timer));
    toast.addEventListener('mouseleave', () => {
      setTimeout(() => {
        toast.classList.add('hide');
        setTimeout(() => toast.remove(), 300);
      }, 1000);
    });
  }

  return {
    show,
    success: (msg, d) => show(msg, 'success', d),
    error:   (msg, d) => show(msg, 'error', d),
    warning: (msg, d) => show(msg, 'warning', d),
    info:    (msg, d) => show(msg, 'info', d),
  };
})();

// ============================================================
// UTILITÁRIOS GERAIS
// ============================================================

const LKUtils = (() => {

  /** Escapar HTML para prevenir XSS */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /** Copiar texto para a área de transferência */
  async function copyToClipboard(text, successMsg = 'Copiado!') {
    try {
      await navigator.clipboard.writeText(text);
      LKToast.success(successMsg);
      return true;
    } catch {
      // Fallback para browsers mais antigos
      const el = document.createElement('textarea');
      el.value = text;
      el.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      LKToast.success(successMsg);
      return true;
    }
  }

  /** Formatar data para formato legível */
  function formatDate(dateStr) {
    if (!dateStr) return '—';
    const date = new Date(dateStr);
    const now  = new Date();
    const diff = now - date;
    const mins = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days  = Math.floor(diff / 86400000);

    if (mins < 1)   return 'agora mesmo';
    if (mins < 60)  return `há ${mins} min`;
    if (hours < 24) return `há ${hours}h`;
    if (days < 7)   return `há ${days}d`;
    return date.toLocaleDateString('pt-PT', { day: '2-digit', month: 'short' });
  }

  /** Extrair domínio de uma URL */
  function extractDomain(url) {
    if (!url) return '';
    try {
      const u = new URL(url.startsWith('http') ? url : 'https://' + url);
      return u.hostname.replace('www.', '');
    } catch {
      return url.split('/')[0];
    }
  }

  /** Obter iniciais de um nome */
  function getInitials(name) {
    if (!name) return 'LK';
    const parts = name.trim().split(/\s+/);
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  /** Debounce */
  function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  /** Validar email */
  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  /** Gerar URL do favicon de um website */
  function getFaviconUrl(url) {
    if (!url) return null;
    const domain = extractDomain(url);
    if (!domain) return null;
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
  }

  /** Formatar tamanho de ficheiro */
  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  /** Verificar se estamos na página correta */
  function getCurrentPage() {
    const path = window.location.pathname;
    const file = path.split('/').pop().replace('.html', '');
    return file || 'index';
  }

  /** Mostrar/ocultar loading em botão */
  function setButtonLoading(btn, loading, originalText = '') {
    if (loading) {
      btn.disabled = true;
      btn.classList.add('loading');
      btn._originalText = btn.innerHTML;
    } else {
      btn.disabled = false;
      btn.classList.remove('loading');
      if (originalText) btn.innerHTML = originalText;
      else if (btn._originalText) btn.innerHTML = btn._originalText;
    }
  }

  return {
    escapeHtml,
    copyToClipboard,
    formatDate,
    extractDomain,
    getInitials,
    applyUserToHeader,
    debounce,
    isValidEmail,
    getFaviconUrl,
    formatBytes,
    getCurrentPage,
    setButtonLoading,
  };
})();

// ============================================================
// TEMA (Dark/Light Mode)
// ============================================================

const LKTheme = (() => {
  const THEME_KEY = 'lk_theme';

  function getTheme() {
    return localStorage.getItem(THEME_KEY) || 'dark';
  }

  function setTheme(theme) {
    localStorage.setItem(THEME_KEY, theme);
    document.body.classList.toggle('light-mode', theme === 'light');
    updateThemeIcons(theme);
  }

  function toggle() {
    setTheme(getTheme() === 'dark' ? 'light' : 'dark');
  }

  function init() {
    setTheme(getTheme());
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.addEventListener('click', toggle);
  }

  function updateThemeIcons(theme) {
    const dark  = document.getElementById('theme-icon-dark');
    const light = document.getElementById('theme-icon-light');
    if (dark)  dark.style.display  = theme === 'dark'  ? 'block' : 'none';
    if (light) light.style.display = theme === 'light' ? 'block' : 'none';
  }

  return { getTheme, setTheme, toggle, init };
})();

// ============================================================
// AUTO-LOGOUT POR INATIVIDADE
// ============================================================

const LKAutoLock = (() => {
  const TIMEOUT_KEY = 'lk_lock_timeout';
  let lockTimer = null;
  let warnTimer = null;

  function getTimeoutMs() {
    // Respeitar preferência de auto-bloqueio (toggle nas definições)
    if (localStorage.getItem('lk_auto_lock') === '0') return 0;
    const mins = parseInt(localStorage.getItem(TIMEOUT_KEY) || '30', 10);
    return mins > 0 ? mins * 60 * 1000 : 0;
  }

  function reset() {
    const timeout = getTimeoutMs();
    if (!timeout) return;

    clearTimeout(lockTimer);
    clearTimeout(warnTimer);

    // Avisar 1 minuto antes de bloquear
    if (timeout > 60000) {
      warnTimer = setTimeout(() => {
        LKToast.warning('A sessão vai bloquear em 1 minuto por inatividade.', 6000);
      }, timeout - 60000);
    }

    lockTimer = setTimeout(() => {
      lockSession();
    }, timeout);
  }

  function lockSession() {
    // Limpar chave de memória E do sessionStorage para forçar reintrodução de senha
    // (apenas quando bloqueia por inatividade — logout limpa tudo via LKApi.logout)
    if (typeof LKCrypto !== 'undefined') LKCrypto.clearSessionKey();

    const lockOverlay = document.getElementById('session-lock');
    if (lockOverlay) {
      lockOverlay.classList.remove('hidden');
      const input = document.getElementById('unlock-password');
      if (input) input.focus();
    }
  }

  // Inicializar SEMPRE os botões do ecrã de bloqueio
  // (independente do timeout — os botões têm de funcionar mesmo com timer desativado)
  function initUnlockScreen() {
    const unlockBtn    = document.getElementById('unlock-btn');
    const lockLogoutBtn= document.getElementById('lock-logout-btn');
    const toggleUnlock = document.getElementById('toggle-unlock');
    const unlockInput  = document.getElementById('unlock-password');

    if (unlockBtn && !unlockBtn._lkInit) {
      unlockBtn._lkInit = true;
      unlockBtn.addEventListener('click', async () => {
        const passwordInput = document.getElementById('unlock-password');
        const password = passwordInput?.value;

        if (!password) {
          LKToast.error('Introduz a senha mestra.');
          return;
        }

        LKUtils.setButtonLoading(unlockBtn, true);

        try {
          const user = LKApi.getStoredUser();
          if (!user?.vault_salt) {
            // Sem dados de sessão — redirecionar para login
            LKApi.clearTokens();
            window.location.href = '/Lock%26Key/frontend/login.html';
            return;
          }

          const { encryptionKey, rawKeyBytes } = await LKCrypto.deriveKeys(
            password, user.email, user.vault_salt, user.pbkdf2_iterations
          );
          LKCrypto.storeSessionKey(encryptionKey, rawKeyBytes);

          document.getElementById('session-lock').classList.add('hidden');
          passwordInput.value = '';
          reset();
          LKToast.success('Sessão desbloqueada!');
        } catch {
          LKToast.error('Senha mestra incorreta.');
        } finally {
          LKUtils.setButtonLoading(unlockBtn, false);
        }
      });
    }

    if (lockLogoutBtn && !lockLogoutBtn._lkInit) {
      lockLogoutBtn._lkInit = true;
      lockLogoutBtn.addEventListener('click', async () => {
        await LKApi.logout();
        window.location.href = '/Lock%26Key/frontend/login.html';
      });
    }

    if (toggleUnlock && !toggleUnlock._lkInit) {
      toggleUnlock._lkInit = true;
      toggleUnlock.addEventListener('click', () => {
        const input = document.getElementById('unlock-password');
        if (input) input.type = input.type === 'password' ? 'text' : 'password';
      });
    }

    if (unlockInput && !unlockInput._lkInit) {
      unlockInput._lkInit = true;
      unlockInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') unlockBtn?.click();
      });
    }
  }

  function init() {
    // Botões do ecrã de bloqueio são sempre inicializados
    initUnlockScreen();

    const timeout = getTimeoutMs();
    if (!timeout) return;

    // Resetar timer em qualquer interação do utilizador
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'];
    events.forEach(e => document.addEventListener(e, reset, { passive: true }));
    reset();
  }

  return { init, initUnlockScreen, reset, lockSession, getTimeoutMs };
})();

// ============================================================
// SIDEBAR E LAYOUT
// ============================================================

/** Atualiza header e mensagem de boas-vindas com dados do utilizador em sessão. */
function applyUserToHeader(user) {
  if (!user) return;

  const nameEl    = document.getElementById('dropdown-name');
  const emailEl   = document.getElementById('dropdown-email');
  const avatar    = document.getElementById('user-avatar');
  const welcomeEl = document.getElementById('welcome-name');

  if (nameEl)    nameEl.textContent    = user.username || 'Utilizador';
  if (emailEl)   emailEl.textContent   = user.email || '';
  if (avatar)    avatar.textContent    = LKUtils.getInitials(user.username || user.email);
  if (welcomeEl) welcomeEl.textContent = user.username || 'utilizador';

  const sidebarUsername = document.getElementById('sidebarUsername');
  const sidebarAvatar   = document.getElementById('sidebarAvatar');
  if (sidebarUsername) sidebarUsername.textContent = user.username || '';
  if (sidebarAvatar)   sidebarAvatar.textContent   = LKUtils.getInitials(user.username || user.email);

  if (user.role === 'admin' || user.role === 'admin_master') {
    const adminLink = document.getElementById('adminNavLink');
    if (adminLink) adminLink.style.display = '';
  }
}

function initDashboardLayout() {
  const layout     = document.getElementById('app-layout');
  const sidebar    = document.getElementById('sidebar');
  const collapseBtn = document.getElementById('collapse-sidebar');
  const mobileBtn  = document.getElementById('mobile-menu-btn');
  const userDropdown = document.getElementById('user-dropdown');
  const logoutBtn  = document.getElementById('logout-btn');

  // Estado guardado
  const isCollapsed = localStorage.getItem('lk_sidebar_collapsed') === '1';
  if (isCollapsed && layout) layout.classList.add('sidebar-collapsed');

  // Colapsar/expandir sidebar
  if (collapseBtn && layout) {
    collapseBtn.addEventListener('click', () => {
      layout.classList.toggle('sidebar-collapsed');
      localStorage.setItem('lk_sidebar_collapsed',
        layout.classList.contains('sidebar-collapsed') ? '1' : '0');
    });
  }

  // Menu mobile
  if (mobileBtn && sidebar) {
    mobileBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
    // Fechar ao clicar fora
    document.addEventListener('click', (e) => {
      if (!sidebar.contains(e.target) && !mobileBtn.contains(e.target)) {
        sidebar.classList.remove('open');
      }
    });
    mobileBtn.style.display = 'flex';
  }

  // Dropdown do utilizador
  if (userDropdown) {
    const avatar = document.getElementById('user-avatar');
    if (avatar) {
      avatar.addEventListener('click', (e) => {
        e.stopPropagation();
        userDropdown.classList.toggle('open');
      });
    }
    // Fechar ao clicar fora do dropdown
    document.addEventListener('click', (e) => {
      if (!userDropdown.contains(e.target)) {
        userDropdown.classList.remove('open');
      }
    });
  }

  LKUtils.applyUserToHeader(LKApi.getStoredUser());

  // Logout
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      if (confirm('Tens a certeza que queres terminar a sessão?')) {
        try {
          await LKApi.logout();
        } finally {
          window.location.href = '/Lock%26Key/frontend/login.html';
        }
      }
    });
  }

  // Atalho de teclado para pesquisa
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      const search = document.getElementById('global-search');
      if (search) search.focus();
    }
  });

  updateNavCounts();
}

/** Atualiza badges do cofre e notas na sidebar (todas as páginas da app). */
async function updateNavCounts() {
  const vaultBadge = document.getElementById('vault-count');
  const notesBadge = document.getElementById('notes-count');
  if (!vaultBadge && !notesBadge) return;
  if (!LKCrypto.getSessionKey()) return;

  try {
    const [encEntries, encNotes] = await Promise.all([
      LKApi.getVaultEntries(),
      LKApi.getNotes(),
    ]);
    if (vaultBadge) vaultBadge.textContent = String(encEntries.length);
    if (notesBadge) notesBadge.textContent = String(encNotes.length);
  } catch (_) {
    /* ignorar — badges ficam no valor anterior */
  }
}

// Inicializar tema ao carregar
document.addEventListener('DOMContentLoaded', () => {
  LKTheme.init();
});

window.LKToast  = LKToast;
window.LKUtils  = LKUtils;
window.LKTheme  = LKTheme;
window.LKAutoLock = LKAutoLock;
window.initDashboardLayout = initDashboardLayout;
window.updateNavCounts = updateNavCounts;


