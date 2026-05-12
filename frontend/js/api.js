/**
 * Lock & Key - Cliente API
 * Centraliza todas as chamadas à REST API do backend.
 * Gere tokens JWT, refresh automático e erros.
 */

'use strict';

const LKApi = (() => {

  // URL base da API - ajusta conforme o teu ambiente
  const BASE_URL = 'http://localhost/Lock&Key/backend/api';

  // ============================================================
  // GESTÃO DE TOKENS
  // ============================================================

  const TOKEN_KEY   = 'lk_access_token';
  const REFRESH_KEY = 'lk_refresh_token';
  const USER_KEY    = 'lk_user';

  function storeTokens(accessToken, refreshToken, user) {
    sessionStorage.setItem(TOKEN_KEY, accessToken);
    // Refresh token em sessionStorage (fecha browser = perde sessão)
    // Em produção considerar secure httpOnly cookie para refresh token
    sessionStorage.setItem(REFRESH_KEY, refreshToken);
    if (user) {
      sessionStorage.setItem(USER_KEY, JSON.stringify(user));
    }
  }

  function getAccessToken()  { return sessionStorage.getItem(TOKEN_KEY); }
  function getRefreshToken() { return sessionStorage.getItem(REFRESH_KEY); }
  function getStoredUser()   {
    try { return JSON.parse(sessionStorage.getItem(USER_KEY)); }
    catch { return null; }
  }

  function clearTokens() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(REFRESH_KEY);
    sessionStorage.removeItem(USER_KEY);
  }

  function isLoggedIn() {
    return !!getAccessToken();
  }

  // ============================================================
  // REQUISIÇÃO BASE
  // ============================================================

  let _refreshPromise = null; // Evitar múltiplos refresh simultâneos

  /**
   * Faz uma requisição autenticada à API.
   * Tenta refresh automático do token se receber 401.
   *
   * @param {string} endpoint   - Caminho do endpoint (ex: '/auth/login.php')
   * @param {Object} options    - Opções fetch (method, body, etc.)
   * @param {boolean} retry     - Se deve tentar refresh após 401
   * @returns {Promise<Object>} - Resposta JSON da API
   */
  async function request(endpoint, options = {}, retry = true) {
    const url    = `${BASE_URL}${endpoint}`;
    const token  = getAccessToken();

    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...options.headers,
    };

    let response;
    try {
      response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include', // Incluir cookies se usados
      });
    } catch (err) {
      throw new Error('Sem conexão com o servidor. Verifica a ligação à internet.');
    }

    // Tentar refresh do token se expirado
    if (response.status === 401 && retry) {
      const refreshToken = getRefreshToken();
      if (refreshToken) {
        try {
          await refreshAccessToken();
          return request(endpoint, options, false); // Retry sem loop infinito
        } catch {
          clearTokens();
          LKCrypto.clearSessionKey();
          window.location.href = '/Lock&Key/frontend/login.html';
          throw new Error('Sessão expirada. Redirecionar para login.');
        }
      } else {
        clearTokens();
        LKCrypto.clearSessionKey();
        window.location.href = '/Lock&Key/frontend/login.html';
        throw new Error('Sessão terminada.');
      }
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.message || `Erro ${response.status}`);
    }

    return data;
  }

  /** Renovar access token usando refresh token */
  async function refreshAccessToken() {
    if (_refreshPromise) return _refreshPromise; // Evitar chamadas simultâneas

    _refreshPromise = (async () => {
      const refreshToken = getRefreshToken();
      if (!refreshToken) throw new Error('Sem refresh token.');

      const response = await fetch(`${BASE_URL}/auth/refresh.php`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
        credentials: 'include',
      });

      const data = await response.json();
      if (!response.ok || !data.data?.access_token) {
        throw new Error('Falha ao renovar sessão.');
      }

      // Guardar novos tokens
      storeTokens(data.data.access_token, data.data.refresh_token, data.data.user);
    })();

    try {
      await _refreshPromise;
    } finally {
      _refreshPromise = null;
    }
  }

  // ============================================================
  // AUTENTICAÇÃO
  // ============================================================

  async function getSalt(email) {
    const res = await request('/auth/get_salt.php', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
    return res.data; // { salt, iterations }
  }

  async function login(email, authKey, isExtension = false) {
    const res = await request('/auth/login.php', {
      method: 'POST',
      body: JSON.stringify({ email, auth_key: authKey, is_extension: isExtension }),
    }, false);

    if (res.data) {
      storeTokens(res.data.access_token, res.data.refresh_token, res.data.user);
    }
    return res.data;
  }

  async function register(email, username, authKey) {
    return request('/auth/register.php', {
      method: 'POST',
      body: JSON.stringify({ email, username, auth_key: authKey }),
    }, false);
  }

  async function logout(allSessions = false) {
    try {
      await request('/auth/logout.php', {
        method: 'POST',
        body: JSON.stringify({ all_sessions: allSessions }),
      }, false);
    } finally {
      clearTokens();
      LKCrypto.clearSessionKey();
    }
  }

  // ============================================================
  // VAULT
  // ============================================================

  async function getVaultEntries(params = {}) {
    const qs = new URLSearchParams(params).toString();
    const res = await request(`/vault/entries.php${qs ? '?' + qs : ''}`);
    return res.data?.entries ?? [];
  }

  async function createVaultEntry(encryptedEntry) {
    return request('/vault/create.php', {
      method: 'POST',
      body: JSON.stringify(encryptedEntry),
    });
  }

  async function updateVaultEntry(encryptedEntry) {
    return request('/vault/update.php', {
      method: 'POST',
      body: JSON.stringify(encryptedEntry),
    });
  }

  async function deleteVaultEntry(uuid) {
    return request('/vault/delete.php', {
      method: 'POST',
      body: JSON.stringify({ uuid }),
    });
  }

  async function exportVault() {
    return request('/vault/export.php');
  }

  // ============================================================
  // NOTAS
  // ============================================================

  async function getNotes() {
    const res = await request('/notes/notes.php');
    return res.data?.notes ?? [];
  }

  async function createNote(encNote) {
    return request('/notes/create.php', {
      method: 'POST',
      body: JSON.stringify(encNote),
    });
  }

  async function updateNote(encNote) {
    return request('/notes/update.php', {
      method: 'POST',
      body: JSON.stringify(encNote),
    });
  }

  async function deleteNote(uuid) {
    return request('/notes/delete.php', {
      method: 'POST',
      body: JSON.stringify({ uuid }),
    });
  }

  // ============================================================
  // UTILIZADOR
  // ============================================================

  async function getProfile() {
    const res = await request('/user/profile.php');
    return res.data;
  }

  async function updateProfile(username) {
    return request('/user/profile.php', {
      method: 'POST',
      body: JSON.stringify({ username }),
    });
  }

  async function changePassword(payload) {
    return request('/user/change_password.php', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // ============================================================
  // EXPORTAR API PÚBLICA
  // ============================================================

  return {
    getSalt,
    login,
    register,
    logout,
    getVaultEntries,
    createVaultEntry,
    updateVaultEntry,
    deleteVaultEntry,
    exportVault,
    getNotes,
    createNote,
    updateNote,
    deleteNote,
    getProfile,
    updateProfile,
    changePassword,
    isLoggedIn,
    getStoredUser,
    clearTokens,
    refreshAccessToken,
    BASE_URL,
  };
})();

window.LKApi = LKApi;
