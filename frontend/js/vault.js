/**
 * Lock & Key - Gestão do Cofre de Passwords
 * Carrega, desencripta, mostra e gere as entradas do cofre.
 */

'use strict';

// Estado do módulo
const VaultState = {
  entries: [],         // Entradas desencriptadas em memória
  filtered: [],        // Entradas após filtro/pesquisa
  currentEntry: null,  // Entrada selecionada atualmente
  view: 'list',        // 'list' ou 'grid'
  filter: 'all',       // 'all', 'favourite', 'weak'
  category: '',        // Filtro de categoria
  searchQuery: '',     // Texto de pesquisa
};

document.addEventListener('DOMContentLoaded', async () => {
  if (!requireAuth()) return;

  initDashboardLayout();
  LKAutoLock.init();
  await loadVaultEntries();
  initVaultEvents();
  initPasswordGenerator();
});

// ============================================================
// CARREGAR ENTRADAS
// ============================================================

async function loadVaultEntries() {
  const key = LKCrypto.getSessionKey();
  if (!key) return;

  try {
    showVaultLoading(true);
    const encEntries = await LKApi.getVaultEntries();
    VaultState.entries = await LKCrypto.decryptAllEntries(encEntries, key);
    VaultState.filtered = [...VaultState.entries];

    updateCounts();
    populateCategoryFilter();
    renderEntries();
  } catch (err) {
    LKToast.error('Erro ao carregar o cofre: ' + err.message);
  } finally {
    showVaultLoading(false);
  }
}

function showVaultLoading(show) {
  const loadingEl = document.getElementById('vault-loading');
  if (loadingEl) loadingEl.style.display = show ? 'flex' : 'none';
}

// ============================================================
// RENDERIZAÇÃO
// ============================================================

function renderEntries() {
  applyFilters();

  const listEl  = document.getElementById('vault-list');
  const gridEl  = document.getElementById('vault-grid');
  const emptyEl = document.getElementById('vault-empty');
  const countLabel = document.getElementById('entries-count-label');
  const navBadge   = document.getElementById('vault-count');

  if (navBadge) navBadge.textContent = VaultState.entries.length;
  if (countLabel) {
    const n = VaultState.filtered.length;
    countLabel.textContent = `${n} entrada${n !== 1 ? 's' : ''}`;
  }

  if (VaultState.filtered.length === 0) {
    if (emptyEl) emptyEl.style.display = 'flex';
    if (listEl) listEl.innerHTML = '';
    if (gridEl) gridEl.innerHTML = '';
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';

  if (VaultState.view === 'list') {
    if (listEl) listEl.innerHTML = VaultState.filtered.map(renderEntryRow).join('');
    if (gridEl) gridEl.style.display = 'none';
    if (listEl) listEl.style.display = '';
  } else {
    if (gridEl) gridEl.innerHTML = VaultState.filtered.map(renderEntryCard).join('');
    if (listEl) listEl.style.display = 'none';
    if (gridEl) gridEl.style.display = '';
  }

  // Adicionar event listeners nas entradas
  attachEntryEvents();
}

function renderEntryRow(entry) {
  const initial  = (entry.title || '?')[0].toUpperCase();
  const strength = LKCrypto.evaluatePasswordStrength(entry.password || '');
  const favicon  = entry.url ? LKUtils.getFaviconUrl(entry.url) : null;

  return `
    <div class="vault-entry" data-uuid="${LKUtils.escapeHtml(entry.uuid)}">
      <div class="entry-favicon">
        ${favicon
          ? `<img src="${LKUtils.escapeHtml(favicon)}" alt="" onerror="this.style.display='none';this.nextElementSibling.style.display='block'"><span class="favicon-letter" style="display:none">${LKUtils.escapeHtml(initial)}</span>`
          : `<span class="favicon-letter">${LKUtils.escapeHtml(initial)}</span>`}
      </div>
      <div class="entry-info">
        <div class="entry-title">${LKUtils.escapeHtml(entry.title || 'Sem título')}</div>
        <div class="entry-username">${LKUtils.escapeHtml(entry.username || entry.url || '—')}</div>
      </div>
      <div class="entry-meta">
        ${entry.is_favourite ? '<span style="font-size:14px">⭐</span>' : ''}
        <div class="strength-dot s${strength.score}" data-tooltip="${strength.label}"></div>
        <span style="font-size:11px;color:var(--text-muted)">${LKUtils.formatDate(entry.last_used || entry.updated_at)}</span>
      </div>
      <div class="entry-actions">
        <button class="btn btn-icon btn-ghost btn-sm copy-user-btn" data-uuid="${entry.uuid}" data-tooltip="Copiar utilizador">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        </button>
        <button class="btn btn-icon btn-ghost btn-sm copy-pass-btn" data-uuid="${entry.uuid}" data-tooltip="Copiar password">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        </button>
        <button class="btn btn-icon btn-ghost btn-sm edit-entry-btn" data-uuid="${entry.uuid}" data-tooltip="Editar">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="btn btn-icon btn-ghost btn-sm delete-entry-btn" data-uuid="${entry.uuid}" data-tooltip="Eliminar" style="color:var(--danger)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        </button>
      </div>
    </div>
  `;
}

function renderEntryCard(entry) {
  const initial  = (entry.title || '?')[0].toUpperCase();
  const strength = LKCrypto.evaluatePasswordStrength(entry.password || '');
  const favicon  = entry.url ? LKUtils.getFaviconUrl(entry.url) : null;

  return `
    <div class="vault-card" data-uuid="${LKUtils.escapeHtml(entry.uuid)}">
      <div class="vault-card-header">
        <div class="entry-favicon">
          ${favicon
            ? `<img src="${LKUtils.escapeHtml(favicon)}" alt="" onerror="this.style.display='none';this.nextElementSibling.style.display='block'"><span class="favicon-letter" style="display:none">${LKUtils.escapeHtml(initial)}</span>`
            : `<span class="favicon-letter">${LKUtils.escapeHtml(initial)}</span>`}
        </div>
        ${entry.is_favourite ? '<span style="font-size:12px">⭐</span>' : ''}
      </div>
      <div class="vault-card-title">${LKUtils.escapeHtml(entry.title || 'Sem título')}</div>
      <div class="vault-card-username">${LKUtils.escapeHtml(entry.username || entry.url || '—')}</div>
      <div class="vault-card-footer">
        <div class="strength-dot s${strength.score}" style="width:10px;height:10px" data-tooltip="${strength.label}"></div>
        <div style="display:flex;gap:4px">
          <button class="btn btn-icon btn-ghost btn-sm copy-pass-btn" data-uuid="${entry.uuid}" data-tooltip="Copiar password">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </button>
          <button class="btn btn-icon btn-ghost btn-sm edit-entry-btn" data-uuid="${entry.uuid}" data-tooltip="Editar">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          </button>
        </div>
      </div>
    </div>
  `;
}

function attachEntryEvents() {
  // Clicar na entrada → mostrar detalhes
  document.querySelectorAll('.vault-entry, .vault-card').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      const uuid = el.dataset.uuid;
      showEntryDetail(uuid);
    });
  });

  // Copiar utilizador
  document.querySelectorAll('.copy-user-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const entry = VaultState.entries.find(e => e.uuid === btn.dataset.uuid);
      if (entry?.username) LKUtils.copyToClipboard(entry.username, 'Utilizador copiado!');
    });
  });

  // Copiar password
  document.querySelectorAll('.copy-pass-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const entry = VaultState.entries.find(e => e.uuid === btn.dataset.uuid);
      if (entry?.password) {
        await LKUtils.copyToClipboard(entry.password, 'Password copiada!');
        // Registar uso
        LKApi.updateVaultEntry({ uuid: entry.uuid, update_last_used: true });
      }
    });
  });

  // Editar entrada
  document.querySelectorAll('.edit-entry-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const entry = VaultState.entries.find(e => e.uuid === btn.dataset.uuid);
      if (entry) openEntryModal(entry);
    });
  });

  // Eliminar entrada
  document.querySelectorAll('.delete-entry-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openDeleteModal(btn.dataset.uuid);
    });
  });
}

// ============================================================
// FILTROS E PESQUISA
// ============================================================

function applyFilters() {
  let result = [...VaultState.entries];

  // Filtro de tipo
  if (VaultState.filter === 'favourite') {
    result = result.filter(e => e.is_favourite);
  } else if (VaultState.filter === 'weak') {
    result = result.filter(e => {
      const s = LKCrypto.evaluatePasswordStrength(e.password || '');
      return s.score <= 1;
    });
  }

  // Filtro de categoria
  if (VaultState.category) {
    result = result.filter(e =>
      (e.category || '').toLowerCase() === VaultState.category.toLowerCase()
    );
  }

  // Pesquisa (client-side nos dados desencriptados)
  if (VaultState.searchQuery) {
    const q = VaultState.searchQuery.toLowerCase();
    result = result.filter(e =>
      (e.title || '').toLowerCase().includes(q) ||
      (e.username || '').toLowerCase().includes(q) ||
      (e.url || '').toLowerCase().includes(q) ||
      (e.category || '').toLowerCase().includes(q) ||
      (e.tags || '').toLowerCase().includes(q)
    );
  }

  VaultState.filtered = result;
}

function populateCategoryFilter() {
  const select = document.getElementById('category-filter');
  if (!select) return;

  const categories = [...new Set(
    VaultState.entries.map(e => e.category).filter(Boolean)
  )].sort();

  const current = select.value;
  select.innerHTML = '<option value="">Todas as categorias</option>' +
    categories.map(c => `<option value="${LKUtils.escapeHtml(c)}">${LKUtils.escapeHtml(c)}</option>`).join('');
  select.value = current;
}

function updateCounts() {
  const navBadge = document.getElementById('vault-count');
  if (navBadge) navBadge.textContent = VaultState.entries.length;
}

// ============================================================
// PAINEL DE DETALHES
// ============================================================

function showEntryDetail(uuid) {
  const entry = VaultState.entries.find(e => e.uuid === uuid);
  if (!entry) return;

  VaultState.currentEntry = entry;

  const panel = document.getElementById('entry-detail-panel');
  if (!panel) return;

  panel.style.display = 'flex';
  panel.style.flexDirection = 'column';

  const strength = LKCrypto.evaluatePasswordStrength(entry.password || '');

  panel.innerHTML = `
    <div class="detail-header">
      <div class="entry-favicon">
        <span class="favicon-letter">${LKUtils.escapeHtml((entry.title || '?')[0].toUpperCase())}</span>
      </div>
      <div style="flex:1;min-width:0">
        <div style="font-weight:700;font-size:16px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${LKUtils.escapeHtml(entry.title || 'Sem título')}</div>
        <div style="font-size:11px;color:var(--text-muted)">${LKUtils.formatDate(entry.updated_at)}</div>
      </div>
      <button class="btn btn-icon btn-ghost" onclick="document.getElementById('entry-detail-panel').style.display='none'">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="detail-body">
      ${entry.url ? `
      <div class="detail-field">
        <div class="detail-field-label">Website</div>
        <div class="detail-field-value">
          <span class="value-text">${LKUtils.escapeHtml(entry.url)}</span>
          <a href="${LKUtils.escapeHtml(entry.url)}" target="_blank" rel="noopener noreferrer" class="btn btn-icon btn-ghost btn-sm" data-tooltip="Abrir">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>
      </div>` : ''}
      ${entry.username ? `
      <div class="detail-field">
        <div class="detail-field-label">Utilizador / Email</div>
        <div class="detail-field-value">
          <span class="value-text">${LKUtils.escapeHtml(entry.username)}</span>
          <button class="btn btn-icon btn-ghost btn-sm" onclick="LKUtils.copyToClipboard('${LKUtils.escapeHtml(entry.username)}', 'Utilizador copiado!')" data-tooltip="Copiar">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      </div>` : ''}
      <div class="detail-field">
        <div class="detail-field-label">Password</div>
        <div class="detail-field-value password hidden" id="detail-pass-field">
          <span class="value-text" id="detail-pass-text">••••••••••••</span>
          <button class="btn btn-icon btn-ghost btn-sm" id="toggle-detail-pass" data-tooltip="Mostrar">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
          <button class="btn btn-icon btn-ghost btn-sm" onclick="LKUtils.copyToClipboard('${LKUtils.escapeHtml(entry.password)}', 'Password copiada!')" data-tooltip="Copiar">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
        <div style="margin-top:6px;display:flex;align-items:center;gap:6px">
          <div class="strength-dot s${strength.score}" style="width:8px;height:8px"></div>
          <span style="font-size:11px;color:${strength.color}">${strength.label}</span>
        </div>
      </div>
      ${entry.notes ? `
      <div class="detail-field">
        <div class="detail-field-label">Notas</div>
        <div style="padding:10px 14px;background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:var(--border-radius);font-size:13px;white-space:pre-wrap">${LKUtils.escapeHtml(entry.notes)}</div>
      </div>` : ''}
      ${entry.category ? `
      <div class="detail-field">
        <div class="detail-field-label">Categoria</div>
        <div class="detail-field-value"><span class="value-text">${LKUtils.escapeHtml(entry.category)}</span></div>
      </div>` : ''}
    </div>
    <div class="detail-footer">
      <button class="btn btn-secondary" style="flex:1" onclick="openEntryModal(VaultState.currentEntry)">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Editar
      </button>
      <button class="btn btn-ghost" style="color:var(--danger)" onclick="openDeleteModal('${entry.uuid}')">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        Eliminar
      </button>
    </div>
  `;

  // Toggle mostrar/ocultar password no painel
  const toggleBtn = document.getElementById('toggle-detail-pass');
  const passText  = document.getElementById('detail-pass-text');
  const passField = document.getElementById('detail-pass-field');
  let passwordVisible = false;

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      passwordVisible = !passwordVisible;
      if (passwordVisible) {
        passText.textContent = entry.password || '—';
        passField.classList.remove('hidden');
        LKApi.updateVaultEntry({ uuid: entry.uuid, update_last_used: true }).catch(() => {});
      } else {
        passText.textContent = '••••••••••••';
        passField.classList.add('hidden');
      }
    });
  }
}

// ============================================================
// MODAL ADICIONAR / EDITAR
// ============================================================

function openEntryModal(entry = null) {
  const modal     = document.getElementById('entry-modal');
  const titleEl   = document.getElementById('modal-title');
  const form      = document.getElementById('entry-form');

  if (!modal) return;

  // Limpar e preencher formulário
  form.reset();
  document.getElementById('entry-uuid').value        = entry?.uuid || '';
  document.getElementById('entry-title').value       = entry?.title || '';
  document.getElementById('entry-url').value         = entry?.url || '';
  document.getElementById('entry-username').value    = entry?.username || '';
  document.getElementById('entry-password').value    = entry?.password || '';
  document.getElementById('entry-notes').value       = entry?.notes || '';
  document.getElementById('entry-category').value   = entry?.category || '';
  document.getElementById('entry-tags').value        = entry?.tags || '';
  document.getElementById('entry-favourite').checked = entry?.is_favourite || false;

  titleEl.textContent = entry ? 'Editar Entrada' : 'Nova Entrada';

  // Mostrar indicador de força inicial
  if (entry?.password) {
    const strength = LKCrypto.evaluatePasswordStrength(entry.password);
    document.getElementById('modal-strength-text').textContent = strength.label;
    document.getElementById('modal-strength').querySelector('.strength-bar').className =
      `strength-bar strength-${strength.score}`;
  }

  modal.classList.add('active');
}

function closeEntryModal() {
  const modal = document.getElementById('entry-modal');
  if (modal) modal.classList.remove('active');
}

// ============================================================
// MODAL DE ELIMINAÇÃO
// ============================================================

let _deleteUuid = null;

function openDeleteModal(uuid) {
  _deleteUuid = uuid;
  const modal = document.getElementById('delete-modal');
  if (modal) modal.classList.add('active');
}

// ============================================================
// GERADOR DE PASSWORDS
// ============================================================

function initPasswordGenerator() {
  const genBtn  = document.getElementById('generate-password-btn');
  const passInput = document.getElementById('entry-password');

  if (genBtn && passInput) {
    genBtn.addEventListener('click', () => {
      const password = LKCrypto.generatePassword({
        length: 20, uppercase: true, lowercase: true, digits: true, symbols: true
      });
      passInput.value = password;
      passInput.type = 'text';
      updateModalStrength(password);
      LKToast.info('Password gerada!', 2000);
    });
  }

  if (passInput) {
    passInput.addEventListener('input', () => updateModalStrength(passInput.value));
  }
}

function updateModalStrength(password) {
  const strengthText = document.getElementById('modal-strength-text');
  const strengthBar  = document.getElementById('modal-strength')?.querySelector('.strength-bar');
  if (!password || !strengthText || !strengthBar) return;

  const strength = LKCrypto.evaluatePasswordStrength(password);
  strengthText.textContent = strength.label;
  strengthText.style.color = strength.color;
  strengthBar.className = `strength-bar strength-${strength.score}`;
}

// ============================================================
// EVENT LISTENERS
// ============================================================

function initVaultEvents() {
  // Pesquisa
  const searchInput = document.getElementById('global-search');
  if (searchInput) {
    searchInput.addEventListener('input', LKUtils.debounce((e) => {
      VaultState.searchQuery = e.target.value.trim();
      renderEntries();
    }, 200));
  }

  // Filtros
  document.querySelectorAll('.filter-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      VaultState.filter = tab.dataset.filter;
      renderEntries();
    });
  });

  // Filtro de categoria
  const catFilter = document.getElementById('category-filter');
  if (catFilter) {
    catFilter.addEventListener('change', () => {
      VaultState.category = catFilter.value;
      renderEntries();
    });
  }

  // Vista lista/grelha
  const viewListBtn = document.getElementById('view-list');
  const viewGridBtn = document.getElementById('view-grid');
  if (viewListBtn) {
    viewListBtn.addEventListener('click', () => {
      VaultState.view = 'list';
      viewListBtn.classList.add('active');
      viewGridBtn?.classList.remove('active');
      renderEntries();
    });
  }
  if (viewGridBtn) {
    viewGridBtn.addEventListener('click', () => {
      VaultState.view = 'grid';
      viewGridBtn.classList.add('active');
      viewListBtn?.classList.remove('active');
      renderEntries();
    });
  }

  // Botão nova entrada
  document.getElementById('new-entry-btn')?.addEventListener('click', () => openEntryModal());
  document.getElementById('empty-add-btn')?.addEventListener('click', () => openEntryModal());

  // Modal fechar
  document.getElementById('modal-close')?.addEventListener('click', closeEntryModal);
  document.getElementById('modal-cancel')?.addEventListener('click', closeEntryModal);
  document.getElementById('entry-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeEntryModal();
  });

  // Toggle password no modal
  document.getElementById('toggle-entry-pass')?.addEventListener('click', () => {
    const input = document.getElementById('entry-password');
    if (input) input.type = input.type === 'password' ? 'text' : 'password';
  });

  // Submissão do formulário de entrada
  document.getElementById('entry-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await saveEntry();
  });

  // Modal de eliminação
  document.getElementById('delete-cancel')?.addEventListener('click', () => {
    document.getElementById('delete-modal').classList.remove('active');
  });

  document.getElementById('delete-confirm')?.addEventListener('click', async () => {
    if (_deleteUuid) {
      await deleteEntry(_deleteUuid);
      document.getElementById('delete-modal').classList.remove('active');
      _deleteUuid = null;
    }
  });
}

// ============================================================
// OPERAÇÕES CRUD
// ============================================================

async function saveEntry() {
  const key = LKCrypto.getSessionKey();
  if (!key) {
    LKToast.error('Sessão expirada.');
    return;
  }

  const uuid     = document.getElementById('entry-uuid').value;
  const title    = document.getElementById('entry-title').value.trim();
  const password = document.getElementById('entry-password').value;

  if (!title || !password) {
    LKToast.error('Título e password são obrigatórios.');
    return;
  }

  const entry = {
    title,
    url:         document.getElementById('entry-url').value.trim(),
    username:    document.getElementById('entry-username').value.trim(),
    password,
    notes:       document.getElementById('entry-notes').value.trim(),
    category:    document.getElementById('entry-category').value.trim(),
    tags:        document.getElementById('entry-tags').value.trim(),
    is_favourite: document.getElementById('entry-favourite').checked,
    strength_score: LKCrypto.evaluatePasswordStrength(password).score,
  };

  const saveBtn = document.getElementById('modal-save');
  LKUtils.setButtonLoading(saveBtn, true);

  try {
    // Encriptar dados no cliente antes de enviar
    const encEntry = await LKCrypto.encryptEntry(entry, key);

    if (uuid) {
      // Atualizar entrada existente
      encEntry.uuid = uuid;
      await LKApi.updateVaultEntry(encEntry);
      LKToast.success('Entrada atualizada!');
    } else {
      // Criar nova entrada
      const res = await LKApi.createVaultEntry(encEntry);
      entry.uuid = res.data.uuid;
      entry.created_at = res.data.created_at;
    }

    closeEntryModal();
    await loadVaultEntries(); // Recarregar lista

  } catch (err) {
    LKToast.error('Erro ao guardar: ' + err.message);
  } finally {
    LKUtils.setButtonLoading(saveBtn, false);
  }
}

async function deleteEntry(uuid) {
  try {
    await LKApi.deleteVaultEntry(uuid);
    LKToast.success('Entrada eliminada.');

    // Fechar painel de detalhes se estava aberto
    const panel = document.getElementById('entry-detail-panel');
    if (VaultState.currentEntry?.uuid === uuid) {
      if (panel) panel.style.display = 'none';
      VaultState.currentEntry = null;
    }

    await loadVaultEntries();
  } catch (err) {
    LKToast.error('Erro ao eliminar: ' + err.message);
  }
}

// Tornar funções disponíveis globalmente (chamadas inline no HTML)
window.openEntryModal = openEntryModal;
window.openDeleteModal = openDeleteModal;
window.VaultState = VaultState;
