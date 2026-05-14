/**
 * Lock & Key - Lógica do Dashboard
 */

'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  if (!await requireAuth()) return;
  initDashboardLayout();
  LKAutoLock.init();
  await loadDashboardData();
});

async function loadDashboardData() {
  const key = LKCrypto.getSessionKey();
  if (!key) return;

  const user = LKApi.getStoredUser();

  // Atualizar nome de boas-vindas
  const welcomeEl = document.getElementById('welcome-name');
  if (welcomeEl && user) welcomeEl.textContent = user.username || 'utilizador';

  try {
    // Carregar entradas e notas em paralelo
    const [encEntries, encNotes] = await Promise.all([
      LKApi.getVaultEntries(),
      LKApi.getNotes(),
    ]);

    const entries = await LKCrypto.decryptAllEntries(encEntries, key);
    const notes   = await LKCrypto.decryptAllNotes(encNotes, key);

    // Atualizar estatísticas
    document.getElementById('stat-total').textContent  = entries.length;
    document.getElementById('stat-notes').textContent  = notes.length;
    document.getElementById('vault-count').textContent = entries.length;

    const strongEntries = entries.filter(e => {
      const s = LKCrypto.evaluatePasswordStrength(e.password || '');
      return s.score >= 3;
    });
    const weakEntries = entries.filter(e => {
      const s = LKCrypto.evaluatePasswordStrength(e.password || '');
      return s.score <= 1;
    });

    document.getElementById('stat-strong').textContent = strongEntries.length;
    document.getElementById('stat-weak').textContent   = weakEntries.length;

    // Entradas recentes (ordenadas por last_used ou updated_at)
    const recent = [...entries]
      .sort((a, b) => new Date(b.last_used || b.updated_at) - new Date(a.last_used || a.updated_at))
      .slice(0, 5);

    renderRecentEntries(recent);
    renderFavourites(entries.filter(e => e.is_favourite).slice(0, 6));

  } catch (err) {
    LKToast.error('Erro ao carregar dashboard: ' + err.message);
  }
}

function renderRecentEntries(entries) {
  const container = document.getElementById('recent-entries');
  if (!container) return;

  if (entries.length === 0) {
    container.innerHTML = `
      <div style="text-align:center;padding:32px;color:var(--text-muted);font-size:13px;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:var(--border-radius-lg)">
        Nenhuma entrada usada recentemente. <a href="vault.html">Ir para o cofre →</a>
      </div>
    `;
    return;
  }

  container.innerHTML = entries.map(entry => {
    const initial  = (entry.title || '?')[0].toUpperCase();
    const strength = LKCrypto.evaluatePasswordStrength(entry.password || '');
    const favicon  = entry.url ? LKUtils.getFaviconUrl(entry.url) : null;

    return `
      <div class="vault-entry" style="cursor:pointer" onclick="window.location.href='vault.html'">
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
          <div class="strength-dot s${strength.score}" data-tooltip="${strength.label}"></div>
          <span style="font-size:11px;color:var(--text-muted)">${LKUtils.formatDate(entry.last_used || entry.updated_at)}</span>
        </div>
        <div class="entry-actions">
          <button class="btn btn-icon btn-ghost btn-sm copy-pass-btn" data-uuid="${LKUtils.escapeHtml(entry.uuid || '')}" data-tooltip="Copiar password">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </button>
        </div>
      </div>
    `;
  }).join('');

  // Listeners dedicados (evitam interpolar segredos no HTML)
  container.querySelectorAll('.copy-pass-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const uuid = btn.dataset.uuid;
      const entry = entries.find(x => x.uuid === uuid);
      if (entry?.password) {
        await LKUtils.copyToClipboard(entry.password, 'Password copiada!');
      }
    });
  });
}

function renderFavourites(entries) {
  const container = document.getElementById('favourite-entries');
  const emptyEl   = document.getElementById('favourites-empty');

  if (!container) return;

  if (entries.length === 0) {
    if (emptyEl) emptyEl.classList.remove('hidden');
    return;
  }

  if (emptyEl) emptyEl.classList.add('hidden');

  container.innerHTML = entries.map(entry => {
    const initial  = (entry.title || '?')[0].toUpperCase();
    const strength = LKCrypto.evaluatePasswordStrength(entry.password || '');

    return `
      <div class="vault-card" onclick="window.location.href='vault.html'">
        <div class="vault-card-header">
          <div class="entry-favicon"><span class="favicon-letter">${LKUtils.escapeHtml(initial)}</span></div>
          <span style="font-size:14px">⭐</span>
        </div>
        <div class="vault-card-title">${LKUtils.escapeHtml(entry.title || 'Sem título')}</div>
        <div class="vault-card-username">${LKUtils.escapeHtml(entry.username || entry.url || '—')}</div>
        <div class="vault-card-footer">
          <div class="strength-dot s${strength.score}" style="width:10px;height:10px"></div>
          <button class="btn btn-icon btn-ghost btn-sm copy-fav-btn" data-uuid="${LKUtils.escapeHtml(entry.uuid || '')}" data-tooltip="Copiar">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </button>
        </div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.copy-fav-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const uuid = btn.dataset.uuid;
      const entry = entries.find(x => x.uuid === uuid);
      if (entry?.password) {
        await LKUtils.copyToClipboard(entry.password, 'Password copiada!');
      }
    });
  });
}
