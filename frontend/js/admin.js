/**
 * Lock & Key — Admin Panel
 * Gestão de utilizadores, audit log e criação de admins.
 * Acesso restrito a roles: admin | admin_master
 */

'use strict';

// ============================================================
// Estado
// ============================================================
const AdminState = {
    user:          null,
    currentSection:'overview',
    users: {
        list:  [],
        page:  1,
        total: 0,
        pages: 0,
        search: '',
        role:   '',
        plan:   '',
        status: '',
    },
    audit: {
        list:  [],
        page:  1,
        total: 0,
        pages: 0,
        search: '',
        action: '',
        actions: [],
    },
    suspendTarget: null,
    suspendAction: null,
};

// Permissões por role
const ROLE_PERMISSIONS = {
    admin: [
        { label: 'Ver lista de utilizadores',          allowed: true  },
        { label: 'Suspender utilizadores normais',     allowed: true  },
        { label: 'Ver audit log (utilizadores)',       allowed: true  },
        { label: 'Criar contas Admin',                 allowed: false },
        { label: 'Alterar role de utilizadores',       allowed: false },
        { label: 'Alterar plano de utilizadores',      allowed: false },
        { label: 'Eliminar utilizadores',              allowed: false },
        { label: 'Ver outros admins',                  allowed: false },
    ],
    admin_master: [
        { label: 'Ver lista de utilizadores',          allowed: true  },
        { label: 'Suspender / banir utilizadores',     allowed: true  },
        { label: 'Ver audit log completo',             allowed: true  },
        { label: 'Criar contas Admin / Admin Master',  allowed: true  },
        { label: 'Alterar role de qualquer utilizador',allowed: true  },
        { label: 'Alterar plano de qualquer utilizador',allowed: true },
        { label: 'Eliminar utilizadores permanentemente',allowed: true},
        { label: 'Acesso total ao sistema',            allowed: true  },
    ],
};

// ============================================================
// Inicialização
// ============================================================
document.addEventListener('DOMContentLoaded', async () => {
    // Verificar autenticação (token JWT)
    if (!LKApi.isLoggedIn()) {
        window.location.href = '/Lock%26Key/frontend/login.html';
        return;
    }

    // O admin panel não necessita da chave de encriptação para funcionar,
    // mas precisa de um token válido para as chamadas à API.
    try {
        // LKApi.getProfile() retorna res.data que agora tem formato { user: {...} }
        const profileData = await LKApi.getProfile();
        // Suportar ambos os formatos por compatibilidade
        const u = profileData?.user ?? profileData;

        if (!u?.role) {
            LKToast.error('Não foi possível obter o perfil ou role.');
            setTimeout(() => { window.location.href = '/Lock%26Key/frontend/login.html'; }, 1500);
            return;
        }

        AdminState.user = u;

        if (!['admin', 'admin_master'].includes(u.role)) {
            LKToast.error('Sem permissão para aceder ao painel admin.');
            setTimeout(() => { window.location.href = '/Lock%26Key/frontend/dashboard.html'; }, 1500);
            return;
        }

        initUI(u);
        loadOverview();
    } catch (e) {
        console.error('Admin init error:', e);
        LKToast.error('Erro ao carregar painel: ' + (e.message || 'Tenta novamente.'));
        setTimeout(() => { window.location.href = '/Lock%26Key/frontend/login.html'; }, 2000);
    }
});

// ============================================================
// Init UI
// ============================================================
function initUI(user) {
    // Sidebar info
    const avatar = LKUtils.getInitials(user.username);
    document.getElementById('sidebarAvatar').textContent   = avatar;
    document.getElementById('sidebarUsername').textContent = user.username;

    // Role badge
    const isMaster = user.role === 'admin_master';
    const roleBadgeHTML = isMaster
        ? '<span class="role-badge master">👑 Admin Master</span>'
        : '<span class="role-badge admin">🛡️ Admin</span>';

    document.getElementById('sidebarRole').innerHTML    = roleBadgeHTML;
    document.getElementById('headerRoleBadge').outerHTML = roleBadgeHTML;

    // Mostrar elementos exclusivos do admin_master
    if (isMaster) {
        document.querySelectorAll('.master-only').forEach(el => el.classList.remove('hidden'));
    }

    // Navegação de secções
    document.querySelectorAll('.nav-link[data-section]').forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            switchSection(link.dataset.section);
        });
    });

    // Tema
    LKTheme.init();
    document.getElementById('themeToggle')?.addEventListener('click', () => LKTheme.toggle());

    // Sidebar toggle
    document.getElementById('menuToggle')?.addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
    });
    document.getElementById('sidebarToggle')?.addEventListener('click', () => {
        document.getElementById('sidebar').classList.remove('open');
    });

    // Logout
    document.getElementById('logoutBtn')?.addEventListener('click', async e => {
        e.preventDefault();
        await LKApi.logout();
        window.location.href = '/Lock%26Key/frontend/login.html';
    });

    // Pesquisa utilizadores (debounce)
    document.getElementById('userSearch')?.addEventListener('input',
        LKUtils.debounce(e => {
            AdminState.users.search = e.target.value;
            AdminState.users.page   = 1;
            loadUsers();
        }, 400)
    );

    // Filtros utilizadores
    ['filterRole', 'filterPlan', 'filterStatus'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', e => {
            AdminState.users[id.replace('filter','').toLowerCase()] = e.target.value;
            AdminState.users.page = 1;
            loadUsers();
        });
    });

    // Pesquisa audit
    document.getElementById('auditSearch')?.addEventListener('input',
        LKUtils.debounce(e => {
            AdminState.audit.search = e.target.value;
            AdminState.audit.page   = 1;
            loadAudit();
        }, 400)
    );
    document.getElementById('filterAction')?.addEventListener('change', e => {
        AdminState.audit.action = e.target.value;
        AdminState.audit.page   = 1;
        loadAudit();
    });

    // Criar admin form
    document.getElementById('createAdminForm')?.addEventListener('submit', handleCreateAdmin);
    document.getElementById('newAdminRole')?.addEventListener('change', updatePermissionsPreview);
    document.getElementById('newAdminPassword')?.addEventListener('input', e => {
        const s = LKCrypto.evaluatePasswordStrength(e.target.value);
        const bar = document.getElementById('newAdminStrengthBar');
        const txt = document.getElementById('newAdminStrengthText');
        if (bar) { bar.style.width = `${(s.score + 1) * 20}%`; bar.style.background = s.color; }
        if (txt)   txt.textContent = s.label;
    });
    document.getElementById('toggleNewAdminPass')?.addEventListener('click', () => {
        const inp = document.getElementById('newAdminPassword');
        inp.type = inp.type === 'password' ? 'text' : 'password';
    });

    updatePermissionsPreview();

    // Modais
    document.getElementById('userModalClose')?.addEventListener('click', () => closeModal('userModal'));
    document.getElementById('suspendModalClose')?.addEventListener('click', () => closeModal('suspendModal'));
    document.getElementById('suspendCancelBtn')?.addEventListener('click', () => closeModal('suspendModal'));
    document.getElementById('suspendConfirmBtn')?.addEventListener('click', confirmSuspend);
}

// ============================================================
// Navegação entre secções
// ============================================================
function switchSection(name) {
    AdminState.currentSection = name;

    document.querySelectorAll('.admin-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

    const section = document.getElementById(`section-${name}`);
    if (section) section.classList.add('active');

    const link = document.querySelector(`.nav-link[data-section="${name}"]`);
    if (link) link.classList.add('active');

    // Título da página
    const titles = {
        overview:     ['Visão Geral',        'Painel de Administração'],
        users:        ['Utilizadores',        'Gestão de contas'],
        audit:        ['Audit Log',           'Registo de eventos de segurança'],
        'create-admin':['Criar Administrador','Apenas Admin Master'],
    };
    const [title, sub] = titles[name] ?? ['Admin', ''];
    document.getElementById('pageTitle').textContent    = title;
    document.getElementById('pageSubtitle').textContent = sub;

    // Carregar dados na primeira vez
    if (name === 'users'  && AdminState.users.list.length === 0)  loadUsers();
    if (name === 'audit'  && AdminState.audit.list.length === 0)  loadAudit();
}

// ============================================================
// Visão Geral — Stats
// ============================================================
async function loadOverview() {
    try {
        const res = await LKApi.request('GET', '/admin/stats.php');
        if (!res.success) return;

        const d = res.data;

        // Stats numéricas
        document.getElementById('statTotalUsers').textContent    = d.totals.total_users ?? 0;
        document.getElementById('statVaultEntries').textContent  = d.totals.total_vault_entries ?? 0;
        document.getElementById('statNotes').textContent         = d.totals.total_notes ?? 0;
        document.getElementById('statActiveSessions').textContent= d.totals.active_sessions ?? 0;

        // Gráfico de registos
        renderRegistrationsChart(d.registrations ?? []);

        // Distribuição de planos
        renderPlanBars(d.totals);

        // Últimos logins
        renderRecentLogins(d.recent_logins ?? []);

    } catch (e) {
        console.error('Erro ao carregar estatísticas:', e);
    }
}

function renderRegistrationsChart(data) {
    const container = document.getElementById('registrationsChart');
    if (!container) return;

    if (data.length === 0) {
        container.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:3rem">Sem dados ainda.</p>';
        return;
    }

    const max = Math.max(...data.map(d => d.count), 1);
    container.innerHTML = `
        <div class="chart-bars">
            ${data.map(d => `
                <div class="chart-bar-col" title="${d.day}: ${d.count} registos">
                    <div class="chart-bar" style="height:${Math.max(4, (d.count / max) * 140)}px"></div>
                    <div class="chart-label">${d.day.slice(5)}</div>
                </div>
            `).join('')}
        </div>
    `;
}

function renderPlanBars(totals) {
    const container = document.getElementById('plansChart');
    if (!container) return;

    const total = (totals.total_users || 0) + (totals.total_admins || 0) + (totals.total_masters || 0);
    const plans = [
        { key: 'free',      label: 'Free',      count: totals.plan_free      ?? 0 },
        { key: 'pro',       label: 'Pro',       count: totals.plan_pro       ?? 0 },
        { key: 'unlimited', label: 'Unlimited', count: totals.plan_unlimited ?? 0 },
    ];

    container.innerHTML = plans.map(p => `
        <div class="plan-bar-row">
            <div class="plan-bar-label">${p.label}</div>
            <div class="plan-bar-track">
                <div class="plan-bar-fill ${p.key}" style="width:${total > 0 ? (p.count / total * 100).toFixed(1) : 0}%"></div>
            </div>
            <div class="plan-bar-count">${p.count}</div>
        </div>
    `).join('');
}

function renderRecentLogins(logins) {
    const container = document.getElementById('recentLogins');
    if (!container) return;

    if (logins.length === 0) {
        container.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem">Nenhum login recente.</p>';
        return;
    }

    container.innerHTML = logins.map(u => `
        <div class="recent-item">
            <div class="recent-avatar">${LKUtils.getInitials(u.username)}</div>
            <div>
                <div class="recent-name">${LKUtils.escapeHtml(u.username)}</div>
                <div class="recent-time">${LKUtils.formatDate(u.last_login)}</div>
            </div>
            <span class="recent-ip">${LKUtils.escapeHtml(u.last_login_ip ?? '—')}</span>
        </div>
    `).join('');
}

// ============================================================
// Utilizadores
// ============================================================
async function loadUsers() {
    const tbody = document.getElementById('usersTableBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="table-loading">A carregar…</td></tr>';

    const { page, search, role, plan, status } = AdminState.users;
    const params = new URLSearchParams({ page, limit: 25 });
    if (search) params.set('search', search);
    if (role)   params.set('role',   role);
    if (plan)   params.set('plan',   plan);
    if (status) params.set('status', status);

    try {
        const res = await LKApi.request('GET', `/admin/users.php?${params}`);
        if (!res.success) throw new Error(res.message);

        AdminState.users.list  = res.data.users;
        AdminState.users.total = res.data.pagination.total;
        AdminState.users.pages = res.data.pagination.pages;

        renderUsersTable(res.data.users);
        renderPagination('usersPagination', res.data.pagination, p => {
            AdminState.users.page = p;
            loadUsers();
        });
    } catch (e) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="table-loading" style="color:var(--error)">${LKUtils.escapeHtml(e.message)}</td></tr>`;
    }
}

function renderUsersTable(users) {
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) return;

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="table-loading">Nenhum utilizador encontrado.</td></tr>';
        return;
    }

    const isMaster = AdminState.user?.role === 'admin_master';

    tbody.innerHTML = users.map(u => `
        <tr>
            <td>
                <div class="user-cell">
                    <div class="user-cell-avatar">${LKUtils.getInitials(u.username)}</div>
                    <div class="user-cell-info">
                        <div class="user-cell-name">${LKUtils.escapeHtml(u.username)}</div>
                        <div class="user-cell-email">${LKUtils.escapeHtml(u.email)}</div>
                    </div>
                </div>
            </td>
            <td>${roleBadge(u.role)}</td>
            <td>${planBadge(u.plan)}</td>
            <td>${statusBadge(u.status)}</td>
            <td style="text-align:center">${u.vault_count ?? 0}</td>
            <td style="font-size:0.8rem;color:var(--text-muted)">${u.last_login ? LKUtils.formatDate(u.last_login) : '—'}</td>
            <td>
                <div class="table-actions">
                    <button class="table-btn" onclick="openUserModal(${u.id})">Ver</button>
                    ${u.status === 'active' && u.role !== 'admin_master' ? `
                        <button class="table-btn danger" onclick="openSuspendModal(${u.id}, '${LKUtils.escapeHtml(u.username)}', 'suspend')">Suspender</button>
                    ` : ''}
                    ${u.status !== 'active' ? `
                        <button class="table-btn" onclick="reactivateUser(${u.id})">Reativar</button>
                    ` : ''}
                    ${isMaster && u.role !== 'admin_master' ? `
                        <button class="table-btn danger" onclick="openSuspendModal(${u.id}, '${LKUtils.escapeHtml(u.username)}', 'ban')">Banir</button>
                    ` : ''}
                </div>
            </td>
        </tr>
    `).join('');
}

// ============================================================
// Modal: Detalhes do Utilizador
// ============================================================
async function openUserModal(userId) {
    const modal = document.getElementById('userModal');
    const body  = document.getElementById('userModalBody');
    const footer= document.getElementById('userModalFooter');

    body.innerHTML  = '<div style="text-align:center;padding:2rem;color:var(--text-muted)">A carregar…</div>';
    footer.innerHTML= '';
    modal.classList.add('active');

    try {
        const res = await LKApi.request('GET', `/admin/users.php?id=${userId}`);
        if (!res.success) throw new Error(res.message);

        const u       = res.data.user;
        const isMaster = AdminState.user?.role === 'admin_master';

        document.getElementById('userModalTitle').textContent = `Utilizador #${u.id}`;

        body.innerHTML = `
            <div class="user-detail-header">
                <div class="user-detail-avatar">${LKUtils.getInitials(u.username)}</div>
                <div>
                    <div class="user-detail-name">${LKUtils.escapeHtml(u.username)}</div>
                    <div class="user-detail-email">${LKUtils.escapeHtml(u.email)}</div>
                    <div class="user-detail-badges">
                        ${roleBadge(u.role)}
                        ${planBadge(u.plan)}
                        ${statusBadge(u.status)}
                    </div>
                </div>
            </div>

            <div class="detail-grid">
                <div class="detail-item"><label>UUID</label><span style="font-family:monospace;font-size:0.75rem">${u.uuid}</span></div>
                <div class="detail-item"><label>Conta criada</label><span>${LKUtils.formatDate(u.created_at)}</span></div>
                <div class="detail-item"><label>Último login</label><span>${u.last_login ? LKUtils.formatDate(u.last_login) : '—'}</span></div>
                <div class="detail-item"><label>Último IP</label><span style="font-family:monospace">${u.last_login_ip ?? '—'}</span></div>
                <div class="detail-item"><label>Passwords</label><span>${u.vault_count}</span></div>
                <div class="detail-item"><label>Notas</label><span>${u.notes_count}</span></div>
                <div class="detail-item"><label>Sessões ativas</label><span>${u.active_sessions}</span></div>
                <div class="detail-item"><label>Email verificado</label><span>${u.email_verified ? '✅ Sim' : '❌ Não'}</span></div>
            </div>

            ${isMaster ? `
            <div class="edit-fields">
                <div class="edit-row">
                    <div class="form-group">
                        <label class="form-label">Role</label>
                        <select id="editRole_${u.id}" class="form-select">
                            <option value="user"         ${u.role === 'user'         ? 'selected' : ''}>Utilizador</option>
                            <option value="admin"        ${u.role === 'admin'        ? 'selected' : ''}>Admin</option>
                            <option value="admin_master" ${u.role === 'admin_master' ? 'selected' : ''}>Admin Master</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Plano</label>
                        <select id="editPlan_${u.id}" class="form-select">
                            <option value="free"      ${u.plan === 'free'      ? 'selected' : ''}>Free</option>
                            <option value="pro"       ${u.plan === 'pro'       ? 'selected' : ''}>Pro</option>
                            <option value="unlimited" ${u.plan === 'unlimited' ? 'selected' : ''}>Unlimited</option>
                        </select>
                    </div>
                </div>
            </div>
            ` : ''}
        `;

        footer.innerHTML = `
            <button class="btn btn-ghost" onclick="closeModal('userModal')">Fechar</button>
            ${isMaster ? `<button class="btn btn-primary" onclick="saveUserChanges(${u.id})">Guardar Alterações</button>` : ''}
        `;

    } catch (e) {
        body.innerHTML = `<p style="color:var(--error);padding:1rem">${LKUtils.escapeHtml(e.message)}</p>`;
    }
}

async function saveUserChanges(userId) {
    const role = document.getElementById(`editRole_${userId}`)?.value;
    const plan = document.getElementById(`editPlan_${userId}`)?.value;

    try {
        const res = await LKApi.request('PATCH', '/admin/users.php', { user_id: userId, role, plan });
        if (!res.success) throw new Error(res.message);
        LKToast.success('Utilizador atualizado.');
        closeModal('userModal');
        loadUsers();
    } catch (e) {
        LKToast.error(e.message);
    }
}

// ============================================================
// Suspender / Banir / Reativar
// ============================================================
function openSuspendModal(userId, username, action) {
    AdminState.suspendTarget = userId;
    AdminState.suspendAction = action;

    document.getElementById('suspendModalTitle').textContent = action === 'ban' ? 'Banir Utilizador' : 'Suspender Utilizador';
    document.getElementById('suspendModalDesc').textContent  = `Confirmas que queres ${action === 'ban' ? 'banir' : 'suspender'} "${username}"?`;
    document.getElementById('suspendReason').value = '';
    document.getElementById('suspendConfirmBtn').className = 'btn btn-danger';
    document.getElementById('suspendModal').classList.add('active');
}

async function confirmSuspend() {
    const { suspendTarget, suspendAction } = AdminState;
    if (!suspendTarget) return;

    const reason  = document.getElementById('suspendReason').value.trim() || 'Conta suspensa por administrador.';
    const newStatus = suspendAction === 'ban' ? 'banned' : 'suspended';

    try {
        const res = await LKApi.request('PATCH', '/admin/users.php', {
            user_id: suspendTarget,
            status:  newStatus,
            reason,
        });
        if (!res.success) throw new Error(res.message);
        LKToast.success(`Utilizador ${suspendAction === 'ban' ? 'banido' : 'suspenso'} com sucesso.`);
        closeModal('suspendModal');
        loadUsers();
    } catch (e) {
        LKToast.error(e.message);
    }
}

async function reactivateUser(userId) {
    try {
        const res = await LKApi.request('PATCH', '/admin/users.php', { user_id: userId, status: 'active' });
        if (!res.success) throw new Error(res.message);
        LKToast.success('Utilizador reativado.');
        loadUsers();
    } catch (e) {
        LKToast.error(e.message);
    }
}

// ============================================================
// Audit Log
// ============================================================
async function loadAudit() {
    const tbody = document.getElementById('auditTableBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="table-loading">A carregar…</td></tr>';

    const { page, search, action } = AdminState.audit;
    const params = new URLSearchParams({ page, limit: 50 });
    if (search) params.set('search', search);
    if (action) params.set('action', action);

    try {
        const res = await LKApi.request('GET', `/admin/audit.php?${params}`);
        if (!res.success) throw new Error(res.message);

        AdminState.audit.list    = res.data.logs;
        AdminState.audit.total   = res.data.pagination.total;
        AdminState.audit.pages   = res.data.pagination.pages;
        AdminState.audit.actions = res.data.actions;

        // Popular filtro de ações
        const sel = document.getElementById('filterAction');
        if (sel && AdminState.audit.actions.length > 0) {
            const current = sel.value;
            sel.innerHTML = '<option value="">Todas as ações</option>' +
                res.data.actions.map(a => `<option value="${LKUtils.escapeHtml(a)}" ${a === current ? 'selected' : ''}>${LKUtils.escapeHtml(a)}</option>`).join('');
        }

        renderAuditTable(res.data.logs);
        renderPagination('auditPagination', res.data.pagination, p => {
            AdminState.audit.page = p;
            loadAudit();
        });
    } catch (e) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="table-loading" style="color:var(--error)">${LKUtils.escapeHtml(e.message)}</td></tr>`;
    }
}

function renderAuditTable(logs) {
    const tbody = document.getElementById('auditTableBody');
    if (!tbody) return;

    if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="table-loading">Nenhum registo encontrado.</td></tr>';
        return;
    }

    tbody.innerHTML = logs.map(log => {
        let details = '';
        try {
            const d = typeof log.details === 'string' ? JSON.parse(log.details) : log.details;
            if (d) details = Object.entries(d).map(([k,v]) => `${k}: ${v}`).join(', ');
        } catch(e) {}

        return `
            <tr>
                <td style="font-size:0.78rem;color:var(--text-muted);white-space:nowrap">${LKUtils.formatDate(log.created_at)}</td>
                <td>
                    ${log.username
                        ? `<span style="font-weight:500">${LKUtils.escapeHtml(log.username)}</span><br>
                           <span style="font-size:0.75rem;color:var(--text-muted)">${LKUtils.escapeHtml(log.email ?? '')}</span>`
                        : '<span style="color:var(--text-muted)">—</span>'
                    }
                </td>
                <td><code style="font-size:0.78rem;background:var(--bg-input);padding:0.15rem 0.4rem;border-radius:4px">${LKUtils.escapeHtml(log.action)}</code></td>
                <td style="font-family:monospace;font-size:0.78rem">${LKUtils.escapeHtml(log.ip_address ?? '—')}</td>
                <td style="font-size:0.78rem;color:var(--text-muted)">${LKUtils.escapeHtml(details || '—')}</td>
            </tr>
        `;
    }).join('');
}

// ============================================================
// Criar Conta Admin (apenas admin_master)
// ============================================================
async function handleCreateAdmin(e) {
    e.preventDefault();

    const username = document.getElementById('newAdminUsername').value.trim();
    const email    = document.getElementById('newAdminEmail').value.trim();
    const password = document.getElementById('newAdminPassword').value;
    const role     = document.getElementById('newAdminRole').value;
    const plan     = document.getElementById('newAdminPlan').value;
    const btn      = document.getElementById('createAdminBtn');

    if (!username || !email || !password) {
        LKToast.error('Preenche todos os campos.');
        return;
    }

    LKUtils.setButtonLoading(btn, true);

    try {
        // Gerar salt e derivar authKey localmente (zero-knowledge)
        const saltBytes = crypto.getRandomValues(new Uint8Array(32));
        const vaultSalt = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        const { authKey } = await LKCrypto.deriveKeys(password, vaultSalt);

        const res = await LKApi.request('POST', '/admin/users.php', {
            username,
            email,
            auth_key:   authKey,
            vault_salt: vaultSalt,
            role,
            plan,
        });

        if (!res.success) throw new Error(res.message);

        LKToast.success(`Conta ${role === 'admin_master' ? 'Admin Master' : 'Admin'} criada com sucesso!`);
        document.getElementById('createAdminForm').reset();
        updatePermissionsPreview();

    } catch (err) {
        LKToast.error(err.message ?? 'Erro ao criar conta.');
    } finally {
        LKUtils.setButtonLoading(btn, false);
    }
}

function updatePermissionsPreview() {
    const role = document.getElementById('newAdminRole')?.value ?? 'admin';
    const container = document.getElementById('permsList');
    if (!container) return;

    const perms = ROLE_PERMISSIONS[role] ?? [];
    container.innerHTML = perms.map(p => `
        <div class="perm-item ${p.allowed ? 'allowed' : 'denied'}">
            ${p.allowed ? '✅' : '❌'} ${LKUtils.escapeHtml(p.label)}
        </div>
    `).join('');
}

// ============================================================
// Helpers de badges
// ============================================================
function roleBadge(role) {
    const map = {
        admin_master: '<span class="role-badge master">👑 Master</span>',
        admin:        '<span class="role-badge admin">🛡️ Admin</span>',
        user:         '<span class="role-badge user">👤 User</span>',
    };
    return map[role] ?? `<span class="role-badge user">${LKUtils.escapeHtml(role)}</span>`;
}
function planBadge(plan) {
    const map = {
        unlimited: '<span class="plan-badge unlimited">♾️ Unlimited</span>',
        pro:       '<span class="plan-badge pro">⭐ Pro</span>',
        free:      '<span class="plan-badge free">🆓 Free</span>',
    };
    return map[plan] ?? `<span class="plan-badge free">${LKUtils.escapeHtml(plan)}</span>`;
}
function statusBadge(status) {
    const map = {
        active:    '<span class="status-badge active">Ativo</span>',
        suspended: '<span class="status-badge suspended">Suspenso</span>',
        banned:    '<span class="status-badge banned">Banido</span>',
    };
    return map[status] ?? `<span class="status-badge active">${LKUtils.escapeHtml(status)}</span>`;
}

// ============================================================
// Paginação reutilizável
// ============================================================
function renderPagination(containerId, pagination, onPage) {
    const el = document.getElementById(containerId);
    if (!el) return;

    const { page, pages, total } = pagination;
    if (pages <= 1) { el.innerHTML = `<span>${total} resultado(s)</span>`; return; }

    const prev = page > 1    ? `<button class="page-btn" onclick="(${onPage})(${page - 1})">← Anterior</button>` : '';
    const next = page < pages ? `<button class="page-btn" onclick="(${onPage})(${page + 1})">Seguinte →</button>` : '';

    el.innerHTML = `${prev}<span>Página ${page} de ${pages} (${total} total)</span>${next}`;
}

// ============================================================
// Modais
// ============================================================
function closeModal(id) {
    document.getElementById(id)?.classList.remove('active');
}

document.addEventListener('click', e => {
    if (e.target.classList.contains('modal-overlay')) {
        e.target.classList.remove('active');
    }
});


