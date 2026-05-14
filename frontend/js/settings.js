/**
 * Lock & Key - Lógica das Definições
 */

'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  if (!await requireAuth()) return;
  initDashboardLayout();
  LKAutoLock.init();
  initSettingsNav();
  await loadProfile();
  initSettingsEvents();
});

function initSettingsNav() {
  const navItems = document.querySelectorAll('.settings-nav-item');

  function activateSection(item) {
    navItems.forEach((i) => i.classList.remove('active'));
    item.classList.add('active');
    document.querySelectorAll('.settings-grid .settings-section').forEach((el) => {
      el.style.display = 'none';
    });
    const section = document.getElementById(`settings-${item.dataset.settings}`);
    if (section) section.style.display = '';
  }

  navItems.forEach((item) => {
    item.addEventListener('click', () => activateSection(item));
    item.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        activateSection(item);
      }
    });
  });
}

async function loadProfile() {
  try {
    const data    = await LKApi.getProfile();
    const profile = data?.user ?? data; // compatibilidade com ambos os formatos

    if (profile) {
      document.getElementById('profile-name').textContent  = profile.username || '—';
      document.getElementById('profile-email').textContent = profile.email || '—';
      document.getElementById('profile-username').value    = profile.username || '';
      document.getElementById('profile-avatar').textContent = LKUtils.getInitials(profile.username);

      if (profile.created_at) {
        document.getElementById('profile-since').textContent =
          new Date(profile.created_at).toLocaleDateString('pt-PT', { month: 'long', year: 'numeric' });
      }
    }
  } catch (err) {
    LKToast.error('Não foi possível carregar o perfil: ' + err.message);
  }
}

function initSettingsEvents() {
  // Guardar perfil
  document.getElementById('save-profile-btn')?.addEventListener('click', async () => {
    const username = document.getElementById('profile-username').value.trim();
    if (!username || username.length < 3) {
      LKToast.error('O nome de utilizador deve ter pelo menos 3 caracteres.');
      return;
    }
    try {
      await LKApi.updateProfile(username);
      document.getElementById('profile-name').textContent = username;
      document.getElementById('profile-avatar').textContent = LKUtils.getInitials(username);
      LKToast.success('Perfil atualizado!');
    } catch (err) {
      LKToast.error(err.message);
    }
  });

  // Alterar senha mestra
  document.getElementById('change-password-btn')?.addEventListener('click', async () => {
    await handleChangePassword();
  });

  // Revogar todas as sessões
  document.getElementById('revoke-all-sessions')?.addEventListener('click', async () => {
    if (!confirm('Tens a certeza? Vais terminar a sessão em todos os dispositivos.')) return;
    try {
      await LKApi.logout(true);
      window.location.href = '/Lock%26Key/frontend/login.html';
    } catch (err) {
      LKToast.error(err.message);
    }
  });

  // Exportar cofre
  document.getElementById('export-vault-btn')?.addEventListener('click', async () => {
    try {
      const data = await LKApi.exportVault();
      const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `lockandkey-vault-${new Date().toISOString().slice(0,10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      LKToast.success('Cofre exportado.');
    } catch (err) {
      LKToast.error(err.message);
    }
  });

  // Tema
  const darkModePref = document.getElementById('pref-dark-mode');
  if (darkModePref) {
    darkModePref.checked = LKTheme.getTheme() === 'dark';
    darkModePref.addEventListener('change', () => {
      LKTheme.setTheme(darkModePref.checked ? 'dark' : 'light');
    });
  }

  // Auto-lock timeout
  const lockTimeout = document.getElementById('pref-lock-timeout');
  if (lockTimeout) {
    lockTimeout.value = localStorage.getItem('lk_lock_timeout') || '30';
    lockTimeout.addEventListener('change', () => {
      localStorage.setItem('lk_lock_timeout', lockTimeout.value);
    });
  }

  // Carregar preferências guardadas
  const autoLockPref = document.getElementById('pref-auto-lock');
  if (autoLockPref) {
    autoLockPref.checked = localStorage.getItem('lk_auto_lock') !== '0';
    autoLockPref.addEventListener('change', () => {
      localStorage.setItem('lk_auto_lock', autoLockPref.checked ? '1' : '0');
    });
  }
  const hidePref = document.getElementById('pref-hide-passwords');
  if (hidePref) {
    hidePref.checked = localStorage.getItem('lk_hide_passwords') !== '0';
    hidePref.addEventListener('change', () => {
      localStorage.setItem('lk_hide_passwords', hidePref.checked ? '1' : '0');
    });
  }

  // Guardar preferências (já são guardadas individualmente; aqui é só feedback)
  document.getElementById('save-prefs-btn')?.addEventListener('click', () => {
    LKToast.success('Preferências guardadas!');
  });

  // Importar cofre (.json)
  document.getElementById('import-file')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (!parsed || typeof parsed !== 'object') {
        throw new Error('Ficheiro inválido.');
      }
      LKToast.info('A importar…');
      await importVaultBackup(parsed);
    } catch (err) {
      LKToast.error('Erro ao importar: ' + err.message);
    } finally {
      e.target.value = '';
    }
  });

  document.getElementById('delete-account-btn')?.addEventListener('click', async () => {
    const confirm1 = confirm('Tens a certeza absoluta de que queres eliminar a conta? Esta ação é irreversível.');
    if (!confirm1) return;
    const confirm2 = prompt('Para confirmar, escreve "ELIMINAR" (em maiúsculas):');
    if (confirm2 !== 'ELIMINAR') {
      LKToast.info('Eliminação cancelada.');
      return;
    }
    const masterPass = prompt('Introduz a senha mestra para confirmar a eliminação.');
    if (!masterPass) {
      LKToast.info('Eliminação cancelada.');
      return;
    }

    const btn = document.getElementById('delete-account-btn');
    LKUtils.setButtonLoading(btn, true);
    try {
      const user = LKApi.getStoredUser();
      if (!user?.email) throw new Error('Sessão inválida.');

      const saltData = await LKApi.getSalt(user.email);
      const { authKey } = await LKCrypto.deriveKeys(
        masterPass,
        user.email,
        saltData.salt,
        saltData.iterations
      );

      await LKApi.deleteAccount(authKey);
      LKToast.success('Conta eliminada.');
      LKApi.clearTokens();
      LKCrypto.clearSessionKey();
      window.location.href = '/Lock%26Key/frontend/login.html';
    } catch (err) {
      LKToast.error(err.message);
    } finally {
      LKUtils.setButtonLoading(btn, false);
    }
  });
}

/**
 * Importa entradas e notas a partir de um JSON exportado pela própria app.
 * Os ciphertexts são criados de novo no servidor (novos UUIDs).
 * Só é permitido se o backup for desta conta (user_uuid) ou, em exports antigos,
 * se a chave de sessão atual conseguir desencriptar uma entrada de teste.
 */
function unwrapVaultExport(raw) {
  if (!raw || typeof raw !== 'object') return raw;
  const inner = raw.data;
  if (
    inner && typeof inner === 'object' &&
    (inner.export_version != null || Array.isArray(inner.entries) || Array.isArray(inner.notes))
  ) {
    return inner;
  }
  return raw;
}

async function importVaultBackup(parsed) {
  parsed = unwrapVaultExport(parsed);
  const ver = parsed.export_version;
  if (ver && ver !== '1.0') {
    throw new Error(`Versão de exportação não suportada: ${ver}`);
  }

  const entries = Array.isArray(parsed.entries) ? parsed.entries : [];
  const notes = Array.isArray(parsed.notes) ? parsed.notes : [];

  await assertBackupDecryptableForCurrentUser(parsed, entries);

  let okE = 0;
  let okN = 0;
  let failE = 0;
  let failN = 0;
  let stoppedByLimit = false;

  for (const e of entries) {
    const payload = {
      title_enc:    e.title_enc,
      password_enc: e.password_enc,
      url_enc:      e.url_enc ?? null,
      username_enc: e.username_enc ?? null,
      notes_enc:    e.notes_enc ?? null,
      category_enc: e.category_enc ?? null,
      tags_enc:     e.tags_enc ?? null,
      iv:           e.iv,
      strength_score: Math.max(0, Math.min(4, Number(e.strength_score) || 0)),
      is_favourite:   !!e.is_favourite,
    };
    if (!payload.iv || !payload.title_enc || !payload.password_enc) {
      failE++;
      continue;
    }
    try {
      await LKApi.createVaultEntry(payload);
      okE++;
    } catch (err) {
      failE++;
      if (err.message && /limite|Limite|429/i.test(err.message)) {
        stoppedByLimit = true;
        break;
      }
    }
  }

  if (!stoppedByLimit) {
    for (const n of notes) {
      const payload = {
        title_enc:    n.title_enc,
        content_enc:  n.content_enc,
        category_enc: n.category_enc ?? null,
        iv:           n.iv,
      };
      if (!payload.iv || !payload.title_enc || payload.content_enc == null) {
        failN++;
        continue;
      }
      try {
        await LKApi.createNote(payload);
        okN++;
      } catch (err) {
        failN++;
        if (err.message && /limite|Limite|429/i.test(err.message)) break;
      }
    }
  }

  const parts = [
    `${okE} entrada(s)`,
    `${okN} nota(s)`,
  ];
  if (failE || failN) {
    parts.push(`${failE + failN} falha(s) ou ignorados`);
  }
  if (stoppedByLimit) {
    parts.push('interrompido: limite do plano');
  }
  LKToast.success('Importação concluída: ' + parts.join(' · ') + '.');
}

async function assertBackupDecryptableForCurrentUser(parsed, entries) {
  const u = LKApi.getStoredUser();
  if (!u?.uuid) throw new Error('Sessão inválida.');

  if (parsed.user_uuid) {
    if (parsed.user_uuid !== u.uuid) {
      throw new Error(
        'Este ficheiro pertence a outra conta. Só podes importar cópias exportadas da tua conta atual.'
      );
    }
    return;
  }

  const key = LKCrypto.getSessionKey();
  if (!key) {
    throw new Error('Desbloqueia o cofre (abre o dashboard) antes de importar este backup sem identificador de conta.');
  }
  if (entries.length === 0) return;

  const probe = { ...entries[0], uuid: entries[0].uuid || 'import-probe' };
  const dec = await LKCrypto.decryptEntry(probe, key);
  if (entries[0].title_enc && dec.title === '[Erro de desencriptação]') {
    throw new Error(
      'Não foi possível desencriptar este backup. Usa a mesma senha mestra que na exportação e desbloqueia o cofre.'
    );
  }
}

async function handleChangePassword() {
  const key = LKCrypto.getSessionKey();
  if (!key) { LKToast.error('Cofre bloqueado ou sessão expirada. Desbloqueia o cofre e tenta de novo.'); return; }

  const currentPass = document.getElementById('current-password').value;
  const newPass     = document.getElementById('new-password').value;
  const confirmPass = document.getElementById('confirm-password').value;

  if (!currentPass || !newPass || !confirmPass) {
    LKToast.error('Preenche todos os campos.'); return;
  }

  if (newPass.length < 12) {
    LKToast.error('A nova senha deve ter pelo menos 12 caracteres.'); return;
  }

  const strength = LKCrypto.evaluatePasswordStrength(newPass);
  if (strength.score < 2) {
    LKToast.error('A nova senha é demasiado fraca.'); return;
  }

  if (newPass !== confirmPass) {
    LKToast.error('As novas senhas não coincidem.'); return;
  }

  const btn = document.getElementById('change-password-btn');
  LKUtils.setButtonLoading(btn, true);

  try {
    const user = LKApi.getStoredUser();
    if (!user) throw new Error('Sessão inválida.');

    // Verificar senha atual
    const saltData = await LKApi.getSalt(user.email);
    const { authKey: currentAuthKey, encryptionKey: currentEncKey } =
      await LKCrypto.deriveKeys(currentPass, user.email, saltData.salt, saltData.iterations);

    // Gerar novo salt e derivar novas chaves
    const newSaltBytes = crypto.getRandomValues(new Uint8Array(32));
    const newSalt = Array.from(newSaltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const { authKey: newAuthKey, encryptionKey: newEncKey } =
      await LKCrypto.deriveKeys(newPass, user.email, newSalt, 200000);

    // Re-encriptar todos os dados do cofre com o novo key
    const [encEntries, encNotes] = await Promise.all([
      LKApi.getVaultEntries(),
      LKApi.getNotes(),
    ]);

    // Desencriptar com chave atual
    const decEntries = await LKCrypto.decryptAllEntries(encEntries, currentEncKey);
    const decNotes   = await LKCrypto.decryptAllNotes(encNotes, currentEncKey);

    // Re-encriptar com nova chave
    const reEncEntries = await Promise.all(
      decEntries.map(async e => {
        const enc = await LKCrypto.encryptEntry(e, newEncKey);
        enc.uuid = e.uuid;
        return enc;
      })
    );
    const reEncNotes = await Promise.all(
      decNotes.map(async n => {
        const enc = await LKCrypto.encryptNote(n, newEncKey);
        enc.uuid = n.uuid;
        return enc;
      })
    );

    await LKApi.changePassword({
      current_auth_key: currentAuthKey,
      new_auth_key:     newAuthKey,
      new_salt:         newSalt,
      entries:          reEncEntries,
      notes:            reEncNotes,
    });

    LKToast.success('Senha alterada! A redirecionar para o login...');
    setTimeout(() => {
      LKApi.clearTokens();
      LKCrypto.clearSessionKey();
      window.location.href = '/Lock%26Key/frontend/login.html';
    }, 2000);

  } catch (err) {
    LKToast.error('Erro: ' + err.message);
  } finally {
    LKUtils.setButtonLoading(btn, false);
  }
}


