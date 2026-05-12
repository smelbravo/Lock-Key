/**
 * Lock & Key - Lógica das Definições
 */

'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  if (!requireAuth()) return;
  initDashboardLayout();
  LKAutoLock.init();
  initSettingsNav();
  await loadProfile();
  initSettingsEvents();
});

function initSettingsNav() {
  const navItems = document.querySelectorAll('.settings-nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      navItems.forEach(i => i.classList.remove('active'));
      item.classList.add('active');

      // Esconder todos os painéis
      document.querySelectorAll('[id^="settings-"]').forEach(el => el.style.display = 'none');

      // Mostrar painel selecionado
      const section = document.getElementById(`settings-${item.dataset.settings}`);
      if (section) section.style.display = '';
    });
  });
}

async function loadProfile() {
  try {
    const profile = await LKApi.getProfile();
    const user    = LKApi.getStoredUser();

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
    LKToast.error('Erro ao carregar perfil: ' + err.message);
  }
}

function initSettingsEvents() {
  // Guardar perfil
  document.getElementById('save-profile-btn')?.addEventListener('click', async () => {
    const username = document.getElementById('profile-username').value.trim();
    if (!username || username.length < 3) {
      LKToast.error('Username deve ter pelo menos 3 caracteres.');
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
    if (!confirm('Tens a certeza? Serás desligado de todos os dispositivos.')) return;
    try {
      await LKApi.logout(true);
      window.location.href = '/lockandkey/frontend/login.html';
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
      LKToast.success('Cofre exportado com sucesso!');
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

  // Guardar preferências
  document.getElementById('save-prefs-btn')?.addEventListener('click', () => {
    LKToast.success('Preferências guardadas!');
  });
}

async function handleChangePassword() {
  const key = LKCrypto.getSessionKey();
  if (!key) { LKToast.error('Sessão expirada.'); return; }

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
      window.location.href = '/lockandkey/frontend/login.html';
    }, 2000);

  } catch (err) {
    LKToast.error('Erro: ' + err.message);
  } finally {
    LKUtils.setButtonLoading(btn, false);
  }
}
