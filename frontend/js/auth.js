/**
 * Lock & Key - Lógica de Autenticação (Login / Registo)
 * Implementa o fluxo zero-knowledge de derivação de chaves.
 */

'use strict';

document.addEventListener('DOMContentLoaded', () => {
  // Redirecionar para dashboard se já estiver autenticado
  if (LKApi.isLoggedIn() && LKCrypto.hasSessionKey()) {
    const page = LKUtils.getCurrentPage();
    if (page === 'login' || page === 'register') {
      window.location.href = '/lockandkey/frontend/dashboard.html';
      return;
    }
  }

  const page = LKUtils.getCurrentPage();
  if (page === 'login')    initLoginPage();
  if (page === 'register') initRegisterPage();
});

// ============================================================
// PÁGINA DE LOGIN
// ============================================================

function initLoginPage() {
  const form         = document.getElementById('login-form');
  const emailInput   = document.getElementById('email');
  const passInput    = document.getElementById('password');
  const togglePassBtn = document.getElementById('toggle-password');
  const submitBtn    = document.getElementById('login-btn');
  const errorDiv     = document.getElementById('auth-error');
  const errorMsg     = document.getElementById('auth-error-msg');
  const derivingDiv  = document.getElementById('deriving-keys');

  // Toggle mostrar/ocultar senha
  if (togglePassBtn) {
    togglePassBtn.addEventListener('click', () => {
      const isPass = passInput.type === 'password';
      passInput.type = isPass ? 'text' : 'password';
      document.getElementById('eye-icon').style.opacity = isPass ? '0.5' : '1';
    });
  }

  // Submissão do formulário
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearError();

      const email    = emailInput.value.trim().toLowerCase();
      const password = passInput.value;

      if (!email || !password) {
        showError('Por favor preenche todos os campos.');
        return;
      }

      if (!LKUtils.isValidEmail(email)) {
        showError('Endereço de email inválido.');
        return;
      }

      LKUtils.setButtonLoading(submitBtn, true);
      derivingDiv.style.display = 'flex';

      try {
        // PASSO 1: Obter salt PBKDF2 do servidor
        const saltData = await LKApi.getSalt(email);

        // PASSO 2: Derivar authKey e encryptionKey localmente
        // Este processo pode demorar alguns segundos (propositadamente - PBKDF2)
        const { authKey, encryptionKey } = await LKCrypto.deriveKeys(
          password,
          email,
          saltData.salt,
          saltData.iterations
        );

        // PASSO 3: Enviar apenas authKey ao servidor (nunca a senha real)
        const loginData = await LKApi.login(email, authKey);

        // PASSO 4: Guardar encryptionKey em memória (NUNCA em storage)
        LKCrypto.storeSessionKey(encryptionKey);

        // Login bem-sucedido → redirecionar para dashboard
        LKToast.success('Login efetuado com sucesso!');
        setTimeout(() => {
          window.location.href = '/lockandkey/frontend/dashboard.html';
        }, 500);

      } catch (err) {
        showError(err.message || 'Erro ao iniciar sessão. Tenta novamente.');
      } finally {
        LKUtils.setButtonLoading(submitBtn, false);
        derivingDiv.style.display = 'none';
      }
    });
  }

  function showError(msg) {
    errorDiv.style.display = 'flex';
    errorMsg.textContent = msg;
    errorDiv.classList.remove('hidden');
  }

  function clearError() {
    errorDiv.style.display = 'none';
    errorDiv.classList.add('hidden');
  }
}

// ============================================================
// PÁGINA DE REGISTO
// ============================================================

function initRegisterPage() {
  const form           = document.getElementById('register-form');
  const usernameInput  = document.getElementById('username');
  const emailInput     = document.getElementById('email');
  const passInput      = document.getElementById('password');
  const confirmInput   = document.getElementById('confirm-password');
  const togglePassBtn  = document.getElementById('toggle-password');
  const submitBtn      = document.getElementById('register-btn');
  const errorDiv       = document.getElementById('auth-error');
  const errorMsg       = document.getElementById('auth-error-msg');
  const derivingDiv    = document.getElementById('deriving-keys');
  const strengthContainer = document.getElementById('strength-container');
  const strengthBar    = document.getElementById('strength-bar');
  const strengthText   = document.getElementById('strength-text');
  const strengthScore  = document.getElementById('strength-score');
  const matchError     = document.getElementById('password-match-error');

  // Toggle senha
  if (togglePassBtn) {
    togglePassBtn.addEventListener('click', () => {
      const isPass = passInput.type === 'password';
      passInput.type = isPass ? 'text' : 'password';
      document.getElementById('eye-icon').style.opacity = isPass ? '0.5' : '1';
    });
  }

  // Indicador de força em tempo real
  if (passInput) {
    passInput.addEventListener('input', () => {
      const val = passInput.value;
      if (!val) {
        strengthContainer.style.display = 'none';
        return;
      }
      strengthContainer.style.display = 'block';

      const result = LKCrypto.evaluatePasswordStrength(val);

      // Atualizar barra de força
      strengthBar.className = `strength-bar strength-${result.score}`;
      strengthText.textContent = result.label;
      strengthText.style.color = result.color;
      strengthScore.textContent = `${result.score}/4`;
    });
  }

  // Verificar se as senhas coincidem
  if (confirmInput) {
    confirmInput.addEventListener('input', () => {
      const match = passInput.value === confirmInput.value;
      matchError.classList.toggle('hidden', match || !confirmInput.value);
    });
  }

  // Submissão do formulário
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearError();

      const username  = usernameInput.value.trim();
      const email     = emailInput.value.trim().toLowerCase();
      const password  = passInput.value;
      const confirm   = confirmInput.value;

      // Validações
      if (!username || !email || !password || !confirm) {
        showError('Por favor preenche todos os campos.');
        return;
      }

      if (username.length < 3 || username.length > 100) {
        showError('Username deve ter entre 3 e 100 caracteres.');
        return;
      }

      if (!LKUtils.isValidEmail(email)) {
        showError('Endereço de email inválido.');
        return;
      }

      if (password.length < 12) {
        showError('A senha mestra deve ter pelo menos 12 caracteres.');
        return;
      }

      const strength = LKCrypto.evaluatePasswordStrength(password);
      if (strength.score < 2) {
        showError('A senha mestra é demasiado fraca. ' + (strength.tips[0] || ''));
        return;
      }

      if (password !== confirm) {
        showError('As senhas mestras não coincidem.');
        return;
      }

      LKUtils.setButtonLoading(submitBtn, true);
      derivingDiv.style.display = 'flex';

      try {
        // PASSO 1: Gerar salt único para este utilizador
        // O salt é gerado no cliente e enviado ao servidor
        // Neste fluxo, o servidor gerará um salt no registo
        // Aqui precisamos obter um salt temporário para gerar o authKey
        // Solução: Usamos um salt gerado localmente para o registo inicial
        // O servidor irá gerar e armazenar o seu próprio salt
        // Após o registo, fazemos login para obter o salt real do servidor

        // Gerar um salt temporário (32 bytes hex)
        const tempSaltBytes = crypto.getRandomValues(new Uint8Array(32));
        const tempSalt = Array.from(tempSaltBytes)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');

        // PASSO 2: Derivar authKey com o salt temporário
        const { authKey } = await LKCrypto.deriveKeys(password, email, tempSalt, 200000);

        // PASSO 3: Enviar para o servidor (que gerará o seu próprio salt)
        await LKApi.register(email, username, authKey);

        LKToast.success('Conta criada com sucesso! A redirecionar para o login...');

        setTimeout(() => {
          window.location.href = '/lockandkey/frontend/login.html?registered=1';
        }, 1500);

      } catch (err) {
        showError(err.message || 'Erro ao criar conta. Tenta novamente.');
      } finally {
        LKUtils.setButtonLoading(submitBtn, false);
        derivingDiv.style.display = 'none';
      }
    });
  }

  function showError(msg) {
    errorDiv.style.display = 'flex';
    errorMsg.textContent = msg;
    errorDiv.classList.remove('hidden');
  }

  function clearError() {
    errorDiv.style.display = 'none';
    errorDiv.classList.add('hidden');
  }
}

// ============================================================
// PROTEÇÃO DE PÁGINAS AUTENTICADAS
// ============================================================

/**
 * Chama esta função nas páginas que requerem autenticação.
 * Redireciona para login se não autenticado.
 */
function requireAuth() {
  if (!LKApi.isLoggedIn()) {
    window.location.href = '/lockandkey/frontend/login.html';
    return false;
  }

  // Se não temos a chave em memória mas temos token, precisamos do unlock
  if (!LKCrypto.hasSessionKey()) {
    // Mostrar ecrã de desbloqueio
    const lockOverlay = document.getElementById('session-lock');
    if (lockOverlay) {
      lockOverlay.classList.remove('hidden');
    }
    return false;
  }

  return true;
}

window.requireAuth = requireAuth;
