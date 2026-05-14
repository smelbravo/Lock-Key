/**
 * Lock & Key - Gerador de passwords
 */

'use strict';

const GenState = {
  password: '',
  history: [],
};

document.addEventListener('DOMContentLoaded', async () => {
  if (!await requireAuth()) return;
  initDashboardLayout();
  LKAutoLock.init();
  initGenerator();
  generatePassword(); // Gerar logo ao abrir
});

function initGenerator() {
  const lengthSlider = document.getElementById('gen-length');
  const lengthVal    = document.getElementById('gen-length-val');
  const generateBtn  = document.getElementById('gen-generate-btn');
  const copyBtn      = document.getElementById('gen-copy-btn');
  const copyBtn2     = document.getElementById('gen-copy-btn2');
  const clearBtn     = document.getElementById('gen-clear-history');

  // Atualizar valor do slider em tempo real
  if (lengthSlider) {
    lengthSlider.addEventListener('input', () => {
      lengthVal.textContent = lengthSlider.value;
      generatePassword();
    });
  }

  // Regenerar ao mudar opções
  ['gen-uppercase', 'gen-lowercase', 'gen-numbers', 'gen-symbols', 'gen-exclude-ambig'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', generatePassword);
  });

  if (generateBtn) generateBtn.addEventListener('click', generatePassword);

  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      if (GenState.password) copyPassword();
    });
  }

  if (copyBtn2) {
    copyBtn2.addEventListener('click', () => {
      if (GenState.password) copyPassword();
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      GenState.history = [];
      renderHistory();
    });
  }
}

function generatePassword() {
  const length      = parseInt(document.getElementById('gen-length')?.value || '20', 10);
  const useUpper    = document.getElementById('gen-uppercase')?.checked ?? true;
  const useLower    = document.getElementById('gen-lowercase')?.checked ?? true;
  const useNumbers  = document.getElementById('gen-numbers')?.checked ?? true;
  const useSymbols  = document.getElementById('gen-symbols')?.checked ?? true;
  const exclAmbig   = document.getElementById('gen-exclude-ambig')?.checked ?? false;

  // Garantir que pelo menos uma opção está activa
  if (!useUpper && !useLower && !useNumbers && !useSymbols) {
    LKToast.error('Seleciona pelo menos um tipo de caractere.');
    return;
  }

  const options = {
    length,
    uppercase: useUpper,
    lowercase: useLower,
    numbers:   useNumbers,
    symbols:   useSymbols,
    excludeAmbiguous: exclAmbig,
  };

  const password = LKCrypto.generatePassword(options);
  GenState.password = password;

  // Mostrar no output
  const output = document.getElementById('gen-output');
  if (output) output.textContent = password;

  // Barra de força
  const strength = LKCrypto.evaluatePasswordStrength(password);
  const fill  = document.getElementById('gen-strength-fill');
  const label = document.getElementById('gen-strength-label');

  const widths = ['0%', '25%', '50%', '75%', '100%'];
  const colors = ['var(--danger)', 'var(--danger)', 'var(--warning)', 'var(--success)', 'var(--primary)'];

  if (fill) {
    fill.style.width      = widths[strength.score] || '0%';
    fill.style.background = colors[strength.score] || 'var(--danger)';
  }
  if (label) label.textContent = strength.label || '—';

  // Adicionar ao histórico
  GenState.history.unshift(password);
  if (GenState.history.length > 20) GenState.history.pop();
  renderHistory();
}

async function copyPassword() {
  if (!GenState.password) return;
  await LKUtils.copyToClipboard(GenState.password);
  LKToast.success('Password copiada!');
}

function renderHistory() {
  const list = document.getElementById('gen-history-list');
  if (!list) return;

  if (!GenState.history.length) {
    list.innerHTML = '<li style="color:var(--text-secondary);font-size:.875rem;padding:.5rem 0">Nenhuma password gerada ainda.</li>';
    return;
  }

  list.innerHTML = GenState.history.map((pw, idx) => `
    <li class="history-item">
      <span class="history-pw">${LKUtils.escapeHtml(pw)}</span>
      <button class="history-copy" data-idx="${idx}" title="Copiar">Copiar</button>
    </li>
  `).join('');

  list.querySelectorAll('.history-copy').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = parseInt(btn.dataset.idx, 10);
      if (GenState.history[idx]) {
        await LKUtils.copyToClipboard(GenState.history[idx]);
        LKToast.success('Copiado!');
      }
    });
  });
}
