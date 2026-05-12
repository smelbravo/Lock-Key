/**
 * Lock & Key Extension - Content Script
 * Injeta-se em todas as páginas web para:
 * 1. Detetar formulários de login
 * 2. Autofill de credenciais
 * 3. Detetar submissões de formulários (para guardar credenciais)
 * 4. Mostrar botão de autofill nos campos de password
 */

'use strict';

// Evitar execução múltipla
if (window.__lockAndKeyInjected) {
  // Já injetado
} else {
  window.__lockAndKeyInjected = true;
  initContentScript();
}

function initContentScript() {
  // Detetar formulários de login existentes na página
  detectLoginForms();

  // Observar mudanças no DOM (SPAs que carregam formulários dinamicamente)
  const observer = new MutationObserver(() => {
    detectLoginForms();
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // Detetar submissões de formulários
  document.addEventListener('submit', onFormSubmit, true);

  // Escutar mensagens do popup/background
  browser.runtime.onMessage.addListener(onMessage);
}

// ============================================================
// DETEÇÃO DE FORMULÁRIOS
// ============================================================

const injectedForms = new WeakSet();

function detectLoginForms() {
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    if (injectedForms.has(form)) return;

    const passwordField = form.querySelector('input[type="password"]');
    if (!passwordField) return;

    injectedForms.add(form);
    injectAutofillButton(passwordField);
  });

  // Também detetar campos de password fora de forms
  document.querySelectorAll('input[type="password"]').forEach(field => {
    if (!field.closest('form') && !field.dataset.lkInjected) {
      injectAutofillButton(field);
    }
  });
}

// ============================================================
// BOTÃO DE AUTOFILL
// ============================================================

function injectAutofillButton(passwordField) {
  if (passwordField.dataset.lkInjected) return;
  passwordField.dataset.lkInjected = '1';

  // Criar wrapper se necessário
  const parent = passwordField.parentElement;
  if (!parent) return;

  // Botão de autofill
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.title = 'Preencher com Lock & Key';
  btn.setAttribute('data-lk-btn', '1');
  btn.style.cssText = `
    position: absolute;
    right: 6px;
    top: 50%;
    transform: translateY(-50%);
    width: 28px;
    height: 28px;
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    border: none;
    border-radius: 6px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2147483647;
    box-shadow: 0 2px 8px rgba(59,130,246,0.4);
    transition: opacity 0.15s;
    opacity: 0;
    padding: 0;
  `;

  btn.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5">
      <rect x="3" y="11" width="18" height="11" rx="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  `;

  // Posicionar relativamente ao campo
  const computedStyle = window.getComputedStyle(parent);
  if (computedStyle.position === 'static') {
    parent.style.position = 'relative';
  }

  parent.appendChild(btn);

  // Mostrar ao focar no campo
  passwordField.addEventListener('focus', () => { btn.style.opacity = '1'; });
  passwordField.addEventListener('blur', () => {
    setTimeout(() => { btn.style.opacity = '0'; }, 200);
  });
  btn.addEventListener('mouseenter', () => { btn.style.opacity = '1'; });

  // Clicar no botão → abrir popup ou autofill
  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();

    // Solicitar ao background para abrir o popup
    browser.runtime.sendMessage({ type: 'SHOW_POPUP' });
  });
}

// ============================================================
// DETEÇÃO DE SUBMISSÃO (para guardar credenciais)
// ============================================================

async function onFormSubmit(e) {
  const form = e.target;
  if (!(form instanceof HTMLFormElement)) return;

  const passwordField  = form.querySelector('input[type="password"]');
  if (!passwordField?.value) return;

  const usernameField = form.querySelector(
    'input[type="email"], input[type="text"], input[name*="user"], input[name*="email"], input[name*="login"], input[id*="user"], input[id*="email"]'
  );

  const username = usernameField?.value || '';
  const password = passwordField.value;

  if (username && password && password.length >= 6) {
    // Enviar para o background para verificar se deve guardar
    browser.runtime.sendMessage({
      type: 'CREDENTIALS_DETECTED',
      data: {
        username,
        password,
        url: window.location.href,
        title: document.title,
      }
    });
  }
}

// ============================================================
// AUTOFILL
// ============================================================

function onMessage(message) {
  if (message.type === 'AUTOFILL') {
    autofillForm(message.data);
  }
  if (message.type === 'DETECT_FORMS') {
    const forms = detectAllLoginForms();
    return Promise.resolve({ forms });
  }
}

function autofillForm(data) {
  const { username, password } = data;
  let filled = false;

  // Tentar encontrar formulários de login
  const forms = document.querySelectorAll('form');
  let targetForm = null;

  for (const form of forms) {
    if (form.querySelector('input[type="password"]')) {
      targetForm = form;
      break;
    }
  }

  if (targetForm) {
    fillFormFields(targetForm, username, password);
    filled = true;
  } else {
    // Tentar preencher campos fora de forms
    const passwordField = document.querySelector('input[type="password"]');
    if (passwordField) {
      const userField = document.querySelector(
        'input[type="email"], input[type="text"][name*="user"], input[type="text"][name*="email"]'
      );
      if (userField && username) fillField(userField, username);
      fillField(passwordField, password);
      filled = true;
    }
  }

  if (filled) {
    // Realçar campos preenchidos brevemente
    highlightFilledFields();
  }

  return filled;
}

function fillFormFields(form, username, password) {
  // Tentar campos de utilizador/email
  const userSelectors = [
    'input[type="email"]',
    'input[type="text"][name*="email"]',
    'input[type="text"][name*="user"]',
    'input[type="text"][name*="login"]',
    'input[type="text"][id*="email"]',
    'input[type="text"][id*="user"]',
    'input[type="text"]',
  ];

  let userField = null;
  for (const sel of userSelectors) {
    userField = form.querySelector(sel);
    if (userField) break;
  }

  if (userField && username) fillField(userField, username);

  const passwordField = form.querySelector('input[type="password"]');
  if (passwordField) fillField(passwordField, password);
}

/**
 * Preenche um campo de input de forma que os frameworks JS (React, Vue, Angular)
 * detetem a mudança corretamente.
 */
function fillField(input, value) {
  if (!input || value === undefined || value === null) return;

  // Focar no campo
  input.focus();

  // Definir valor usando o descriptor nativo (necessário para React/Vue)
  const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype, 'value'
  )?.set;

  if (nativeInputValueSetter) {
    nativeInputValueSetter.call(input, value);
  } else {
    input.value = value;
  }

  // Disparar eventos para que frameworks JS detetem a mudança
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  input.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
  input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
}

function highlightFilledFields() {
  const style = document.createElement('style');
  style.textContent = `
    .lk-autofilled {
      background-color: rgba(59, 130, 246, 0.08) !important;
      border-color: #3b82f6 !important;
      box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2) !important;
      transition: all 0.3s !important;
    }
  `;
  document.head.appendChild(style);

  const fields = document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"]');
  fields.forEach(f => {
    if (f.value) {
      f.classList.add('lk-autofilled');
      setTimeout(() => f.classList.remove('lk-autofilled'), 2000);
    }
  });

  setTimeout(() => style.remove(), 3000);
}

function detectAllLoginForms() {
  const forms = [];
  document.querySelectorAll('form').forEach(form => {
    if (form.querySelector('input[type="password"]')) {
      forms.push({
        hasEmail: !!form.querySelector('input[type="email"]'),
        hasUser:  !!form.querySelector('input[type="text"]'),
      });
    }
  });
  return forms;
}
