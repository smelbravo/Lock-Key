/**
 * Lock & Key - Módulo de Criptografia Zero-Knowledge
 *
 * Utiliza a Web Crypto API nativa do browser (sem bibliotecas externas).
 * É mais segura que CryptoJS porque usa implementações nativas otimizadas.
 *
 * ARQUITETURA ZERO-KNOWLEDGE:
 * ─────────────────────────────────────────────────────────────────────────
 * masterPassword + email + salt
 *         ↓ PBKDF2-SHA256 (200.000 iterações)
 *     512 bits de material de chave
 *         ↓
 *   ┌─────────────────┬────────────────────────────────────────────┐
 *   │  authKey (256b) │           encryptionKey (256b)              │
 *   │ Enviado p/ srv  │ Fica APENAS no browser (sessionStorage)     │
 *   │ hash(Argon2id)  │ Encripta/desencripta dados do cofre         │
 *   └─────────────────┴────────────────────────────────────────────┘
 *
 * O servidor NUNCA vê:
 * - A senha mestra real
 * - O encryptionKey
 * - Os dados do cofre em texto simples
 */

'use strict';

const LKCrypto = (() => {

  // ============================================================
  // UTILITÁRIOS DE CODIFICAÇÃO
  // ============================================================

  /** Converte ArrayBuffer ou Uint8Array para string hexadecimal */
  function bytesToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /** Converte string hexadecimal para Uint8Array */
  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
  }

  /** Converte Uint8Array/ArrayBuffer para string Base64 URL-safe */
  function bytesToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /** Converte string Base64 para Uint8Array */
  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /** Codificar string para Uint8Array (UTF-8) */
  const encode = str => new TextEncoder().encode(str);

  /** Descodificar Uint8Array para string (UTF-8) */
  const decode = bytes => new TextDecoder().decode(bytes);

  // ============================================================
  // DERIVAÇÃO DE CHAVES (PBKDF2)
  // ============================================================

  /**
   * Deriva authKey e encryptionKey a partir da senha mestra.
   *
   * @param {string} masterPassword - Senha mestra do utilizador
   * @param {string} email          - Email (usado como pepper adicional)
   * @param {string} salt           - Salt hexadecimal (obtido do servidor)
   * @param {number} iterations     - Iterações PBKDF2 (padrão: 200000)
   * @returns {Promise<{authKey: string, encryptionKey: CryptoKey}>}
   */
  async function deriveKeys(masterPassword, email, salt, iterations = 200000) {
    // 1. Importar senha mestra como material de chave PBKDF2
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encode(masterPassword),
      'PBKDF2',
      false, // não exportável
      ['deriveBits']
    );

    // 2. Salt = salt do servidor + email (para que contas diferentes com mesmo
    //    salt de servidor ainda tenham chaves diferentes)
    const saltBytes = encode(salt + email.toLowerCase());

    // 3. Derivar 512 bits (256 para authKey + 256 para encryptionKey)
    const bits = await crypto.subtle.deriveBits(
      {
        name:       'PBKDF2',
        salt:       saltBytes,
        iterations: iterations,
        hash:       'SHA-256',
      },
      keyMaterial,
      512
    );

    // 4. Separar os 512 bits em dois segmentos de 256 bits
    const authKeyBytes = bits.slice(0, 32);      // Primeiros 256 bits → authKey
    const encKeyBytes  = bits.slice(32);          // Últimos 256 bits → encryptionKey

    // 5. authKey como hex (enviado ao servidor para autenticação)
    const authKey = bytesToHex(authKeyBytes);

    // 6. Importar encKeyBytes como CryptoKey AES-GCM (nunca sai do browser)
    const encryptionKey = await crypto.subtle.importKey(
      'raw',
      encKeyBytes,
      { name: 'AES-GCM' },
      false, // não exportável
      ['encrypt', 'decrypt']
    );

    // Retornar também os bytes raw para que possam ser persistidos em sessionStorage
    // (necessário para restaurar a chave ao navegar entre páginas)
    return { authKey, encryptionKey, rawKeyBytes: encKeyBytes };
  }

  // ============================================================
  // ENCRIPTAÇÃO / DESENCRIPTAÇÃO AES-256-GCM
  // ============================================================

  /**
   * Encripta um objeto JavaScript com AES-256-GCM.
   * Gera um IV aleatório único para cada operação.
   *
   * @param {*} data             - Dados a encriptar (qualquer tipo serializável)
   * @param {CryptoKey} key      - Chave AES-GCM
   * @returns {Promise<{ciphertext: string, iv: string}>}
   *   ciphertext: Base64 do ciphertext + authentication tag
   *   iv:         Base64 do IV (12 bytes = 16 chars base64)
   */
  async function encrypt(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96 bits, padrão GCM
    const plaintext = encode(typeof data === 'string' ? data : JSON.stringify(data));

    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key,
      plaintext
    );

    return {
      ciphertext: bytesToBase64(ciphertextBuffer),
      iv:         bytesToBase64(iv),
    };
  }

  /**
   * Desencripta dados AES-256-GCM.
   *
   * @param {string} ciphertext  - Base64 do ciphertext
   * @param {string} iv          - Base64 do IV
   * @param {CryptoKey} key      - Chave AES-GCM
   * @param {boolean} parseJson  - Se true, faz JSON.parse do resultado
   * @returns {Promise<*>}
   */
  async function decrypt(ciphertext, iv, key, parseJson = true) {
    const ciphertextBytes = base64ToBytes(ciphertext);
    const ivBytes         = base64ToBytes(iv);

    const plaintextBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
      key,
      ciphertextBytes
    );

    const plaintext = decode(plaintextBuffer);
    return parseJson ? JSON.parse(plaintext) : plaintext;
  }

  // ============================================================
  // ENCRIPTAÇÃO DE ENTRADAS DO COFRE
  // ============================================================

  /**
   * Encripta uma entrada completa do cofre.
   * Cada campo é encriptado individualmente com o MESMO IV (por performance).
   * O IV é único por entrada e armazenado com ela.
   *
   * @param {Object} entry  - Dados da entrada em texto simples
   * @param {CryptoKey} key - Chave de encriptação
   * @returns {Promise<Object>} Entrada pronta para enviar à API
   */
  async function encryptEntry(entry, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ivB64 = bytesToBase64(iv);

    // Função helper para encriptar um campo individual
    const encField = async (value) => {
      if (value === null || value === undefined || value === '') return null;
      const plaintext = encode(String(value));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key,
        plaintext
      );
      return bytesToBase64(ciphertext);
    };

    return {
      title_enc:    await encField(entry.title),
      url_enc:      await encField(entry.url),
      username_enc: await encField(entry.username),
      password_enc: await encField(entry.password),
      notes_enc:    await encField(entry.notes),
      category_enc: await encField(entry.category),
      tags_enc:     await encField(entry.tags),
      iv:           ivB64,
      strength_score: entry.strength_score ?? 0,
      is_favourite:   entry.is_favourite ?? false,
    };
  }

  /**
   * Desencripta uma entrada do cofre recebida da API.
   *
   * @param {Object} encEntry   - Entrada encriptada da API
   * @param {CryptoKey} key     - Chave de encriptação
   * @returns {Promise<Object>} Entrada em texto simples
   */
  async function decryptEntry(encEntry, key) {
    const iv = base64ToBytes(encEntry.iv);

    // Função helper para desencriptar um campo
    const decField = async (ciphertextB64) => {
      if (!ciphertextB64) return '';
      try {
        const ciphertext = base64ToBytes(ciphertextB64);
        const plaintext  = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv, tagLength: 128 },
          key,
          ciphertext
        );
        return decode(plaintext);
      } catch {
        return '[Erro de desencriptação]';
      }
    };

    return {
      uuid:           encEntry.uuid,
      title:          await decField(encEntry.title_enc),
      url:            await decField(encEntry.url_enc),
      username:       await decField(encEntry.username_enc),
      password:       await decField(encEntry.password_enc),
      notes:          await decField(encEntry.notes_enc),
      category:       await decField(encEntry.category_enc),
      tags:           await decField(encEntry.tags_enc),
      strength_score: encEntry.strength_score,
      is_favourite:   encEntry.is_favourite,
      last_used:      encEntry.last_used,
      created_at:     encEntry.created_at,
      updated_at:     encEntry.updated_at,
    };
  }

  /**
   * Desencripta todas as entradas do cofre em paralelo.
   *
   * @param {Array} encEntries - Array de entradas encriptadas
   * @param {CryptoKey} key    - Chave de encriptação
   * @returns {Promise<Array>}
   */
  async function decryptAllEntries(encEntries, key) {
    return Promise.all(encEntries.map(e => decryptEntry(e, key)));
  }

  /**
   * Encripta uma nota segura.
   * NOTA: O backend exige `title_enc` e `content_enc` obrigatórios — por isso
   * encriptamos mesmo quando o conteúdo é uma string vazia (encField vs encFieldOpt).
   */
  async function encryptNote(note, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ivB64 = bytesToBase64(iv);

    // Encripta sempre (mesmo string vazia) — usado para campos obrigatórios
    const encField = async (value) => {
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key,
        encode(String(value ?? ''))
      );
      return bytesToBase64(ciphertext);
    };

    // Encripta apenas se houver valor (devolve null caso contrário)
    const encFieldOpt = async (value) => {
      if (value === null || value === undefined || value === '') return null;
      return encField(value);
    };

    return {
      title_enc:    await encField(note.title || 'Sem título'),
      content_enc:  await encField(note.content || ''),
      category_enc: await encFieldOpt(note.category),
      iv:           ivB64,
      is_favourite: note.is_favourite ?? false,
    };
  }

  /**
   * Desencripta uma nota segura.
   */
  async function decryptNote(encNote, key) {
    const iv = base64ToBytes(encNote.iv);

    const decField = async (ciphertextB64) => {
      if (!ciphertextB64) return '';
      try {
        const plaintext = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv, tagLength: 128 },
          key,
          base64ToBytes(ciphertextB64)
        );
        return decode(plaintext);
      } catch {
        return '[Erro de desencriptação]';
      }
    };

    return {
      uuid:        encNote.uuid,
      title:       await decField(encNote.title_enc),
      content:     await decField(encNote.content_enc),
      category:    await decField(encNote.category_enc),
      is_favourite: encNote.is_favourite,
      created_at:  encNote.created_at,
      updated_at:  encNote.updated_at,
    };
  }

  async function decryptAllNotes(encNotes, key) {
    return Promise.all(encNotes.map(n => decryptNote(n, key)));
  }

  // ============================================================
  // AVALIAÇÃO DE FORÇA DE PASSWORD
  // ============================================================

  /**
   * Avalia a força de uma password (0-4).
   * Baseado em critérios de comprimento, diversidade e entropia.
   *
   * @param {string} password
   * @returns {{ score: number, label: string, color: string, tips: string[] }}
   */
  function evaluatePasswordStrength(password) {
    if (!password) return { score: 0, label: 'Muito fraca', color: '#ef4444', tips: [] };

    let score = 0;
    const tips = [];

    const hasLower   = /[a-z]/.test(password);
    const hasUpper   = /[A-Z]/.test(password);
    const hasDigit   = /\d/.test(password);
    const hasSymbol  = /[^a-zA-Z0-9]/.test(password);
    const len        = password.length;

    if (len >= 8)  score++;
    if (len >= 12) score++;
    if (len >= 16) score++;

    if (hasLower && hasUpper) score++;
    if (hasDigit)             score++;
    if (hasSymbol)            score++;

    // Penalizar repetições
    if (/(.)\1{2,}/.test(password)) score -= 1;

    // Penalizar sequências comuns
    if (/123|abc|qwerty|password/i.test(password)) score -= 1;

    score = Math.max(0, Math.min(4, Math.round(score / 1.5)));

    if (len < 12)  tips.push('Usa pelo menos 12 caracteres');
    if (!hasUpper) tips.push('Adiciona letras maiúsculas');
    if (!hasDigit) tips.push('Adiciona números');
    if (!hasSymbol) tips.push('Adiciona símbolos (!@#$%...)');

    const labels = ['Muito fraca', 'Fraca', 'Razoável', 'Forte', 'Muito forte'];
    const colors = ['#ef4444', '#f97316', '#f59e0b', '#84cc16', '#10b981'];

    return {
      score,
      label: labels[score],
      color: colors[score],
      tips,
    };
  }

  // ============================================================
  // GERADOR DE PASSWORDS
  // ============================================================

  /**
   * Gera uma password aleatória criptograficamente segura.
   *
   * @param {Object} options
   * @param {number}  options.length     - Comprimento (padrão: 20)
   * @param {boolean} options.uppercase         - Incluir maiúsculas
   * @param {boolean} options.lowercase         - Incluir minúsculas
   * @param {boolean} options.digits|numbers    - Incluir números (aceita ambos os nomes)
   * @param {boolean} options.symbols           - Incluir símbolos
   * @param {boolean} options.excludeAmbiguous  - Excluir caracteres ambíguos (0O1lI)
   * @returns {string}
   */
  function generatePassword(opts = {}) {
    const {
      length           = 20,
      uppercase        = true,
      lowercase        = true,
      symbols          = true,
      excludeAmbiguous = false,
    } = opts;
    // Aceitar tanto `digits` como `numbers` para evitar erros de naming
    const useDigits = opts.digits ?? opts.numbers ?? true;

    let upperSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let lowerSet = 'abcdefghijklmnopqrstuvwxyz';
    let digitSet = '0123456789';
    let symSet   = '!@#$%^&*()-_=+[]{}|;:,.<>?';

    if (excludeAmbiguous) {
      const ambiguous = /[0O1lI|`'"{}\[\]()<>;:,.]/g;
      upperSet = upperSet.replace(ambiguous, '');
      lowerSet = lowerSet.replace(ambiguous, '');
      digitSet = digitSet.replace(ambiguous, '');
      symSet   = symSet.replace(ambiguous, '');
    }

    let charset = '';
    const required = [];

    if (uppercase) { charset += upperSet; required.push(upperSet); }
    if (lowercase) { charset += lowerSet; required.push(lowerSet); }
    if (useDigits) { charset += digitSet; required.push(digitSet); }
    if (symbols)   { charset += symSet;   required.push(symSet); }

    if (!charset) return '';

    // Garantir pelo menos um caractere de cada conjunto ativado
    let password = required.map(set => {
      const randomIndex = crypto.getRandomValues(new Uint32Array(1))[0] % set.length;
      return set[randomIndex];
    });

    // Preencher o resto aleatoriamente
    const remaining = length - password.length;
    const randomValues = crypto.getRandomValues(new Uint32Array(remaining));
    for (let i = 0; i < remaining; i++) {
      password.push(charset[randomValues[i] % charset.length]);
    }

    // Embaralhar usando Fisher-Yates com valores criptograficamente seguros
    const shuffleValues = crypto.getRandomValues(new Uint32Array(password.length));
    for (let i = password.length - 1; i > 0; i--) {
      const j = shuffleValues[i] % (i + 1);
      [password[i], password[j]] = [password[j], password[i]];
    }

    return password.join('');
  }

  // ============================================================
  // GESTÃO DA CHAVE NA SESSÃO
  // ============================================================

  const SESSION_KEY_REF = 'lk_enc_key_ref';
  const SESSION_KEY_RAW = 'lk_enc_key_raw'; // bytes raw em base64 para restaurar entre páginas

  let _sessionEncKey = null;

  /**
   * Guardar chave em memória E os bytes raw em sessionStorage.
   * sessionStorage é limpo ao fechar o browser/tab — compromisso
   * razoável entre segurança e usabilidade (chave nunca vai ao servidor).
   */
  function storeSessionKey(cryptoKey, rawBytes = null) {
    _sessionEncKey = cryptoKey;
    sessionStorage.setItem(SESSION_KEY_REF, '1');
    if (rawBytes) {
      // Guardar bytes raw em base64 para restaurar na próxima página
      const b64 = btoa(String.fromCharCode(...new Uint8Array(rawBytes)));
      sessionStorage.setItem(SESSION_KEY_RAW, b64);
    }
  }

  /**
   * Tentar restaurar a chave a partir do sessionStorage.
   * Chamado em cada página no requireAuth() antes de mostrar o ecrã de bloqueio.
   * @returns {Promise<boolean>} true se restaurada com sucesso
   */
  async function restoreSessionKey() {
    if (_sessionEncKey !== null) return true; // já em memória
    const raw = sessionStorage.getItem(SESSION_KEY_RAW);
    if (!raw) return false;
    try {
      const bytes = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
      _sessionEncKey = await crypto.subtle.importKey(
        'raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
      );
      sessionStorage.setItem(SESSION_KEY_REF, '1');
      return true;
    } catch {
      clearSessionKey();
      return false;
    }
  }

  function getSessionKey() {
    return _sessionEncKey;
  }

  function clearSessionKey() {
    _sessionEncKey = null;
    sessionStorage.removeItem(SESSION_KEY_REF);
    sessionStorage.removeItem(SESSION_KEY_RAW);
  }

  function hasSessionKey() {
    return _sessionEncKey !== null;
  }

  // ============================================================
  // EXPORTAR API PÚBLICA
  // ============================================================

  return {
    deriveKeys,
    encrypt,
    decrypt,
    encryptEntry,
    decryptEntry,
    decryptAllEntries,
    encryptNote,
    decryptNote,
    decryptAllNotes,
    evaluatePasswordStrength,
    generatePassword,
    storeSessionKey,
    restoreSessionKey,
    getSessionKey,
    clearSessionKey,
    hasSessionKey,
    bytesToHex,
    hexToBytes,
    bytesToBase64,
    base64ToBytes,
  };
})();

// Tornar disponível globalmente
window.LKCrypto = LKCrypto;
