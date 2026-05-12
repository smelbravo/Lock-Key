-- ============================================================
-- Lock & Key - Schema da Base de Dados MySQL
-- Arquitetura de encriptação zero-knowledge:
--   - Dados do cofre encriptados no cliente (AES-256-GCM)
--   - Servidor nunca vê dados em texto simples
--   - authKey (derivado da senha mestra) é autenticado pelo servidor
--   - encryptionKey nunca sai do browser
-- ============================================================

CREATE DATABASE IF NOT EXISTS lockandkey
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE lockandkey;

-- ============================================================
-- Tabela de Utilizadores
-- Armazena credenciais de autenticação e salt para derivação de chaves
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id              INT UNSIGNED        AUTO_INCREMENT PRIMARY KEY,
    uuid            CHAR(36)            NOT NULL UNIQUE,
    email           VARCHAR(255)        NOT NULL UNIQUE,
    username        VARCHAR(100)        NOT NULL,
    -- Hash do authKey (derivado do master password no cliente)
    -- Nunca armazenamos o master password real, nem o encryptionKey
    auth_key_hash   VARCHAR(255)        NOT NULL,
    -- Salt utilizado para PBKDF2 no cliente (gerado no registo)
    vault_salt      CHAR(64)            NOT NULL,
    -- Iterações PBKDF2 (permite upgrade futuro)
    pbkdf2_iterations INT UNSIGNED     NOT NULL DEFAULT 200000,
    -- Campos de segurança
    email_verified  TINYINT(1)          NOT NULL DEFAULT 0,
    is_active       TINYINT(1)          NOT NULL DEFAULT 1,
    -- Proteção contra brute force
    failed_login_attempts INT UNSIGNED  NOT NULL DEFAULT 0,
    locked_until    TIMESTAMP           NULL,
    -- Metadados
    last_login      TIMESTAMP           NULL,
    last_login_ip   VARCHAR(45)         NULL,
    created_at      TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP           NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_email (email),
    INDEX idx_uuid (uuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Tabela de Entradas do Cofre (Passwords)
-- Todos os campos sensíveis são encriptados no cliente com AES-256-GCM
-- ============================================================
CREATE TABLE IF NOT EXISTS vault_entries (
    id                  INT UNSIGNED    AUTO_INCREMENT PRIMARY KEY,
    uuid                CHAR(36)        NOT NULL UNIQUE,
    user_id             INT UNSIGNED    NOT NULL,
    -- Dados encriptados (ciphertext em Base64, AES-256-GCM no cliente)
    title_enc           TEXT            NOT NULL,
    url_enc             TEXT            NULL,
    username_enc        TEXT            NULL,
    password_enc        TEXT            NOT NULL,
    notes_enc           TEXT            NULL,
    category_enc        TEXT            NULL,
    tags_enc            TEXT            NULL,
    -- IV único por entrada (Base64, 12 bytes para GCM)
    iv                  CHAR(24)        NOT NULL,
    -- Score de força da password (0-4), calculado no cliente e enviado em claro
    -- Não é dado sensível - apenas um indicador
    strength_score      TINYINT UNSIGNED NULL DEFAULT 0,
    -- Metadados não sensíveis
    is_favourite        TINYINT(1)      NOT NULL DEFAULT 0,
    last_used           TIMESTAMP       NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_uuid (uuid),
    INDEX idx_last_used (last_used),
    INDEX idx_favourite (user_id, is_favourite)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Tabela de Notas Seguras
-- Conteúdo totalmente encriptado no cliente
-- ============================================================
CREATE TABLE IF NOT EXISTS secure_notes (
    id                  INT UNSIGNED    AUTO_INCREMENT PRIMARY KEY,
    uuid                CHAR(36)        NOT NULL UNIQUE,
    user_id             INT UNSIGNED    NOT NULL,
    -- Dados encriptados
    title_enc           TEXT            NOT NULL,
    content_enc         MEDIUMTEXT      NOT NULL,
    category_enc        TEXT            NULL,
    -- IV único por nota
    iv                  CHAR(24)        NOT NULL,
    -- Metadados
    is_favourite        TINYINT(1)      NOT NULL DEFAULT 0,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_uuid (uuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Tabela de Sessões / Tokens JWT
-- Permite revogar tokens e listar sessões ativas
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id              INT UNSIGNED    AUTO_INCREMENT PRIMARY KEY,
    user_id         INT UNSIGNED    NOT NULL,
    -- Hash SHA-256 do token JWT (nunca armazenar token em claro)
    token_hash      VARCHAR(64)     NOT NULL UNIQUE,
    -- Hash SHA-256 do refresh token
    refresh_hash    VARCHAR(64)     NULL UNIQUE,
    -- Informação do dispositivo (User-Agent truncado)
    device_info     VARCHAR(300)    NULL,
    ip_address      VARCHAR(45)     NULL,
    -- Indica se é sessão da extensão Firefox
    is_extension    TINYINT(1)      NOT NULL DEFAULT 0,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Access token expira em 1 hora
    expires_at      TIMESTAMP       NOT NULL,
    -- Refresh token expira em 30 dias
    refresh_expires_at TIMESTAMP    NULL,
    last_activity   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_revoked      TINYINT(1)      NOT NULL DEFAULT 0,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token_hash (token_hash),
    INDEX idx_refresh_hash (refresh_hash),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Tabela de Rate Limiting
-- Proteção contra ataques de brute force por IP e email
-- ============================================================
CREATE TABLE IF NOT EXISTS rate_limits (
    id              INT UNSIGNED    AUTO_INCREMENT PRIMARY KEY,
    -- Identificador: IP ou email
    identifier      VARCHAR(255)    NOT NULL,
    action          VARCHAR(100)    NOT NULL,
    attempts        INT UNSIGNED    NOT NULL DEFAULT 1,
    window_start    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    blocked_until   TIMESTAMP       NULL,

    UNIQUE KEY uq_identifier_action (identifier, action),
    INDEX idx_window_start (window_start),
    INDEX idx_blocked_until (blocked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Tabela de Auditoria de Segurança
-- Registo de eventos importantes para análise forense
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id          INT UNSIGNED    AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED    NULL,
    action      VARCHAR(100)    NOT NULL,
    ip_address  VARCHAR(45)     NULL,
    user_agent  VARCHAR(500)    NULL,
    details     JSON            NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Procedimento para limpar dados expirados (executar periodicamente)
-- ============================================================
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS cleanup_expired_data()
BEGIN
    -- Remover sessões expiradas há mais de 7 dias
    DELETE FROM sessions
    WHERE expires_at < DATE_SUB(NOW(), INTERVAL 7 DAY);

    -- Remover entradas de rate limit antigas (mais de 24 horas)
    DELETE FROM rate_limits
    WHERE window_start < DATE_SUB(NOW(), INTERVAL 24 HOUR)
      AND (blocked_until IS NULL OR blocked_until < NOW());

    -- Limpar audit log com mais de 90 dias
    DELETE FROM audit_log
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
END //
DELIMITER ;
