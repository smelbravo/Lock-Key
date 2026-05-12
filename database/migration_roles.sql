-- ============================================================
-- Lock & Key - Migração: Sistema de Roles e Planos
-- Executar no phpMyAdmin após o schema.sql original
-- ============================================================

USE lockandkey;

-- Adicionar colunas de role, plano e status à tabela users
ALTER TABLE users
    ADD COLUMN role ENUM('user', 'admin', 'admin_master')
        NOT NULL DEFAULT 'user'
        AFTER username,

    ADD COLUMN plan ENUM('free', 'pro', 'unlimited')
        NOT NULL DEFAULT 'free'
        AFTER role,

    ADD COLUMN plan_expires_at TIMESTAMP NULL
        AFTER plan,

    ADD COLUMN status ENUM('active', 'suspended', 'banned')
        NOT NULL DEFAULT 'active'
        AFTER plan_expires_at,

    ADD COLUMN suspended_reason VARCHAR(500) NULL
        AFTER status,

    ADD INDEX idx_role (role),
    ADD INDEX idx_plan (plan),
    ADD INDEX idx_status (status);

-- Limites de plano por role
-- free:      50 entradas, 10 notas
-- pro:       500 entradas, 100 notas
-- unlimited: sem limite
CREATE TABLE IF NOT EXISTS plan_limits (
    plan        ENUM('free','pro','unlimited') NOT NULL PRIMARY KEY,
    vault_max   INT NOT NULL DEFAULT 50,
    notes_max   INT NOT NULL DEFAULT 10,
    label       VARCHAR(50) NOT NULL,
    description VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO plan_limits (plan, vault_max, notes_max, label, description) VALUES
    ('free',      50,         10,   'Free',         'Conta gratuita — até 50 passwords e 10 notas'),
    ('pro',       500,        100,  'Pro',           'Conta Pro — até 500 passwords e 100 notas'),
    ('unlimited', 2147483647, 2147483647, 'Unlimited', 'Sem limites — acesso completo a todas as funcionalidades');
