-- ============================================================
-- Lock & Key — Apagar conta admin incorreta para recriar
-- Executar no phpMyAdmin ANTES de correr o create_admin.php
-- ============================================================

USE lockandkey;

-- Apagar a conta admin criada com hash errado
DELETE FROM users WHERE email = 'samuelbravo543@gmail.com';

-- Limpar rate limits e sessões orphans
DELETE FROM rate_limits;
DELETE FROM sessions WHERE user_id NOT IN (SELECT id FROM users);

-- Confirmar que foi apagada
SELECT COUNT(*) AS admin_count FROM users WHERE email = 'samuelbravo543@gmail.com';
-- Deve mostrar 0
