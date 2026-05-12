-- ============================================================
-- Lock & Key — Reset do Rate Limit e desbloqueio de conta
-- Executar no phpMyAdmin quando bloqueado por demasiadas tentativas
-- ============================================================

USE lockandkey;

-- 1. Limpar todos os rate limits (desbloqueia IPs e emails)
DELETE FROM rate_limits;

-- 2. Desbloquear a conta (reset tentativas falhadas)
UPDATE users
SET failed_login_attempts = 0,
    locked_until = NULL
WHERE email = 'samuelbravo543@gmail.com';

-- 3. Verificar se a conta admin existe
SELECT id, username, email, role, plan, status
FROM users
WHERE email = 'samuelbravo543@gmail.com';
