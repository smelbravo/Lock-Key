<?php
/**
 * Lock & Key - Bootstrap
 * Ficheiro central incluído por todos os endpoints da API.
 * Carrega configurações, classes e define a constante de segurança.
 */

declare(strict_types=1);

// Constante que autoriza a execução dos ficheiros de configuração
define('LK_APP', true);

// Reportar todos os erros em desenvolvimento, nenhum em produção
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// Zona horária UTC
date_default_timezone_set('UTC');

// Carregar configuração e ambiente
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/config/database.php';

// Helpers
require_once __DIR__ . '/helpers/encryption.php';
require_once __DIR__ . '/helpers/jwt.php';
require_once __DIR__ . '/helpers/response.php';

// Middleware
require_once __DIR__ . '/middleware/auth.php';
require_once __DIR__ . '/middleware/rate_limit.php';

/**
 * Registar evento no audit log
 */
function auditLog(string $action, ?int $userId = null, array $details = []): void
{
    try {
        Database::execute(
            'INSERT INTO audit_log (user_id, action, ip_address, user_agent, details)
             VALUES (?, ?, ?, ?, ?)',
            [
                $userId,
                $action,
                AuthMiddleware::getClientIp(),
                substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
                !empty($details) ? json_encode($details) : null,
            ]
        );
    } catch (\Throwable $e) {
        error_log("auditLog error: " . $e->getMessage());
    }
}

/**
 * Sanitizar string de input (prevenir XSS básico)
 * Nota: os dados do cofre já chegam encriptados, mas campos como email/username
 * devem ser sanitizados
 */
function sanitize(string $input, int $maxLength = 255): string
{
    return substr(trim(strip_tags($input)), 0, $maxLength);
}

/**
 * Validar email
 */
function validateEmail(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false && strlen($email) <= 255;
}
