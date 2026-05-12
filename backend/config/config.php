<?php
/**
 * Lock & Key - Configuração Principal
 * Carrega variáveis de ambiente do ficheiro .env
 * NUNCA expor este ficheiro publicamente
 */

declare(strict_types=1);

// Impedir acesso direto ao ficheiro
if (!defined('LK_APP')) {
    http_response_code(403);
    exit('Acesso negado.');
}

/**
 * Carrega o ficheiro .env do diretório raiz
 */
function loadEnv(): void
{
    $envPath = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . '.env';

    if (!file_exists($envPath)) {
        // Fallback: tentar .env na raiz do projeto
        $envPath = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . '.env';
    }

    if (!file_exists($envPath)) {
        throw new RuntimeException('Ficheiro .env não encontrado. Copiar .env.example para .env e configurar.');
    }

    $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach ($lines as $line) {
        // Ignorar comentários
        if (str_starts_with(trim($line), '#')) {
            continue;
        }

        if (str_contains($line, '=')) {
            [$key, $value] = explode('=', $line, 2);
            $key   = trim($key);
            $value = trim($value);

            // Remover aspas envolventes se existirem
            if (
                (str_starts_with($value, '"') && str_ends_with($value, '"')) ||
                (str_starts_with($value, "'") && str_ends_with($value, "'"))
            ) {
                $value = substr($value, 1, -1);
            }

            if (!array_key_exists($key, $_ENV)) {
                $_ENV[$key]    = $value;
                putenv("{$key}={$value}");
            }
        }
    }
}

/**
 * Obtém variável de ambiente com valor padrão
 */
function env(string $key, mixed $default = null): mixed
{
    return $_ENV[$key] ?? getenv($key) ?: $default;
}

// Carregar .env
loadEnv();

// ============================================================
// Configuração da Aplicação
// ============================================================
define('APP_ENV',     env('APP_ENV', 'production'));
define('APP_URL',     env('APP_URL', 'http://localhost'));
define('API_URL',     env('API_URL', 'http://localhost/api'));
define('APP_DEBUG',   APP_ENV === 'development');

// ============================================================
// Configuração JWT
// ============================================================
define('JWT_SECRET',       env('JWT_SECRET'));
define('JWT_ISSUER',       env('JWT_ISSUER', 'lockandkey'));
define('JWT_ACCESS_TTL',   (int) env('JWT_ACCESS_TTL', 3600));      // 1 hora
define('JWT_REFRESH_TTL',  (int) env('JWT_REFRESH_TTL', 2592000));  // 30 dias

if (empty(JWT_SECRET) || strlen(JWT_SECRET) < 64) {
    throw new RuntimeException('JWT_SECRET inválido. Deve ter pelo menos 64 caracteres.');
}

// ============================================================
// Configuração de Encriptação do Servidor
// ============================================================
define('SERVER_ENCRYPT_KEY', hex2bin(env('SERVER_ENCRYPT_KEY', '')));

// ============================================================
// Rate Limiting
// ============================================================
define('RATE_LIMIT_LOGIN_MAX',      (int) env('RATE_LIMIT_LOGIN_MAX', 5));
define('RATE_LIMIT_LOGIN_WINDOW',   (int) env('RATE_LIMIT_LOGIN_WINDOW', 900));  // 15 min
define('RATE_LIMIT_REGISTER_MAX',   (int) env('RATE_LIMIT_REGISTER_MAX', 3));
define('RATE_LIMIT_REGISTER_WINDOW',(int) env('RATE_LIMIT_REGISTER_WINDOW', 3600)); // 1 hora

// ============================================================
// Segurança de Sessão
// ============================================================
define('SESSION_TIMEOUT', (int) env('SESSION_TIMEOUT', 1800)); // 30 min
define('SESSION_NAME',    env('SESSION_NAME', 'lk_session'));

// ============================================================
// Headers de Segurança HTTP (aplicados em cada resposta API)
// ============================================================
function applySecurityHeaders(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    $allowedOrigins = explode(',', env('CORS_ALLOWED_ORIGINS', APP_URL));

    // CORS controlado
    if (in_array($origin, $allowedOrigins, true)) {
        header("Access-Control-Allow-Origin: {$origin}");
    }
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');

    // Segurança
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

    // Content Security Policy
    header(
        "Content-Security-Policy: " .
        "default-src 'self'; " .
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " .
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; " .
        "font-src 'self' https://fonts.gstatic.com; " .
        "img-src 'self' data: https:; " .
        "connect-src 'self' " . API_URL . "; " .
        "frame-ancestors 'none';"
    );

    // HSTS (apenas em produção com HTTPS)
    if (APP_ENV === 'production') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
}

// Tratar preflight OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    applySecurityHeaders();
    http_response_code(204);
    exit();
}

applySecurityHeaders();
header('Content-Type: application/json; charset=utf-8');
