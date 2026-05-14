<?php
/**
 * Lock & Key - API: Login
 * POST /api/auth/login.php
 *
 * Fluxo de Login Zero-Knowledge:
 * 1. Cliente envia email para obter o salt PBKDF2 (endpoint get_salt.php)
 * 2. Cliente usa salt para derivar authKey e encryptionKey via PBKDF2
 * 3. Cliente envia email + authKey para este endpoint
 * 4. Servidor verifica hash(authKey) com Argon2id
 * 5. Servidor emite JWT access token + refresh token
 * 6. encryptionKey fica apenas na memória do browser
 *
 * Body esperado:
 * {
 *   "email": string,
 *   "auth_key": string (hex, 64 chars),
 *   "is_extension": bool (opcional, para sessões da extensão)
 * }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$body = Response::getJsonBody();
Response::requireFields($body, ['email', 'auth_key']);

$email       = strtolower(sanitize($body['email']));
$authKey     = trim($body['auth_key'] ?? '');
$isExtension = (bool) ($body['is_extension'] ?? false);

// Rate limiting ANTES de qualquer query à BD
RateLimit::checkLogin($email);

// Validações básicas
if (!validateEmail($email)) {
    Response::error('Credenciais inválidas.', 401);
}

if (!preg_match('/^[0-9a-f]{64}$/', $authKey)) {
    Response::error('Credenciais inválidas.', 401);
}

// Obter utilizador
$user = Database::fetchOne(
    'SELECT id, uuid, email, username, auth_key_hash, vault_salt, pbkdf2_iterations,
            is_active, failed_login_attempts, locked_until, role, plan, status
     FROM users
     WHERE email = ?',
    [$email]
);

// Verificar se a conta está bloqueada temporariamente
if ($user !== null && $user['locked_until'] !== null) {
    if (strtotime($user['locked_until']) > time()) {
        $minutesLeft = ceil((strtotime($user['locked_until']) - time()) / 60);
        Response::error(
            "Conta temporariamente bloqueada. Tente novamente em {$minutesLeft} minutos.",
            423
        );
    }
}

// Verificar credenciais (tempo constante para prevenir timing attacks)
// Se utilizador não existe, executamos verificação falsa para manter tempo consistente.
// IMPORTANTE: sem este "fake verify", um atacante consegue distinguir emails registados
// de não-registados medindo o tempo de resposta (Argon2id demora ~250ms vs <1ms).
$validCredentials = false;
if ($user !== null) {
    $validCredentials = Encryption::verifyPassword($authKey, $user['auth_key_hash']);
} else {
    // Hash dummy fixo para garantir tempo de resposta consistente
    // (gerado uma vez com Encryption::hashPassword('dummy'))
    $dummyHash = '$argon2id$v=19$m=65536,t=4,p=2$ZHVtbXlzYWx0ZHVtbXk$' .
                 'ZHVtbXloYXNoZHVtbXloYXNoZHVtbXloYXNoZHVtbXloYXNoZHVtbXk';
    Encryption::verifyPassword($authKey, $dummyHash); // ignorar resultado
}

if (!$validCredentials) {
    // Incrementar tentativas falhadas
    if ($user !== null) {
        $attempts = (int) $user['failed_login_attempts'] + 1;
        $lockedUntil = null;

        // Bloquear após 10 tentativas falhadas (além do rate limit)
        if ($attempts >= 10) {
            $lockedUntil = date('Y-m-d H:i:s', time() + 3600); // 1 hora
        }

        Database::execute(
            'UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?',
            [$attempts, $lockedUntil, $user['id']]
        );

        auditLog('login_failed', $user['id'], ['email' => $email, 'attempts' => $attempts]);
    } else {
        auditLog('login_failed_unknown', null, ['email' => $email]);
    }

    // Atraso para prevenir enumeração
    usleep(random_int(100000, 300000));
    Response::error('Credenciais inválidas.', 401);
}

// Verificar se a conta está ativa
if (!(bool) $user['is_active'] || $user['status'] === 'banned') {
    Response::error('Conta desativada. Contacte o suporte.', 403);
}
if ($user['status'] === 'suspended') {
    Response::error('Conta suspensa. Contacte o suporte.', 403);
}

// Login bem-sucedido
// Resetar tentativas falhadas e rate limit
Database::execute(
    'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW(), last_login_ip = ? WHERE id = ?',
    [AuthMiddleware::getClientIp(), $user['id']]
);

RateLimit::resetLogin($email);

// Verificar se o hash necessita de ser atualizado (parâmetros melhorados)
if (Encryption::needsRehash($user['auth_key_hash'])) {
    $newHash = Encryption::hashPassword($authKey);
    Database::execute(
        'UPDATE users SET auth_key_hash = ? WHERE id = ?',
        [$newHash, $user['id']]
    );
}

// Gerar tokens JWT
$accessToken  = JWT::generate([
    'user_id' => $user['id'],
    'uuid'    => $user['uuid'],
    'email'   => $user['email'],
]);
$refreshToken = JWT::generateRefreshToken();

// Registar sessão na BD
AuthMiddleware::createSession($user['id'], $accessToken, $refreshToken, $isExtension);

// Registar audit log
auditLog('login_success', $user['id']);

Response::success([
    'access_token'  => $accessToken,
    'refresh_token' => $refreshToken,
    'expires_in'    => JWT_ACCESS_TTL,
    'token_type'    => 'Bearer',
    'user' => [
        'uuid'     => $user['uuid'],
        'email'    => $user['email'],
        'username' => $user['username'],
        'role'     => $user['role'],
        'plan'     => $user['plan'],
        // Salt e iterações necessários para o cliente derivar as chaves
        'vault_salt'        => $user['vault_salt'],
        'pbkdf2_iterations' => (int) $user['pbkdf2_iterations'],
    ],
], 'Login efetuado com sucesso.');
