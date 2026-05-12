<?php
/**
 * Lock & Key - API: Renovar Token JWT
 * POST /api/auth/refresh.php
 *
 * Troca um refresh token válido por um novo par access+refresh token.
 * O refresh token antigo é invalidado (rotação de tokens).
 *
 * Body: { "refresh_token": string }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$body = Response::getJsonBody();
Response::requireFields($body, ['refresh_token']);

$refreshToken = trim($body['refresh_token']);

if (strlen($refreshToken) !== 128) { // 64 bytes = 128 hex chars
    Response::error('Refresh token inválido.', 401);
}

$refreshHash = hash('sha256', $refreshToken);

// Obter sessão com refresh token válido
$session = Database::fetchOne(
    'SELECT s.id, s.user_id, s.is_extension, u.uuid, u.email, u.username,
            u.vault_salt, u.pbkdf2_iterations, u.is_active, u.role, u.plan, u.status
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.refresh_hash = ?
       AND s.refresh_expires_at > NOW()
       AND s.is_revoked = 0',
    [$refreshHash]
);

if ($session === null) {
    Response::unauthorized('Refresh token inválido ou expirado.');
}

if (!(bool) $session['is_active'] || $session['status'] === 'banned') {
    Response::unauthorized('Conta desativada.');
}
if ($session['status'] === 'suspended') {
    Response::unauthorized('Conta suspensa.');
}

try {
    Database::beginTransaction();

    // Revogar sessão antiga (rotação de tokens)
    Database::execute(
        'UPDATE sessions SET is_revoked = 1 WHERE id = ?',
        [$session['id']]
    );

    // Gerar novos tokens
    $newAccessToken  = JWT::generate([
        'user_id' => $session['user_id'],
        'uuid'    => $session['uuid'],
        'email'   => $session['email'],
    ]);
    $newRefreshToken = JWT::generateRefreshToken();

    // Criar nova sessão
    AuthMiddleware::createSession(
        $session['user_id'],
        $newAccessToken,
        $newRefreshToken,
        (bool) $session['is_extension']
    );

    Database::commit();

    Response::success([
        'access_token'  => $newAccessToken,
        'refresh_token' => $newRefreshToken,
        'expires_in'    => JWT_ACCESS_TTL,
        'token_type'    => 'Bearer',
        'user' => [
            'uuid'              => $session['uuid'],
            'email'             => $session['email'],
            'username'          => $session['username'],
            'role'              => $session['role'],
            'plan'              => $session['plan'],
            'vault_salt'        => $session['vault_salt'],
            'pbkdf2_iterations' => (int) $session['pbkdf2_iterations'],
        ],
    ]);

} catch (\Throwable $e) {
    Database::rollback();
    Response::serverError($e->getMessage());
}
