<?php
/**
 * Lock & Key - API: Eliminar conta permanentemente
 * POST /api/user/delete_account.php
 *
 * Corpo: { "auth_key": "<hex 64>" } — authKey derivado da senha mestra (igual ao login).
 * Apenas o próprio utilizador pode eliminar a própria conta (JWT).
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user = AuthMiddleware::require();
$body = Response::getJsonBody();
Response::requireFields($body, ['auth_key']);

$authKey = trim($body['auth_key'] ?? '');

if (!preg_match('/^[0-9a-f]{64}$/', $authKey)) {
    Response::error('auth_key inválido.', 422);
}

$row = Database::fetchOne(
    'SELECT id, email, username, auth_key_hash, role FROM users WHERE id = ?',
    [$user['id']]
);

if ($row === null) {
    Response::notFound('Utilizador não encontrado.');
}

// Impedir eliminação da única conta admin_master
if ($row['role'] === 'admin_master') {
    $masters = Database::fetchOne(
        "SELECT COUNT(*) AS c FROM users WHERE role = 'admin_master'"
    );
    if ((int) ($masters['c'] ?? 0) <= 1) {
        Response::forbidden('Não é possível eliminar a única conta Admin Master do sistema.');
    }
}

if (!Encryption::verifyPassword($authKey, $row['auth_key_hash'])) {
    usleep(random_int(100000, 300000));
    Response::error('Senha mestra incorreta.', 401);
}

$userId   = (int) $row['id'];
$userEmail = $row['email'];

try {
    Database::beginTransaction();

    auditLog('account_deleted', $userId, ['email' => $userEmail, 'username' => $row['username']]);

    Database::execute('DELETE FROM rate_limits WHERE identifier = ?', [$userEmail]);

    Database::execute('DELETE FROM users WHERE id = ?', [$userId]);

    Database::commit();

    Response::success(['deleted' => true], 'Conta eliminada permanentemente.');
} catch (\Throwable $e) {
    Database::rollback();
    error_log('delete_account: ' . $e->getMessage());
    Response::serverError($e->getMessage());
}
