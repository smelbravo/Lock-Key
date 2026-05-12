<?php
/**
 * Lock & Key - API: Perfil do Utilizador
 * GET  /api/user/profile.php  → obter perfil
 * POST /api/user/profile.php  → atualizar username
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

$user = AuthMiddleware::require();

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Estatísticas do cofre
    $stats = Database::fetchOne(
        'SELECT
            (SELECT COUNT(*) FROM vault_entries WHERE user_id = ?) as entries_count,
            (SELECT COUNT(*) FROM secure_notes WHERE user_id = ?) as notes_count,
            (SELECT COUNT(*) FROM sessions WHERE user_id = ? AND is_revoked = 0 AND expires_at > NOW()) as active_sessions',
        [$user['id'], $user['id'], $user['id']]
    );

    $userData = Database::fetchOne(
        'SELECT uuid, email, username, created_at, last_login, last_login_ip
         FROM users WHERE id = ?',
        [$user['id']]
    );

    Response::success(array_merge($userData ?? [], $stats ?? []));

} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body    = Response::getJsonBody();
    $newName = sanitize($body['username'] ?? '', 100);

    if (strlen($newName) < 3 || strlen($newName) > 100) {
        Response::error('Username deve ter entre 3 e 100 caracteres.', 422);
    }

    Database::execute('UPDATE users SET username = ? WHERE id = ?', [$newName, $user['id']]);
    Response::success(['username' => $newName], 'Perfil atualizado com sucesso.');
} else {
    Response::methodNotAllowed(['GET', 'POST']);
}
