<?php
/**
 * Lock & Key - API: Alterar Senha Mestra
 * POST /api/user/change_password.php
 *
 * OPERAÇÃO CRÍTICA - Arquitetura Zero-Knowledge:
 * Ao alterar a senha mestra, o encryptionKey muda.
 * Isso significa que TODOS os dados do cofre precisam de ser re-encriptados
 * com o novo encryptionKey no CLIENTE antes de serem enviados.
 *
 * Fluxo:
 * 1. Cliente verifica authKey atual
 * 2. Cliente deriva novos authKey e encryptionKey
 * 3. Cliente re-encripta todos os dados com novo encryptionKey
 * 4. Envia novo authKey + todos os dados re-encriptados numa transação
 *
 * Body: {
 *   "current_auth_key": string,
 *   "new_auth_key": string,
 *   "new_salt": string,
 *   "entries": array (dados re-encriptados),
 *   "notes": array (notas re-encriptadas)
 * }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user = AuthMiddleware::require();
$body = Response::getJsonBody();
Response::requireFields($body, ['current_auth_key', 'new_auth_key', 'new_salt']);

$currentAuthKey = trim($body['current_auth_key']);
$newAuthKey     = trim($body['new_auth_key']);
$newSalt        = trim($body['new_salt']);

// Validar formato das chaves
if (!preg_match('/^[0-9a-f]{64}$/', $currentAuthKey) ||
    !preg_match('/^[0-9a-f]{64}$/', $newAuthKey) ||
    !preg_match('/^[0-9a-f]{64}$/', $newSalt)) {
    Response::error('Chaves de autenticação inválidas.', 422);
}

// Rate limiting rigoroso para esta operação
RateLimit::check(
    $user['email'],
    'change_password',
    3,   // máximo 3 tentativas
    3600 // em 1 hora
);

// Verificar authKey atual
$userData = Database::fetchOne(
    'SELECT auth_key_hash FROM users WHERE id = ?',
    [$user['id']]
);

if (!Encryption::verifyPassword($currentAuthKey, $userData['auth_key_hash'])) {
    auditLog('change_password_failed', $user['id']);
    Response::error('Senha atual incorreta.', 401);
}

try {
    Database::beginTransaction();

    // Atualizar authKey e salt
    $newHash = Encryption::hashPassword($newAuthKey);
    Database::execute(
        'UPDATE users SET auth_key_hash = ?, vault_salt = ?, updated_at = NOW() WHERE id = ?',
        [$newHash, $newSalt, $user['id']]
    );

    // Re-encriptar entradas do cofre (se fornecidas)
    $entries = $body['entries'] ?? [];
    foreach ($entries as $entry) {
        if (empty($entry['uuid'])) continue;
        Database::execute(
            'UPDATE vault_entries
             SET title_enc = ?, url_enc = ?, username_enc = ?, password_enc = ?,
                 notes_enc = ?, category_enc = ?, tags_enc = ?, iv = ?, updated_at = NOW()
             WHERE uuid = ? AND user_id = ?',
            [
                $entry['title_enc'] ?? null, $entry['url_enc'] ?? null,
                $entry['username_enc'] ?? null, $entry['password_enc'] ?? null,
                $entry['notes_enc'] ?? null, $entry['category_enc'] ?? null,
                $entry['tags_enc'] ?? null, $entry['iv'] ?? null,
                sanitize($entry['uuid'], 36), $user['id'],
            ]
        );
    }

    // Re-encriptar notas (se fornecidas)
    $notes = $body['notes'] ?? [];
    foreach ($notes as $note) {
        if (empty($note['uuid'])) continue;
        Database::execute(
            'UPDATE secure_notes
             SET title_enc = ?, content_enc = ?, category_enc = ?, iv = ?, updated_at = NOW()
             WHERE uuid = ? AND user_id = ?',
            [
                $note['title_enc'] ?? null, $note['content_enc'] ?? null,
                $note['category_enc'] ?? null, $note['iv'] ?? null,
                sanitize($note['uuid'], 36), $user['id'],
            ]
        );
    }

    // Revogar todas as sessões (forçar novo login com nova senha)
    AuthMiddleware::revokeAllSessions($user['id']);

    Database::commit();

    auditLog('change_password_success', $user['id']);
    RateLimit::reset($user['email'], 'change_password');

    Response::success(null, 'Senha alterada com sucesso. Faça login novamente.');

} catch (\Throwable $e) {
    Database::rollback();
    error_log("Change password error: " . $e->getMessage());
    Response::serverError($e->getMessage());
}
