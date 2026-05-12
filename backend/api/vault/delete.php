<?php
/**
 * Lock & Key - API: Eliminar Entrada do Cofre
 * POST /api/vault/delete.php
 *
 * Elimina permanentemente uma entrada do cofre.
 * Verifica que pertence ao utilizador autenticado.
 *
 * Body: { "uuid": string }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user = AuthMiddleware::require();
$body = Response::getJsonBody();
Response::requireFields($body, ['uuid']);

$uuid = sanitize($body['uuid'], 36);

$affected = Database::execute(
    'DELETE FROM vault_entries WHERE uuid = ? AND user_id = ?',
    [$uuid, $user['id']]
);

if ($affected === 0) {
    Response::notFound('Entrada não encontrada.');
}

auditLog('vault_entry_deleted', $user['id'], ['uuid' => $uuid]);

Response::success(null, 'Entrada eliminada com sucesso.');
