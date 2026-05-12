<?php
/**
 * Lock & Key - API: Eliminar Nota Segura
 * POST /api/notes/delete.php
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user = AuthMiddleware::require();
$body = Response::getJsonBody();
Response::requireFields($body, ['uuid']);

$uuid     = sanitize($body['uuid'], 36);
$affected = Database::execute('DELETE FROM secure_notes WHERE uuid = ? AND user_id = ?', [$uuid, $user['id']]);

if ($affected === 0) Response::notFound('Nota não encontrada.');

Response::success(null, 'Nota eliminada com sucesso.');
