<?php
/**
 * Lock & Key - API: Atualizar Nota Segura
 * POST /api/notes/update.php
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user = AuthMiddleware::require();
$body = Response::getJsonBody();
Response::requireFields($body, ['uuid', 'title_enc', 'content_enc', 'iv']);

$uuid = sanitize($body['uuid'], 36);

$note = Database::fetchOne('SELECT id FROM secure_notes WHERE uuid = ? AND user_id = ?', [$uuid, $user['id']]);
if ($note === null) Response::notFound('Nota não encontrada.');

$iv = $body['iv'] ?? '';
if (!preg_match('/^[A-Za-z0-9+\/]{16}$/', $iv)) Response::error('IV inválido.', 422);

Database::execute(
    'UPDATE secure_notes
     SET title_enc = ?, content_enc = ?, category_enc = ?, iv = ?,
         is_favourite = ?, updated_at = NOW()
     WHERE uuid = ? AND user_id = ?',
    [
        $body['title_enc'],
        $body['content_enc'],
        $body['category_enc'] ?? null,
        $iv,
        (int) (bool) ($body['is_favourite'] ?? false),
        $uuid, $user['id'],
    ]
);

Response::success(['uuid' => $uuid, 'updated_at' => date('Y-m-d H:i:s')], 'Nota atualizada com sucesso.');
