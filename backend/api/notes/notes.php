<?php
/**
 * Lock & Key - API: Listar Notas Seguras
 * GET /api/notes/notes.php
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('GET');

$user = AuthMiddleware::require();

$notes = Database::fetchAll(
    'SELECT uuid, title_enc, content_enc, category_enc, iv,
            is_favourite, created_at, updated_at
     FROM secure_notes
     WHERE user_id = ?
     ORDER BY updated_at DESC',
    [$user['id']]
);

foreach ($notes as &$note) {
    $note['is_favourite'] = (bool) $note['is_favourite'];
}
unset($note);

Response::success(['notes' => $notes, 'count' => count($notes)]);
