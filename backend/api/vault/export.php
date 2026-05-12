<?php
/**
 * Lock & Key - API: Exportar Cofre
 * GET /api/vault/export.php
 *
 * Exporta todas as entradas encriptadas do utilizador.
 * Os dados saem encriptados - apenas o utilizador pode desencriptar.
 * O ficheiro exportado pode ser re-importado noutro cliente.
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('GET');

$user = AuthMiddleware::require();

$entries = Database::fetchAll(
    'SELECT uuid, title_enc, url_enc, username_enc, password_enc,
            notes_enc, category_enc, tags_enc, iv,
            strength_score, is_favourite, last_used, created_at, updated_at
     FROM vault_entries WHERE user_id = ?
     ORDER BY created_at ASC',
    [$user['id']]
);

$notes = Database::fetchAll(
    'SELECT uuid, title_enc, content_enc, category_enc, iv,
            is_favourite, created_at, updated_at
     FROM secure_notes WHERE user_id = ?
     ORDER BY created_at ASC',
    [$user['id']]
);

auditLog('vault_export', $user['id']);

Response::success([
    'export_version' => '1.0',
    'exported_at'    => date('Y-m-d H:i:s'),
    'user_uuid'      => $user['uuid'],
    'entries'        => $entries,
    'notes'          => $notes,
    'totals' => [
        'entries' => count($entries),
        'notes'   => count($notes),
    ],
], 'Cofre exportado com sucesso.');
