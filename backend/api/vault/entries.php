<?php
/**
 * Lock & Key - API: Listar Entradas do Cofre
 * GET /api/vault/entries.php
 *
 * Retorna todas as entradas do cofre do utilizador autenticado.
 * Os dados estão encriptados (o cliente desencripta localmente).
 * O servidor nunca vê o conteúdo em texto simples.
 *
 * Query params:
 *   ?favourite=1  - apenas favoritos
 *   ?recent=1     - ordenar por last_used
 *   ?limit=N      - limitar resultados
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('GET');

$user = AuthMiddleware::require();

$onlyFavourite = isset($_GET['favourite']) && $_GET['favourite'] === '1';
$recentFirst   = isset($_GET['recent']) && $_GET['recent'] === '1';
$limit         = isset($_GET['limit']) ? min((int) $_GET['limit'], 500) : 500;

$sql    = 'SELECT uuid, title_enc, url_enc, username_enc, password_enc,
                  notes_enc, category_enc, tags_enc, iv,
                  strength_score, is_favourite, last_used, created_at, updated_at
           FROM vault_entries
           WHERE user_id = ?';
$params = [$user['id']];

if ($onlyFavourite) {
    $sql .= ' AND is_favourite = 1';
}

if ($recentFirst) {
    $sql .= ' ORDER BY last_used DESC, updated_at DESC';
} else {
    $sql .= ' ORDER BY created_at DESC';
}

$sql .= ' LIMIT ?';
$params[] = $limit;

$entries = Database::fetchAll($sql, $params);

// Converter campos booleanos
foreach ($entries as &$entry) {
    $entry['is_favourite']  = (bool) $entry['is_favourite'];
    $entry['strength_score'] = (int) $entry['strength_score'];
}
unset($entry);

Response::success([
    'entries' => $entries,
    'count'   => count($entries),
]);
