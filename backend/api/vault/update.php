<?php
/**
 * Lock & Key - API: Atualizar Entrada no Cofre
 * POST /api/vault/update.php
 *
 * Atualiza uma entrada existente com novos dados encriptados.
 * Verifica que a entrada pertence ao utilizador autenticado.
 *
 * Body: { "uuid": string, ...campos encriptados... }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user = AuthMiddleware::require();
$body = Response::getJsonBody();
Response::requireFields($body, ['uuid']);

$uuid = sanitize($body['uuid'], 36);

// Verificar que a entrada existe e pertence a este utilizador
$entry = Database::fetchOne(
    'SELECT id FROM vault_entries WHERE uuid = ? AND user_id = ?',
    [$uuid, $user['id']]
);

if ($entry === null) {
    Response::notFound('Entrada não encontrada.');
}

// CASO ESPECIAL: pedido para apenas registar uso (sem reencriptar)
// O frontend envia { uuid, update_last_used: true } quando o utilizador
// revela/copia a password sem editar — não exige título/password/iv.
$updateOnlyLastUsed =
    isset($body['update_last_used']) && $body['update_last_used'] === true
    && !isset($body['title_enc']) && !isset($body['password_enc']) && !isset($body['iv']);

if ($updateOnlyLastUsed) {
    Database::execute(
        'UPDATE vault_entries SET last_used = NOW() WHERE uuid = ? AND user_id = ?',
        [$uuid, $user['id']]
    );
    Response::success(['uuid' => $uuid], 'Última utilização atualizada.');
}

// Caso normal: edição completa — exige título, password e IV
Response::requireFields($body, ['title_enc', 'password_enc', 'iv']);

// Validar IV
$iv = $body['iv'] ?? '';
if (!preg_match('/^[A-Za-z0-9+\/]{16}$/', $iv)) {
    Response::error('IV inválido.', 422);
}

function validateEncField(?string $value, string $field): ?string
{
    if ($value === null || $value === '') return null;
    if (base64_decode($value, true) === false) {
        Response::error("Campo '{$field}' inválido.", 422);
    }
    if (strlen($value) > 65535) {
        Response::error("Campo '{$field}' excede o tamanho máximo.", 422);
    }
    return $value;
}

$titleEnc    = validateEncField($body['title_enc'] ?? null, 'title_enc');
$passwordEnc = validateEncField($body['password_enc'] ?? null, 'password_enc');
$urlEnc      = validateEncField($body['url_enc'] ?? null, 'url_enc');
$usernameEnc = validateEncField($body['username_enc'] ?? null, 'username_enc');
$notesEnc    = validateEncField($body['notes_enc'] ?? null, 'notes_enc');
$categoryEnc = validateEncField($body['category_enc'] ?? null, 'category_enc');
$tagsEnc     = validateEncField($body['tags_enc'] ?? null, 'tags_enc');

$strengthScore = max(0, min(4, (int) ($body['strength_score'] ?? 0)));
$isFavourite   = isset($body['is_favourite']) ? (int) (bool) $body['is_favourite'] : null;
$updateLastUsed = (bool) ($body['update_last_used'] ?? false);

$sql    = 'UPDATE vault_entries
           SET title_enc = ?, url_enc = ?, username_enc = ?, password_enc = ?,
               notes_enc = ?, category_enc = ?, tags_enc = ?, iv = ?,
               strength_score = ?, updated_at = NOW()';
$params = [
    $titleEnc, $urlEnc, $usernameEnc, $passwordEnc,
    $notesEnc, $categoryEnc, $tagsEnc, $iv, $strengthScore,
];

if ($isFavourite !== null) {
    $sql .= ', is_favourite = ?';
    $params[] = $isFavourite;
}

if ($updateLastUsed) {
    $sql .= ', last_used = NOW()';
}

$sql      .= ' WHERE uuid = ? AND user_id = ?';
$params[]  = $uuid;
$params[]  = $user['id'];

Database::execute($sql, $params);

Response::success(['uuid' => $uuid, 'updated_at' => date('Y-m-d H:i:s')], 'Entrada atualizada com sucesso.');
