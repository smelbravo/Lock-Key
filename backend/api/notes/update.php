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

// Validar tamanho e formato base64 de cada campo encriptado (igual ao create.php)
function validateNoteUpdField(?string $v, string $f, int $maxLen = 65535): ?string {
    if ($v === null || $v === '') return null;
    if (base64_decode($v, true) === false) Response::error("Campo '{$f}' inválido.", 422);
    if (strlen($v) > $maxLen) Response::error("Campo '{$f}' excede o tamanho máximo.", 422);
    return $v;
}

$titleEnc    = validateNoteUpdField($body['title_enc']    ?? null, 'title_enc');
$contentEnc  = validateNoteUpdField($body['content_enc']  ?? null, 'content_enc', 1048576); // 1MB
$categoryEnc = validateNoteUpdField($body['category_enc'] ?? null, 'category_enc');

if ($titleEnc === null || $contentEnc === null) {
    Response::error('Título e conteúdo são obrigatórios.', 422);
}

Database::execute(
    'UPDATE secure_notes
     SET title_enc = ?, content_enc = ?, category_enc = ?, iv = ?,
         is_favourite = ?, updated_at = NOW()
     WHERE uuid = ? AND user_id = ?',
    [
        $titleEnc, $contentEnc, $categoryEnc, $iv,
        (int) (bool) ($body['is_favourite'] ?? false),
        $uuid, $user['id'],
    ]
);

Response::success(['uuid' => $uuid, 'updated_at' => date('Y-m-d H:i:s')], 'Nota atualizada com sucesso.');
