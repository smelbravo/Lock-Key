<?php
/**
 * Lock & Key - API: Criar Nota Segura
 * POST /api/notes/create.php
 *
 * Body: { "title_enc": string, "content_enc": string, "category_enc": string|null, "iv": string }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user = AuthMiddleware::require();
$body = Response::getJsonBody();
Response::requireFields($body, ['title_enc', 'content_enc', 'iv']);

$iv = $body['iv'] ?? '';
if (!preg_match('/^[A-Za-z0-9+\/]{16}$/', $iv)) {
    Response::error('IV inválido.', 422);
}

function validateNoteField(?string $v, string $f, int $maxLen = 65535): ?string
{
    if ($v === null || $v === '') return null;
    if (base64_decode($v, true) === false) Response::error("Campo '{$f}' inválido.", 422);
    if (strlen($v) > $maxLen) Response::error("Campo '{$f}' excede o tamanho máximo.", 422);
    return $v;
}

$titleEnc   = validateNoteField($body['title_enc'] ?? null, 'title_enc');
$contentEnc = validateNoteField($body['content_enc'] ?? null, 'content_enc', 1048576); // 1MB
$categoryEnc = validateNoteField($body['category_enc'] ?? null, 'category_enc');

if ($titleEnc === null || $contentEnc === null) {
    Response::error('Título e conteúdo são obrigatórios.', 422);
}

// Limite de notas
$count = Database::fetchOne('SELECT COUNT(*) as cnt FROM secure_notes WHERE user_id = ?', [$user['id']]);
if ((int) $count['cnt'] >= 1000) {
    Response::error('Limite de notas atingido (1.000).', 429);
}

$uuid = Encryption::generateUUID();

Database::insert(
    'INSERT INTO secure_notes (uuid, user_id, title_enc, content_enc, category_enc, iv)
     VALUES (?, ?, ?, ?, ?, ?)',
    [$uuid, $user['id'], $titleEnc, $contentEnc, $categoryEnc, $iv]
);

Response::success(['uuid' => $uuid, 'created_at' => date('Y-m-d H:i:s')], 'Nota criada com sucesso.', 201);
