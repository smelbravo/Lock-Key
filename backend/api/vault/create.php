<?php
/**
 * Lock & Key - API: Criar Entrada no Cofre
 * POST /api/vault/create.php
 *
 * Recebe dados JÁ ENCRIPTADOS pelo cliente (AES-256-GCM).
 * O servidor armazena apenas ciphertext - nunca vê dados em claro.
 *
 * Body esperado:
 * {
 *   "title_enc": string (ciphertext base64),
 *   "password_enc": string (ciphertext base64, obrigatório),
 *   "url_enc": string|null,
 *   "username_enc": string|null,
 *   "notes_enc": string|null,
 *   "category_enc": string|null,
 *   "tags_enc": string|null,
 *   "iv": string (base64, 12 bytes = 16 chars base64),
 *   "strength_score": int (0-4, calculado no cliente)
 * }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user = AuthMiddleware::require();
$body = Response::getJsonBody();
Response::requireFields($body, ['title_enc', 'password_enc', 'iv']);

// Validar IV (base64 de 12 bytes = 16 chars)
$iv = $body['iv'] ?? '';
if (!preg_match('/^[A-Za-z0-9+\/]{16}$/', $iv)) {
    Response::error('IV inválido. Deve ser base64 de 12 bytes.', 422);
}

// Validar campos encriptados (devem ser base64 válido)
function validateEncrypted(?string $value, string $field): ?string
{
    if ($value === null || $value === '') return null;
    if (base64_decode($value, true) === false) {
        Response::error("Campo '{$field}' contém dados encriptados inválidos.", 422);
    }
    if (strlen($value) > 65535) { // 64KB por campo
        Response::error("Campo '{$field}' excede o tamanho máximo.", 422);
    }
    return $value;
}

$titleEnc    = validateEncrypted($body['title_enc'] ?? null, 'title_enc');
$passwordEnc = validateEncrypted($body['password_enc'] ?? null, 'password_enc');
$urlEnc      = validateEncrypted($body['url_enc'] ?? null, 'url_enc');
$usernameEnc = validateEncrypted($body['username_enc'] ?? null, 'username_enc');
$notesEnc    = validateEncrypted($body['notes_enc'] ?? null, 'notes_enc');
$categoryEnc = validateEncrypted($body['category_enc'] ?? null, 'category_enc');
$tagsEnc     = validateEncrypted($body['tags_enc'] ?? null, 'tags_enc');

if ($titleEnc === null || $passwordEnc === null) {
    Response::error('Título e password são obrigatórios.', 422);
}

$strengthScore = max(0, min(4, (int) ($body['strength_score'] ?? 0)));
$isFavourite   = (bool) ($body['is_favourite'] ?? false);

// Verificar limite de entradas conforme o plano do utilizador
$plan      = $user['plan'] ?? 'free';
$limits    = getPlanLimits($plan);
$vaultMax  = $limits['vault_max'];

$count = Database::fetchOne(
    'SELECT COUNT(*) as cnt FROM vault_entries WHERE user_id = ?',
    [$user['id']]
);
if ((int) $count['cnt'] >= $vaultMax) {
    Response::error(
        "Limite do plano '{$plan}' atingido ({$vaultMax} entradas). Faz upgrade para guardar mais.",
        429
    );
}

$uuid = Encryption::generateUUID();

Database::insert(
    'INSERT INTO vault_entries
        (uuid, user_id, title_enc, url_enc, username_enc, password_enc,
         notes_enc, category_enc, tags_enc, iv, strength_score, is_favourite)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
        $uuid, $user['id'], $titleEnc, $urlEnc, $usernameEnc, $passwordEnc,
        $notesEnc, $categoryEnc, $tagsEnc, $iv, $strengthScore, (int) $isFavourite,
    ]
);

Response::success([
    'uuid'       => $uuid,
    'created_at' => date('Y-m-d H:i:s'),
], 'Entrada criada com sucesso.', 201);
