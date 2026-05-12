<?php
/**
 * Lock & Key - API: Registo de Utilizador
 * POST /api/auth/register.php
 *
 * Arquitetura Zero-Knowledge:
 * - O cliente deriva authKey e encryptionKey da senha mestra usando PBKDF2
 * - O servidor recebe apenas authKey (nunca a senha mestra real)
 * - O encryptionKey NUNCA chega ao servidor
 * - O servidor armazena hash(authKey) com Argon2id
 * - O salt PBKDF2 é gerado no servidor e enviado ao cliente
 *
 * Body esperado:
 * {
 *   "email": string,
 *   "username": string,
 *   "auth_key": string (hex, 64 chars - 256 bits derivados da senha mestra)
 * }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$body = Response::getJsonBody();
Response::requireFields($body, ['email', 'username', 'auth_key']);

// Rate limiting por IP
RateLimit::checkRegister();

// Sanitizar e validar inputs
$email    = strtolower(sanitize($body['email']));
$username = sanitize($body['username'], 100);
$authKey  = trim($body['auth_key'] ?? '');

// Validações
if (!validateEmail($email)) {
    Response::error('Endereço de email inválido.', 422);
}

if (strlen($username) < 3 || strlen($username) > 100) {
    Response::error('Username deve ter entre 3 e 100 caracteres.', 422);
}

// Validar authKey: deve ser hex de 64 chars (256 bits)
if (!preg_match('/^[0-9a-f]{64}$/', $authKey)) {
    Response::error('Chave de autenticação inválida. Verifique o processo de derivação.', 422);
}

// Verificar se o email já existe
$existing = Database::fetchOne(
    'SELECT id FROM users WHERE email = ?',
    [$email]
);

if ($existing !== null) {
    // Não revelar se o email existe (segurança)
    // Usar atraso artificial para prevenir enumeração de email via timing
    usleep(random_int(100000, 300000));
    Response::error('Não foi possível criar a conta. Verifique os dados e tente novamente.', 409);
}

try {
    Database::beginTransaction();

    // Gerar UUID e salt para o novo utilizador
    $uuid      = Encryption::generateUUID();
    $vaultSalt = Encryption::generateSalt(); // Salt PBKDF2 (enviado ao cliente no login)

    // Hash do authKey com Argon2id (NUNCA armazenar authKey em claro)
    $authKeyHash = Encryption::hashPassword($authKey);

    // Inserir utilizador
    Database::insert(
        'INSERT INTO users (uuid, email, username, auth_key_hash, vault_salt, pbkdf2_iterations)
         VALUES (?, ?, ?, ?, ?, ?)',
        [$uuid, $email, $username, $authKeyHash, $vaultSalt, 200000]
    );

    Database::commit();

    // Registar no audit log
    auditLog('user_registered', null, ['email' => $email]);

    Response::success([
        'uuid'     => $uuid,
        'email'    => $email,
        'username' => $username,
    ], 'Conta criada com sucesso!', 201);

} catch (\Throwable $e) {
    Database::rollback();
    error_log("Register error: " . $e->getMessage());
    Response::serverError($e->getMessage());
}
