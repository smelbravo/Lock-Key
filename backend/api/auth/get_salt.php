<?php
/**
 * Lock & Key - API: Obter Salt PBKDF2
 * POST /api/auth/get_salt.php
 *
 * Primeiro passo do login zero-knowledge:
 * O cliente precisa do salt para derivar authKey e encryptionKey
 * antes de poder autenticar.
 *
 * SEGURANÇA: Retornamos sempre uma resposta (mesmo para emails inexistentes)
 * para evitar enumeração de contas. Se o email não existe, geramos um salt
 * determinístico falso (baseado no email + segredo do servidor).
 *
 * Body esperado: { "email": string }
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$body = Response::getJsonBody();
Response::requireFields($body, ['email']);

$email = strtolower(sanitize($body['email']));

if (!validateEmail($email)) {
    Response::error('Email inválido.', 422);
}

// Rate limiting leve (evitar abuso de enumeração)
RateLimit::check(AuthMiddleware::getClientIp(), 'get_salt', 30, 60);

$user = Database::fetchOne(
    'SELECT vault_salt, pbkdf2_iterations FROM users WHERE email = ?',
    [$email]
);

if ($user !== null) {
    Response::success([
        'salt'       => $user['vault_salt'],
        'iterations' => (int) $user['pbkdf2_iterations'],
    ]);
} else {
    // Gerar salt determinístico falso para não revelar que o email não existe
    // Isto mantém o tempo de resposta consistente e impede enumeração
    $fakeSalt = hash_hmac('sha256', $email . 'fake_salt_seed', JWT_SECRET);
    usleep(random_int(50000, 150000)); // Simular tempo de query BD

    Response::success([
        'salt'       => $fakeSalt,
        'iterations' => 200000,
    ]);
}
