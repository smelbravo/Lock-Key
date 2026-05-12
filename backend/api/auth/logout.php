<?php
/**
 * Lock & Key - API: Logout
 * POST /api/auth/logout.php
 *
 * Revoga o token JWT atual na base de dados.
 * O cliente deve também limpar o token e encryptionKey da memória.
 *
 * Header: Authorization: Bearer <token>
 * Body: { "all_sessions": bool } (opcional - terminar todas as sessões)
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('POST');

$user  = AuthMiddleware::require();
$body  = Response::getJsonBody();
$token = substr($_SERVER['HTTP_AUTHORIZATION'] ?? '', 7);

$allSessions = (bool) ($body['all_sessions'] ?? false);

if ($allSessions) {
    // Revogar todas as sessões do utilizador
    AuthMiddleware::revokeAllSessions($user['id']);
    auditLog('logout_all', $user['id']);
    Response::success(null, 'Todas as sessões terminadas com sucesso.');
} else {
    // Revogar apenas sessão atual
    AuthMiddleware::revokeSession($token);
    auditLog('logout', $user['id']);
    Response::success(null, 'Sessão terminada com sucesso.');
}
