<?php
/**
 * Lock & Key - Middleware de Autenticação JWT
 *
 * Verifica o token JWT em cada requisição protegida:
 * 1. Extrai o token do header Authorization: Bearer <token>
 * 2. Verifica a assinatura HMAC-SHA256
 * 3. Confirma que o token não está revogado na BD
 * 4. Atualiza last_activity da sessão
 * 5. Retorna os dados do utilizador autenticado
 */

declare(strict_types=1);

if (!defined('LK_APP')) {
    http_response_code(403);
    exit('Acesso negado.');
}

class AuthMiddleware
{
    /**
     * Verificar autenticação e retornar dados do utilizador
     * Termina a execução com 401 se não autenticado
     *
     * @return array Dados do utilizador { id, uuid, email, username }
     */
    public static function require(): array
    {
        $token = self::extractToken();

        if ($token === null) {
            Response::unauthorized('Token de autenticação em falta. Faça login.');
        }

        try {
            // Verificar assinatura e expiração
            $payload = JWT::verify($token);
        } catch (RuntimeException $e) {
            Response::unauthorized($e->getMessage());
        }

        // Verificar se o token está revogado na BD
        $tokenHash = JWT::hash($token);
        $session   = Database::fetchOne(
            'SELECT s.id, s.user_id, s.is_revoked, u.uuid, u.email, u.username, u.is_active
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ?
               AND s.expires_at > NOW()
               AND s.is_revoked = 0',
            [$tokenHash]
        );

        if ($session === null) {
            Response::unauthorized('Sessão inválida ou expirada. Faça login novamente.');
        }

        if (!$session['is_active']) {
            Response::unauthorized('Conta desativada. Contacte o suporte.');
        }

        // Atualizar last_activity (não crítico - ignorar falha)
        try {
            Database::execute(
                'UPDATE sessions SET last_activity = NOW() WHERE token_hash = ?',
                [$tokenHash]
            );
        } catch (\Throwable $e) {
            // Não bloquear o utilizador por falha de atualização
        }

        return [
            'id'       => (int) $payload['user_id'],
            'uuid'     => $session['uuid'],
            'email'    => $session['email'],
            'username' => $session['username'],
        ];
    }

    /**
     * Verificar autenticação opcional (retorna null se não autenticado)
     */
    public static function optional(): ?array
    {
        $token = self::extractToken();
        if ($token === null) return null;

        try {
            return self::require();
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Registar sessão na BD após login bem-sucedido
     *
     * @param  int    $userId       ID do utilizador
     * @param  string $token        JWT access token
     * @param  string $refreshToken Refresh token opaco
     * @param  bool   $isExtension  Sessão da extensão Firefox
     */
    public static function createSession(
        int    $userId,
        string $token,
        string $refreshToken,
        bool   $isExtension = false
    ): void {
        $tokenHash   = JWT::hash($token);
        $refreshHash = hash('sha256', $refreshToken);
        $deviceInfo  = substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 300);
        $ip          = self::getClientIp();

        Database::execute(
            'INSERT INTO sessions
                (user_id, token_hash, refresh_hash, device_info, ip_address, is_extension,
                 expires_at, refresh_expires_at)
             VALUES (?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), DATE_ADD(NOW(), INTERVAL ? SECOND))',
            [
                $userId, $tokenHash, $refreshHash,
                $deviceInfo, $ip, (int) $isExtension,
                JWT_ACCESS_TTL, JWT_REFRESH_TTL,
            ]
        );
    }

    /**
     * Revogar sessão (logout)
     *
     * @param string $token JWT token a revogar
     */
    public static function revokeSession(string $token): void
    {
        $tokenHash = JWT::hash($token);
        Database::execute(
            'UPDATE sessions SET is_revoked = 1 WHERE token_hash = ?',
            [$tokenHash]
        );
    }

    /**
     * Revogar todas as sessões de um utilizador
     */
    public static function revokeAllSessions(int $userId): void
    {
        Database::execute(
            'UPDATE sessions SET is_revoked = 1 WHERE user_id = ?',
            [$userId]
        );
    }

    /**
     * Extrair token JWT do header Authorization
     */
    private static function extractToken(): ?string
    {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

        // Suporte para Apache que pode remover o header Authorization
        if (empty($authHeader) && function_exists('getallheaders')) {
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        }

        if (empty($authHeader)) return null;

        if (!str_starts_with($authHeader, 'Bearer ')) return null;

        $token = substr($authHeader, 7);
        return !empty($token) ? $token : null;
    }

    /**
     * Obter IP real do cliente (considera proxies confiáveis)
     */
    public static function getClientIp(): string
    {
        // Verificar headers de proxy (apenas em produção com proxies confiáveis)
        if (APP_ENV === 'production') {
            $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'];
            foreach ($headers as $header) {
                if (!empty($_SERVER[$header])) {
                    $ip = explode(',', $_SERVER[$header])[0];
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                }
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}
