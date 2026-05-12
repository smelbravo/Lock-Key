<?php
/**
 * Lock & Key - Middleware de Rate Limiting
 *
 * Protege endpoints sensíveis contra ataques de brute force:
 * - Login: máx 5 tentativas em 15 minutos por IP+email
 * - Registo: máx 3 tentativas em 1 hora por IP
 *
 * Implementação baseada em sliding window na base de dados.
 * Em produção considerar Redis para melhor performance.
 */

declare(strict_types=1);

if (!defined('LK_APP')) {
    http_response_code(403);
    exit('Acesso negado.');
}

class RateLimit
{
    /**
     * Verificar e registar tentativa
     *
     * @param  string $identifier  IP ou email
     * @param  string $action      Ação a limitar (ex: 'login', 'register')
     * @param  int    $maxAttempts Máximo de tentativas
     * @param  int    $windowSecs  Janela de tempo em segundos
     * @return void                Termina com 429 se limite excedido
     */
    public static function check(
        string $identifier,
        string $action,
        int $maxAttempts,
        int $windowSecs
    ): void {
        $identifier = hash('sha256', strtolower(trim($identifier))); // Anonimizar identificador

        try {
            // Obter registo existente
            $record = Database::fetchOne(
                'SELECT id, attempts, window_start, blocked_until
                 FROM rate_limits
                 WHERE identifier = ? AND action = ?',
                [$identifier, $action]
            );

            $now = time();

            if ($record === null) {
                // Primeira tentativa - criar registo
                Database::execute(
                    'INSERT INTO rate_limits (identifier, action, attempts, window_start)
                     VALUES (?, ?, 1, NOW())',
                    [$identifier, $action]
                );
                return;
            }

            // Verificar se ainda está bloqueado
            if ($record['blocked_until'] !== null) {
                $blockedUntil = strtotime($record['blocked_until']);
                if ($now < $blockedUntil) {
                    $retryAfter = $blockedUntil - $now;
                    Response::tooManyRequests($retryAfter);
                }
            }

            $windowStart = strtotime($record['window_start']);

            // Janela de tempo expirou - resetar
            if (($now - $windowStart) > $windowSecs) {
                Database::execute(
                    'UPDATE rate_limits
                     SET attempts = 1, window_start = NOW(), blocked_until = NULL
                     WHERE identifier = ? AND action = ?',
                    [$identifier, $action]
                );
                return;
            }

            // Incrementar tentativas
            $attempts = (int) $record['attempts'] + 1;

            if ($attempts > $maxAttempts) {
                // Calcular tempo de bloqueio (exponential backoff)
                $overLimit   = $attempts - $maxAttempts;
                $blockTime   = min(3600, $windowSecs * (2 ** ($overLimit - 1)));
                $blockedUntil = date('Y-m-d H:i:s', $now + $blockTime);

                Database::execute(
                    'UPDATE rate_limits
                     SET attempts = ?, blocked_until = ?
                     WHERE identifier = ? AND action = ?',
                    [$attempts, $blockedUntil, $identifier, $action]
                );

                Response::tooManyRequests($blockTime);
            }

            // Atualizar contador
            Database::execute(
                'UPDATE rate_limits SET attempts = ? WHERE identifier = ? AND action = ?',
                [$attempts, $identifier, $action]
            );

        } catch (\PDOException $e) {
            // Em caso de falha da BD, permitir a requisição mas registar
            error_log("Rate limit error: " . $e->getMessage());
        }
    }

    /**
     * Resetar contador após sucesso (ex: após login bem-sucedido)
     */
    public static function reset(string $identifier, string $action): void
    {
        $identifier = hash('sha256', strtolower(trim($identifier)));

        try {
            Database::execute(
                'DELETE FROM rate_limits WHERE identifier = ? AND action = ?',
                [$identifier, $action]
            );
        } catch (\PDOException $e) {
            error_log("Rate limit reset error: " . $e->getMessage());
        }
    }

    /**
     * Verificar rate limit para login (IP + email combinados)
     */
    public static function checkLogin(string $email): void
    {
        $ip = AuthMiddleware::getClientIp();

        // Limitar por IP
        self::check(
            $ip,
            'login_ip',
            RATE_LIMIT_LOGIN_MAX * 3, // IP pode ter múltiplos utilizadores
            RATE_LIMIT_LOGIN_WINDOW
        );

        // Limitar por email (protege contas específicas)
        self::check(
            $email,
            'login_email',
            RATE_LIMIT_LOGIN_MAX,
            RATE_LIMIT_LOGIN_WINDOW
        );
    }

    /**
     * Resetar rate limit de login após sucesso
     */
    public static function resetLogin(string $email): void
    {
        $ip = AuthMiddleware::getClientIp();
        self::reset($ip, 'login_ip');
        self::reset($email, 'login_email');
    }

    /**
     * Verificar rate limit para registo
     */
    public static function checkRegister(): void
    {
        $ip = AuthMiddleware::getClientIp();
        self::check($ip, 'register', RATE_LIMIT_REGISTER_MAX, RATE_LIMIT_REGISTER_WINDOW);
    }
}
