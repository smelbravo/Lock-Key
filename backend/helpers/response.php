<?php
/**
 * Lock & Key - Helper de Respostas API
 * Padroniza todas as respostas JSON da API
 * Formato: { success, data/error, message, timestamp }
 */

declare(strict_types=1);

if (!defined('LK_APP')) {
    http_response_code(403);
    exit('Acesso negado.');
}

class Response
{
    /**
     * Resposta de sucesso
     *
     * @param mixed  $data    Dados a retornar
     * @param string $message Mensagem descritiva
     * @param int    $status  Código HTTP (padrão 200)
     */
    public static function success(mixed $data = null, string $message = 'OK', int $status = 200): never
    {
        http_response_code($status);
        echo json_encode([
            'success'   => true,
            'message'   => $message,
            'data'      => $data,
            'timestamp' => time(),
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit();
    }

    /**
     * Resposta de erro
     *
     * @param string $message Mensagem de erro (segura para exposição)
     * @param int    $status  Código HTTP (padrão 400)
     * @param array  $errors  Erros de validação detalhados (opcional)
     */
    public static function error(string $message, int $status = 400, array $errors = []): never
    {
        http_response_code($status);
        $body = [
            'success'   => false,
            'message'   => $message,
            'timestamp' => time(),
        ];
        if (!empty($errors)) {
            $body['errors'] = $errors;
        }
        echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit();
    }

    /**
     * Resposta 401 Não Autorizado
     */
    public static function unauthorized(string $message = 'Não autorizado.'): never
    {
        self::error($message, 401);
    }

    /**
     * Resposta 403 Proibido
     */
    public static function forbidden(string $message = 'Acesso proibido.'): never
    {
        self::error($message, 403);
    }

    /**
     * Resposta 404 Não Encontrado
     */
    public static function notFound(string $message = 'Recurso não encontrado.'): never
    {
        self::error($message, 404);
    }

    /**
     * Resposta 429 Rate Limit
     */
    public static function tooManyRequests(int $retryAfter = 900): never
    {
        header("Retry-After: {$retryAfter}");
        self::error(
            "Demasiadas tentativas. Tente novamente em " . ceil($retryAfter / 60) . " minutos.",
            429
        );
    }

    /**
     * Resposta 500 Erro Interno
     * Nunca expõe detalhes do erro em produção
     */
    public static function serverError(string $internalMessage = ''): never
    {
        if (APP_DEBUG && !empty($internalMessage)) {
            self::error("Erro interno: {$internalMessage}", 500);
        }
        self::error('Erro interno do servidor. Tente novamente.', 500);
    }

    /**
     * Resposta 405 Método Não Permitido
     */
    public static function methodNotAllowed(array $allowed = []): never
    {
        if (!empty($allowed)) {
            header('Allow: ' . implode(', ', $allowed));
        }
        self::error('Método HTTP não permitido.', 405);
    }

    /**
     * Validar método HTTP da requisição
     */
    public static function requireMethod(string ...$methods): void
    {
        if (!in_array($_SERVER['REQUEST_METHOD'], $methods, true)) {
            self::methodNotAllowed($methods);
        }
    }

    /**
     * Obter e validar corpo JSON da requisição
     */
    public static function getJsonBody(): array
    {
        $raw = file_get_contents('php://input');
        if (empty($raw)) {
            return [];
        }

        $data = json_decode($raw, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            self::error('Corpo da requisição JSON inválido.', 400);
        }

        return is_array($data) ? $data : [];
    }

    /**
     * Validar campos obrigatórios no body
     *
     * @param array $body   Dados recebidos
     * @param array $fields Campos obrigatórios
     */
    public static function requireFields(array $body, array $fields): void
    {
        $missing = [];
        foreach ($fields as $field) {
            if (!isset($body[$field]) || (is_string($body[$field]) && trim($body[$field]) === '')) {
                $missing[] = $field;
            }
        }

        if (!empty($missing)) {
            self::error(
                'Campos obrigatórios em falta: ' . implode(', ', $missing),
                422,
                array_map(fn($f) => ['field' => $f, 'message' => 'Campo obrigatório.'], $missing)
            );
        }
    }
}
