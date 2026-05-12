<?php
/**
 * Lock & Key - Implementação JWT (JSON Web Tokens)
 * Algoritmo: HS256 (HMAC-SHA256)
 * Sem dependências externas - implementação pura em PHP
 *
 * Decisão de Segurança:
 * - Access token: TTL curto (1h) para minimizar janela de exposição
 * - Refresh token: TTL longo (30d) armazenado de forma segura no servidor
 * - Tokens são invalidados na BD para permitir logout imediato
 * - O token hash é armazenado na BD para verificação e revogação
 */

declare(strict_types=1);

if (!defined('LK_APP')) {
    http_response_code(403);
    exit('Acesso negado.');
}

class JWT
{
    /**
     * Gerar um novo JWT
     *
     * @param array  $payload  Dados a incluir no token (user_id, email, etc.)
     * @param int    $ttl      Time-to-live em segundos
     * @return string          Token JWT assinado
     */
    public static function generate(array $payload, int $ttl = JWT_ACCESS_TTL): string
    {
        $header = self::base64UrlEncode(json_encode([
            'alg' => 'HS256',
            'typ' => 'JWT',
        ]));

        $now = time();
        $payload = array_merge($payload, [
            'iss' => JWT_ISSUER,
            'iat' => $now,
            'exp' => $now + $ttl,
            'jti' => bin2hex(random_bytes(16)), // JWT ID único para evitar replay
        ]);

        $payloadEncoded = self::base64UrlEncode(json_encode($payload));
        $signature      = self::sign("{$header}.{$payloadEncoded}");

        return "{$header}.{$payloadEncoded}.{$signature}";
    }

    /**
     * Verificar e decodificar um JWT
     *
     * @param  string $token   Token JWT a verificar
     * @return array           Payload decodificado
     * @throws RuntimeException Se o token for inválido ou expirado
     */
    public static function verify(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new RuntimeException('Token JWT malformado.');
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        // Verificar assinatura (tempo constante para evitar timing attacks)
        $expectedSig = self::sign("{$headerB64}.{$payloadB64}");
        if (!hash_equals($expectedSig, $signatureB64)) {
            throw new RuntimeException('Assinatura JWT inválida.');
        }

        // Decodificar payload
        $payload = json_decode(self::base64UrlDecode($payloadB64), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('Payload JWT inválido.');
        }

        // Verificar expiração
        if (!isset($payload['exp']) || $payload['exp'] < time()) {
            throw new RuntimeException('Token JWT expirado.');
        }

        // Verificar issuer
        if (($payload['iss'] ?? '') !== JWT_ISSUER) {
            throw new RuntimeException('Issuer JWT inválido.');
        }

        return $payload;
    }

    /**
     * Extrair payload sem verificar assinatura (use apenas para diagnóstico)
     */
    public static function decode(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        return is_array($payload) ? $payload : null;
    }

    /**
     * Obter o hash do token para armazenar na BD
     * Nunca armazenar o token em claro na BD
     */
    public static function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * Gerar refresh token (opaco, não é JWT)
     */
    public static function generateRefreshToken(): string
    {
        return bin2hex(random_bytes(64)); // 128 chars hex
    }

    /**
     * Assinar string com HMAC-SHA256
     */
    private static function sign(string $data): string
    {
        return self::base64UrlEncode(
            hash_hmac('sha256', $data, JWT_SECRET, true)
        );
    }

    /**
     * Codificação Base64 URL-safe (RFC 4648)
     */
    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Descodificação Base64 URL-safe
     */
    private static function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
    }
}
