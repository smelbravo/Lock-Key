<?php
/**
 * Lock & Key - Utilitários de Encriptação no Servidor
 *
 * Decisões de Segurança:
 * - AES-256-GCM para encriptação autenticada (AEAD)
 *   Detecta adulteração dos dados encriptados
 * - Cada operação gera IV/nonce aleatório único (12 bytes para GCM)
 * - Os dados do cofre são encriptados NO CLIENTE antes de chegarem aqui
 *   Esta classe é para dados auxiliares do servidor (não o cofre do utilizador)
 * - password_hash() com PASSWORD_ARGON2ID para hashes de passwords
 *   Argon2id é resistente a ataques de GPU e side-channel
 */

declare(strict_types=1);

if (!defined('LK_APP')) {
    http_response_code(403);
    exit('Acesso negado.');
}

class Encryption
{
    private const CIPHER   = 'aes-256-gcm';
    private const IV_LEN   = 12;  // 96 bits, recomendado para GCM
    private const TAG_LEN  = 16;  // 128 bits authentication tag

    /**
     * Encriptar dados com AES-256-GCM
     * Usado para dados auxiliares do servidor (não o cofre)
     *
     * @param  string $plaintext Texto a encriptar
     * @param  string $key       Chave de 32 bytes (256 bits)
     * @return string            IV + Tag + Ciphertext em Base64
     */
    public static function encrypt(string $plaintext, string $key = ''): string
    {
        if (empty($key)) {
            $key = SERVER_ENCRYPT_KEY;
        }

        if (strlen($key) !== 32) {
            throw new RuntimeException('Chave de encriptação deve ter 32 bytes.');
        }

        $iv  = random_bytes(self::IV_LEN);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LEN
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Falha na encriptação.');
        }

        // Combinar: IV (12) + Tag (16) + Ciphertext
        return base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * Desencriptar dados AES-256-GCM
     *
     * @param  string $encoded  Dados em Base64 (IV + Tag + Ciphertext)
     * @param  string $key      Chave de 32 bytes
     * @return string           Texto desencriptado
     */
    public static function decrypt(string $encoded, string $key = ''): string
    {
        if (empty($key)) {
            $key = SERVER_ENCRYPT_KEY;
        }

        if (strlen($key) !== 32) {
            throw new RuntimeException('Chave de desencriptação deve ter 32 bytes.');
        }

        $raw = base64_decode($encoded, true);
        if ($raw === false || strlen($raw) < self::IV_LEN + self::TAG_LEN + 1) {
            throw new RuntimeException('Dados encriptados inválidos.');
        }

        $iv         = substr($raw, 0, self::IV_LEN);
        $tag        = substr($raw, self::IV_LEN, self::TAG_LEN);
        $ciphertext = substr($raw, self::IV_LEN + self::TAG_LEN);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            throw new RuntimeException('Falha na desencriptação. Dados adulterados?');
        }

        return $plaintext;
    }

    /**
     * Hash seguro de password com Argon2id
     *
     * Argon2id combina proteção contra ataques de side-channel (Argon2i)
     * e ataques de GPU (Argon2d), sendo a escolha recomendada para passwords.
     *
     * @param  string $password Password em texto simples
     * @return string           Hash Argon2id
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,   // 64 MB - resistência a GPU
            'time_cost'   => 4,       // 4 iterações
            'threads'     => 2,       // 2 threads paralelos
        ]);
    }

    /**
     * Verificar password contra hash
     * Usa comparação em tempo constante (resistente a timing attacks)
     *
     * @param  string $password Password em texto simples
     * @param  string $hash     Hash Argon2id armazenado
     * @return bool
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Verificar se o hash necessita de ser re-calculado (parâmetros atualizados)
     */
    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 2,
        ]);
    }

    /**
     * Gerar UUID v4 criptograficamente seguro
     */
    public static function generateUUID(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40); // versão 4
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80); // variante RFC 4122

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    /**
     * Gerar salt aleatório para PBKDF2 (enviado ao cliente para derivação de chaves)
     * 32 bytes = 256 bits de entropia
     */
    public static function generateSalt(): string
    {
        return bin2hex(random_bytes(32)); // 64 chars hex
    }

    /**
     * Gerar token seguro (para refresh tokens, CSRF, etc.)
     * @param  int $bytes Comprimento em bytes
     */
    public static function generateToken(int $bytes = 64): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * Comparação de strings em tempo constante
     * Previne timing attacks na comparação de tokens
     */
    public static function timingSafeCompare(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }
}
