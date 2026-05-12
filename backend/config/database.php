<?php
/**
 * Lock & Key - Conexão à Base de Dados (PDO Singleton)
 * Utiliza PDO com prepared statements para prevenir SQL injection
 * Charset utf8mb4 para suporte completo a Unicode e emoji
 */

declare(strict_types=1);

if (!defined('LK_APP')) {
    http_response_code(403);
    exit('Acesso negado.');
}

class Database
{
    private static ?PDO $instance = null;

    /**
     * Obtém a instância PDO (singleton)
     * Cria a conexão na primeira chamada, reutiliza nas seguintes
     */
    public static function getInstance(): PDO
    {
        if (self::$instance === null) {
            self::$instance = self::createConnection();
        }
        return self::$instance;
    }

    private static function createConnection(): PDO
    {
        $host    = env('DB_HOST', '127.0.0.1');
        $port    = env('DB_PORT', '3306');
        $dbname  = env('DB_NAME', 'lockandkey');
        $charset = env('DB_CHARSET', 'utf8mb4');
        $user    = env('DB_USER', 'root');
        $pass    = env('DB_PASS', '');

        $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset={$charset}";

        $options = [
            // Lançar exceções em vez de retornar false
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            // Retornar arrays associativos por padrão
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // Desativar emulação de prepared statements (mais seguro)
            PDO::ATTR_EMULATE_PREPARES   => false,
            // Persistência de conexão (cuidado em produção com pools)
            PDO::ATTR_PERSISTENT         => false,
            // Tempo limite de conexão
            PDO::ATTR_TIMEOUT            => 10,
            // Inicialização: desativar strict mode problemático, forçar charset
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci, time_zone='+00:00'",
            // Ativar SSL em produção
            // PDO::MYSQL_ATTR_SSL_CA => '/path/to/ca.pem',
        ];

        try {
            $pdo = new PDO($dsn, $user, $pass, $options);
            return $pdo;
        } catch (PDOException $e) {
            // Em produção, não expor detalhes do erro
            if (APP_DEBUG) {
                throw new RuntimeException('Falha na conexão à base de dados: ' . $e->getMessage());
            }
            throw new RuntimeException('Serviço temporariamente indisponível. Tente novamente.');
        }
    }

    /**
     * Executar query com parâmetros e retornar statement
     */
    public static function query(string $sql, array $params = []): PDOStatement
    {
        $pdo  = self::getInstance();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    /**
     * Obter um único registo
     */
    public static function fetchOne(string $sql, array $params = []): ?array
    {
        $result = self::query($sql, $params)->fetch();
        return $result ?: null;
    }

    /**
     * Obter todos os registos
     */
    public static function fetchAll(string $sql, array $params = []): array
    {
        return self::query($sql, $params)->fetchAll();
    }

    /**
     * Executar INSERT e retornar último ID inserido
     */
    public static function insert(string $sql, array $params = []): string
    {
        self::query($sql, $params);
        return self::getInstance()->lastInsertId();
    }

    /**
     * Executar UPDATE/DELETE e retornar número de linhas afetadas
     */
    public static function execute(string $sql, array $params = []): int
    {
        return self::query($sql, $params)->rowCount();
    }

    /**
     * Iniciar transação
     */
    public static function beginTransaction(): void
    {
        self::getInstance()->beginTransaction();
    }

    /**
     * Confirmar transação
     */
    public static function commit(): void
    {
        self::getInstance()->commit();
    }

    /**
     * Reverter transação
     */
    public static function rollback(): void
    {
        self::getInstance()->rollBack();
    }

    // Impedir clonagem e deserialização
    private function __construct() {}
    private function __clone() {}
    public function __wakeup(): void
    {
        throw new \Exception('Não é possível deserializar singleton.');
    }
}
