<?php
/**
 * Lock & Key - Script de Criação de Conta Admin Master
 * 
 * ATENÇÃO: Este script deve ser executado UMA ÚNICA VEZ.
 * Apagar ou mover para fora do htdocs após execução!
 * 
 * Aceder via: http://localhost/Lock&Key/setup/create_admin.php
 * 
 * Segurança: Implementa o mesmo fluxo zero-knowledge do frontend —
 * usa PBKDF2-SHA256 em PHP para derivar o authKey, tal como o browser faria.
 */

// Proteção básica: token de setup
define('SETUP_TOKEN', 'LK_SETUP_2026_INIT');

// Verificar se já foi executado
$lockFile = __DIR__ . '/.setup_done';

header('Content-Type: text/html; charset=utf-8');

// Carregar configuração
$envPath = dirname(__DIR__) . '/config/.env';
if (!file_exists($envPath)) {
    die('<h2 style="color:red">Erro: ficheiro config/.env não encontrado.</h2>');
}

// Ler .env
$lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$env = [];
foreach ($lines as $line) {
    if (strpos(trim($line), '#') === 0) continue;
    if (strpos($line, '=') === false) continue;
    [$key, $val] = explode('=', $line, 2);
    $env[trim($key)] = trim($val);
}

// Conectar à base de dados
try {
    $dsn = sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        $env['DB_HOST'] ?? '127.0.0.1',
        $env['DB_PORT'] ?? '3306',
        $env['DB_NAME'] ?? 'lockandkey'
    );
    $pdo = new PDO($dsn, $env['DB_USER'] ?? 'root', $env['DB_PASS'] ?? '', [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
} catch (PDOException $e) {
    die('<h2 style="color:red">Erro de base de dados: ' . htmlspecialchars($e->getMessage()) . '</h2>');
}

// ============================================================
// DADOS DO ADMIN MASTER
// ============================================================
$adminData = [
    'username' => 'adminM_smel',
    'email'    => 'samuelbravo543@gmail.com',
    'password' => 'adm!nM4ster_smel_!!!',
    'role'     => 'admin_master',
    'plan'     => 'unlimited',
];

// ============================================================
// Processar criação
// ============================================================
$message = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['token'] ?? '') === SETUP_TOKEN) {

    // Verificar se o email já existe
    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ?');
    $stmt->execute([$adminData['email']]);
    if ($stmt->fetch()) {
        // Utilizador já existe — apenas atualizar role e plano
        $stmt = $pdo->prepare("
            UPDATE users
            SET role = 'admin_master', plan = 'unlimited', status = 'active'
            WHERE email = ?
        ");
        $stmt->execute([$adminData['email']]);
        $message = 'Conta já existia. Role e plano atualizados para admin_master / unlimited.';
        $success = true;
    } else {
        // Criar nova conta com derivação PBKDF2 em PHP (replica o que o browser faz)
        // O browser faz: PBKDF2-SHA256(masterPassword, salt, 200000, 512bits)
        // Primeiros 256 bits = authKey (enviado ao servidor)
        // Últimos 256 bits = encryptionKey (fica no browser, nunca no servidor)

        // Gerar salt (32 bytes = 64 hex chars), tal como o frontend
        $saltBytes  = random_bytes(32);
        $vaultSalt  = bin2hex($saltBytes);

        // IMPORTANTE: O frontend usa PBKDF2(password, UTF8(salt_hex + email), 200000, 512bits)
        // O salt do PBKDF2 é a concatenação do salt hexadecimal com o email em minúsculas
        // Isto replica exatamente o que o browser faz em crypto.js:
        //   const saltBytes = encode(salt + email.toLowerCase()); // TextEncoder UTF-8
        $pbkdf2Salt = $vaultSalt . strtolower($adminData['email']);

        // Derivar chave com PBKDF2-SHA256 (200.000 iterações, 64 bytes = 512 bits)
        $derived    = hash_pbkdf2('sha256', $adminData['password'], $pbkdf2Salt, 200000, 64, true);

        // Primeiros 32 bytes = authKey
        $authKeyRaw = substr($derived, 0, 32);
        $authKeyHex = bin2hex($authKeyRaw);

        // Hash do authKey com Argon2id (como o backend faz no registo normal)
        $authKeyHash = password_hash($authKeyHex, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 3,
        ]);

        // Gerar UUID v4 com random_bytes (criptograficamente seguro)
        $bytes    = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40); // version 4
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80); // variant 10xx
        $uuid     = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));

        try {
            $stmt = $pdo->prepare("
                INSERT INTO users
                    (uuid, email, username, role, plan, auth_key_hash, vault_salt, pbkdf2_iterations, email_verified, is_active, status)
                VALUES
                    (:uuid, :email, :username, :role, :plan, :auth_key_hash, :vault_salt, 200000, 1, 1, 'active')
            ");
            $stmt->execute([
                ':uuid'          => $uuid,
                ':email'         => $adminData['email'],
                ':username'      => $adminData['username'],
                ':role'          => $adminData['role'],
                ':plan'          => $adminData['plan'],
                ':auth_key_hash' => $authKeyHash,
                ':vault_salt'    => $vaultSalt,
            ]);

            $success = true;
            $message = 'Conta admin_master criada com sucesso!';

            // Criar ficheiro de lock para evitar re-execução acidental
            file_put_contents($lockFile, date('Y-m-d H:i:s'));

        } catch (PDOException $e) {
            $message = 'Erro ao criar conta: ' . htmlspecialchars($e->getMessage());
        }
    }
}

// Verificar se já existe um admin master
$stmt = $pdo->prepare("SELECT username, email, role, plan, created_at FROM users WHERE role = 'admin_master' LIMIT 1");
$stmt->execute();
$existingAdmin = $stmt->fetch();
?>
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <title>Lock & Key — Setup Admin</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #0d1117;
            color: #e6edf3;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 2rem;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 2.5rem;
            max-width: 520px;
            width: 100%;
        }
        .logo { font-size: 2rem; margin-bottom: 0.5rem; }
        h1 { font-size: 1.4rem; margin-bottom: 0.25rem; color: #58a6ff; }
        p.sub { color: #8b949e; font-size: 0.9rem; margin-bottom: 2rem; }
        .field { margin-bottom: 1.2rem; }
        label { display: block; font-size: 0.85rem; color: #8b949e; margin-bottom: 0.4rem; }
        .value {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 0.6rem 1rem;
            font-family: monospace;
            font-size: 0.9rem;
            color: #e6edf3;
        }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.7rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .badge-gold  { background: #2d2109; color: #f0a500; border: 1px solid #f0a500; }
        .badge-blue  { background: #0d1b2e; color: #58a6ff; border: 1px solid #58a6ff; }
        .btn {
            width: 100%;
            padding: 0.8rem;
            background: #1f6feb;
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            margin-top: 1rem;
        }
        .btn:hover { background: #388bfd; }
        .alert {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }
        .alert-success { background: #0d2a1e; border: 1px solid #2ea043; color: #3fb950; }
        .alert-error   { background: #2d0f0f; border: 1px solid #f85149; color: #f85149; }
        .alert-info    { background: #0d1b2e; border: 1px solid #1f6feb; color: #58a6ff; }
        .warning {
            background: #2d1f09;
            border: 1px solid #f0a500;
            color: #f0a500;
            border-radius: 8px;
            padding: 1rem;
            font-size: 0.85rem;
            margin-top: 1.5rem;
        }
        .divider { border: none; border-top: 1px solid #30363d; margin: 1.5rem 0; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        td { padding: 0.4rem 0; color: #8b949e; }
        td:last-child { color: #e6edf3; text-align: right; }
    </style>
</head>
<body>
<div class="card">
    <div class="logo">🔐</div>
    <h1>Lock & Key — Setup Admin</h1>
    <p class="sub">Criação única da conta administrador master</p>

    <?php if ($message): ?>
        <div class="alert <?= $success ? 'alert-success' : 'alert-error' ?>">
            <?= htmlspecialchars($message) ?>
        </div>
    <?php endif; ?>

    <?php if ($existingAdmin): ?>
        <div class="alert alert-info">
            ✅ Já existe um admin master registado:
            <br><strong><?= htmlspecialchars($existingAdmin['username']) ?></strong>
            (<?= htmlspecialchars($existingAdmin['email']) ?>)
        </div>
    <?php else: ?>
        <p style="color:#8b949e;font-size:0.9rem;margin-bottom:1.5rem;">
            A conta seguinte será criada com privilégios de <strong>Admin Master</strong> e plano <strong>Unlimited</strong>:
        </p>

        <div class="field">
            <label>Username</label>
            <div class="value"><?= htmlspecialchars($adminData['username']) ?></div>
        </div>
        <div class="field">
            <label>Email</label>
            <div class="value"><?= htmlspecialchars($adminData['email']) ?></div>
        </div>
        <div class="field">
            <label>Role</label>
            <span class="badge badge-gold">👑 Admin Master</span>
        </div>
        <div class="field">
            <label>Plano</label>
            <span class="badge badge-blue">♾️ Unlimited</span>
        </div>

        <form method="POST">
            <input type="hidden" name="token" value="<?= SETUP_TOKEN ?>">
            <button type="submit" class="btn">🚀 Criar Conta Admin Master</button>
        </form>
    <?php endif; ?>

    <div class="warning">
        ⚠️ <strong>Importante:</strong> Após criar a conta, apaga ou move este ficheiro
        <code>setup/create_admin.php</code> para fora do servidor web.
        Deixá-lo acessível é um risco de segurança.
    </div>
</div>
</body>
</html>
