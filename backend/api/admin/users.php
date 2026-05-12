<?php
/**
 * Lock & Key - API Admin: Listagem e Gestão de Utilizadores
 * 
 * GET  /admin/users.php          → listar todos os utilizadores
 * GET  /admin/users.php?id=X     → detalhes de um utilizador
 * POST /admin/users.php          → criar conta admin
 * PATCH /admin/users.php         → atualizar role/plano/status
 * DELETE /admin/users.php        → suspender/banir utilizador (nunca apaga dados)
 * 
 * Acesso: admin_master (todas as ações) | admin (GET + suspender)
 */

define('LK_APP', true);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod(['GET', 'POST', 'PATCH', 'DELETE']);

// Autenticar e verificar role de admin
$user = Auth::require();

if (!in_array($user['role'], ['admin', 'admin_master'])) {
    Response::forbidden('Acesso restrito a administradores.');
}

$db     = Database::getInstance();
$method = $_SERVER['REQUEST_METHOD'];

// ============================================================
// GET — Listar utilizadores ou detalhes de um
// ============================================================
if ($method === 'GET') {
    $userId = isset($_GET['id']) ? (int)$_GET['id'] : null;
    $page   = max(1, (int)($_GET['page'] ?? 1));
    $limit  = min(100, max(10, (int)($_GET['limit'] ?? 25)));
    $offset = ($page - 1) * $limit;
    $search = sanitize($_GET['search'] ?? '');
    $role   = sanitize($_GET['role'] ?? '');
    $plan   = sanitize($_GET['plan'] ?? '');
    $status = sanitize($_GET['status'] ?? '');

    // Detalhes de um utilizador específico
    if ($userId) {
        $row = $db->fetchOne("
            SELECT
                u.id, u.uuid, u.email, u.username, u.role, u.plan,
                u.plan_expires_at, u.status, u.suspended_reason,
                u.email_verified, u.last_login, u.last_login_ip,
                u.failed_login_attempts, u.locked_until,
                u.created_at, u.updated_at,
                (SELECT COUNT(*) FROM vault_entries WHERE user_id = u.id) AS vault_count,
                (SELECT COUNT(*) FROM secure_notes  WHERE user_id = u.id) AS notes_count,
                (SELECT COUNT(*) FROM sessions WHERE user_id = u.id AND is_revoked = 0 AND expires_at > NOW()) AS active_sessions
            FROM users u
            WHERE u.id = ?
        ", [$userId]);

        if (!$row) Response::notFound('Utilizador não encontrado.');

        auditLog($user['user_id'], 'admin_view_user', null, null, ['target_user_id' => $userId]);
        Response::success(['user' => $row]);
    }

    // Listar com filtros
    $where  = ['1=1'];
    $params = [];

    if ($search) {
        $where[]  = '(u.username LIKE ? OR u.email LIKE ?)';
        $params[] = "%$search%";
        $params[] = "%$search%";
    }
    if ($role && in_array($role, ['user', 'admin', 'admin_master'])) {
        $where[]  = 'u.role = ?';
        $params[] = $role;
    }
    if ($plan && in_array($plan, ['free', 'pro', 'unlimited'])) {
        $where[]  = 'u.plan = ?';
        $params[] = $plan;
    }
    if ($status && in_array($status, ['active', 'suspended', 'banned'])) {
        $where[]  = 'u.status = ?';
        $params[] = $status;
    }

    // admins não podem ver outros admins_master (só o próprio admin_master vê tudo)
    if ($user['role'] === 'admin') {
        $where[]  = "u.role != 'admin_master'";
    }

    $whereSQL = implode(' AND ', $where);

    $total = $db->fetchOne(
        "SELECT COUNT(*) AS cnt FROM users u WHERE $whereSQL",
        $params
    )['cnt'];

    $users = $db->fetchAll("
        SELECT
            u.id, u.uuid, u.username, u.email, u.role, u.plan,
            u.status, u.email_verified, u.last_login, u.created_at,
            (SELECT COUNT(*) FROM vault_entries WHERE user_id = u.id) AS vault_count,
            (SELECT COUNT(*) FROM secure_notes  WHERE user_id = u.id) AS notes_count
        FROM users u
        WHERE $whereSQL
        ORDER BY u.created_at DESC
        LIMIT $limit OFFSET $offset
    ", $params);

    Response::success([
        'users'      => $users,
        'pagination' => [
            'total'   => (int)$total,
            'page'    => $page,
            'limit'   => $limit,
            'pages'   => (int)ceil($total / $limit),
        ],
    ]);
}

// ============================================================
// POST — Criar conta Admin (apenas admin_master pode)
// ============================================================
if ($method === 'POST') {
    if ($user['role'] !== 'admin_master') {
        Response::forbidden('Apenas o Admin Master pode criar administradores.');
    }

    $body = Response::getJsonBody();
    Response::requireFields($body, ['username', 'email', 'auth_key', 'vault_salt', 'role']);

    $newUsername = sanitize($body['username']);
    $newEmail    = sanitize($body['email']);
    $authKey     = $body['auth_key'];
    $vaultSalt   = $body['vault_salt'];
    $newRole     = $body['role'];
    $newPlan     = $body['plan'] ?? 'pro';

    if (!validateEmail($newEmail)) {
        Response::error('Email inválido.', 422);
    }
    if (!in_array($newRole, ['admin', 'admin_master'])) {
        Response::error('Role inválida. Use: admin ou admin_master.', 422);
    }
    if (!in_array($newPlan, ['free', 'pro', 'unlimited'])) {
        Response::error('Plano inválido.', 422);
    }
    if (strlen($vaultSalt) !== 64) {
        Response::error('vault_salt inválido.', 422);
    }

    // Verificar se email já existe
    $existing = $db->fetchOne('SELECT id FROM users WHERE email = ?', [$newEmail]);
    if ($existing) Response::error('Email já registado.', 409);

    $authKeyHash = Encryption::hashPassword($authKey);
    $uuid        = Encryption::generateUUID();

    $newUserId = $db->insert("
        INSERT INTO users (uuid, email, username, role, plan, auth_key_hash, vault_salt, email_verified, is_active, status)
        VALUES (:uuid, :email, :username, :role, :plan, :akHash, :salt, 1, 1, 'active')
    ", [
        ':uuid'     => $uuid,
        ':email'    => $newEmail,
        ':username' => $newUsername,
        ':role'     => $newRole,
        ':plan'     => $newPlan,
        ':akHash'   => $authKeyHash,
        ':salt'     => $vaultSalt,
    ]);

    auditLog($user['user_id'], 'admin_create_user', null, null, [
        'new_user_id' => $newUserId,
        'role'        => $newRole,
        'plan'        => $newPlan,
    ]);

    Response::success(['message' => 'Conta criada com sucesso.', 'user_id' => $newUserId], 201);
}

// ============================================================
// PATCH — Atualizar role, plano ou status
// ============================================================
if ($method === 'PATCH') {
    $body   = Response::getJsonBody();
    $target = (int)($body['user_id'] ?? 0);

    if (!$target) Response::error('user_id obrigatório.', 422);

    $targetUser = $db->fetchOne('SELECT id, role, email FROM users WHERE id = ?', [$target]);
    if (!$targetUser) Response::notFound('Utilizador não encontrado.');

    // Admins não podem modificar outros admins / admin_master
    if ($user['role'] === 'admin' && in_array($targetUser['role'], ['admin', 'admin_master'])) {
        Response::forbidden('Sem permissão para modificar outros administradores.');
    }
    // Ninguém pode rebaixar o próprio admin_master (excepto ele próprio)
    if ($targetUser['role'] === 'admin_master' && $user['user_id'] !== $target && $user['role'] !== 'admin_master') {
        Response::forbidden('Sem permissão para modificar o Admin Master.');
    }

    $updates = [];
    $params  = [];

    if (isset($body['role']) && $user['role'] === 'admin_master') {
        if (!in_array($body['role'], ['user', 'admin', 'admin_master'])) {
            Response::error('Role inválida.', 422);
        }
        $updates[] = 'role = ?';
        $params[]  = $body['role'];
    }
    if (isset($body['plan']) && $user['role'] === 'admin_master') {
        if (!in_array($body['plan'], ['free', 'pro', 'unlimited'])) {
            Response::error('Plano inválido.', 422);
        }
        $updates[] = 'plan = ?';
        $params[]  = $body['plan'];
    }
    if (isset($body['status'])) {
        if (!in_array($body['status'], ['active', 'suspended', 'banned'])) {
            Response::error('Status inválido.', 422);
        }
        $updates[] = 'status = ?';
        $params[]  = $body['status'];
        if ($body['status'] !== 'active' && isset($body['reason'])) {
            $updates[] = 'suspended_reason = ?';
            $params[]  = sanitize($body['reason']);
        }
        if ($body['status'] === 'active') {
            $updates[] = 'suspended_reason = NULL';
        }
    }

    if (empty($updates)) Response::error('Nenhum campo para atualizar.', 422);

    $params[] = $target;
    $db->execute('UPDATE users SET ' . implode(', ', $updates) . ' WHERE id = ?', $params);

    // Revogar todas as sessões se suspenso/banido
    if (isset($body['status']) && $body['status'] !== 'active') {
        $db->execute('UPDATE sessions SET is_revoked = 1 WHERE user_id = ?', [$target]);
    }

    auditLog($user['user_id'], 'admin_update_user', null, null, array_merge(['target_user_id' => $target], $body));

    Response::success(['message' => 'Utilizador atualizado com sucesso.']);
}

// ============================================================
// DELETE — Suspender utilizador (não elimina dados permanentemente)
// ============================================================
if ($method === 'DELETE') {
    $body   = Response::getJsonBody();
    $target = (int)($body['user_id'] ?? 0);

    if (!$target) Response::error('user_id obrigatório.', 422);

    $targetUser = $db->fetchOne('SELECT id, role FROM users WHERE id = ?', [$target]);
    if (!$targetUser) Response::notFound('Utilizador não encontrado.');

    if ($targetUser['role'] === 'admin_master') {
        Response::forbidden('Não é possível remover o Admin Master.');
    }
    if ($user['role'] === 'admin' && $targetUser['role'] === 'admin') {
        Response::forbidden('Admins não podem remover outros admins.');
    }

    $permanent = ($body['permanent'] ?? false) === true && $user['role'] === 'admin_master';

    if ($permanent) {
        $db->execute('DELETE FROM users WHERE id = ?', [$target]);
        $action = 'Utilizador eliminado permanentemente.';
    } else {
        $db->execute("UPDATE users SET status = 'banned', suspended_reason = ? WHERE id = ?", [
            sanitize($body['reason'] ?? 'Conta suspensa por administrador.'),
            $target,
        ]);
        $db->execute('UPDATE sessions SET is_revoked = 1 WHERE user_id = ?', [$target]);
        $action = 'Utilizador suspenso com sucesso.';
    }

    auditLog($user['user_id'], 'admin_delete_user', null, null, [
        'target_user_id' => $target,
        'permanent'      => $permanent,
    ]);

    Response::success(['message' => $action]);
}

