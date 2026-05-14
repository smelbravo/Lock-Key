<?php
/**
 * Lock & Key - API Admin: Audit Log
 *
 * GET /admin/audit.php → listagem paginada do log de auditoria
 *
 * Acesso: admin | admin_master
 */

declare(strict_types=1);
require_once dirname(__DIR__, 2) . '/bootstrap.php';

Response::requireMethod('GET');

$user = AuthMiddleware::require();

if (!in_array($user['role'], ['admin', 'admin_master'], true)) {
    Response::forbidden('Acesso restrito a administradores.');
}

$page   = max(1, (int) ($_GET['page'] ?? 1));
$limit  = min(100, max(10, (int) ($_GET['limit'] ?? 50)));
$offset = ($page - 1) * $limit;

$action = sanitize($_GET['action'] ?? '');
$search = sanitize($_GET['search'] ?? '');

$where  = ['1=1'];
$params = [];

if ($action !== '') {
    $where[]  = 'a.action = ?';
    $params[] = $action;
}
if ($search !== '') {
    $where[]  = '(u.username LIKE ? OR u.email LIKE ? OR a.ip_address LIKE ?)';
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
}

// Admins apenas veem logs de utilizadores normais (ou ações sem utilizador associado)
if ($user['role'] === 'admin') {
    $where[] = "(u.role = 'user' OR u.id IS NULL)";
}

$whereSQL = implode(' AND ', $where);

$totalRow = Database::fetchOne(
    "SELECT COUNT(*) AS cnt FROM audit_log a LEFT JOIN users u ON a.user_id = u.id WHERE {$whereSQL}",
    $params
);
$total = (int) ($totalRow['cnt'] ?? 0);

$logs = Database::fetchAll("
    SELECT a.id, a.action, a.ip_address, a.user_agent, a.details, a.created_at,
           u.username, u.email, u.role AS user_role
    FROM audit_log a
    LEFT JOIN users u ON a.user_id = u.id
    WHERE {$whereSQL}
    ORDER BY a.created_at DESC
    LIMIT {$limit} OFFSET {$offset}
", $params);

// Tipos de ações disponíveis para filtro
$actions = Database::fetchAll(
    "SELECT DISTINCT action FROM audit_log ORDER BY action ASC"
);

Response::success([
    'logs'       => $logs,
    'actions'    => array_column($actions, 'action'),
    'pagination' => [
        'total' => $total,
        'page'  => $page,
        'limit' => $limit,
        'pages' => $limit > 0 ? (int) ceil($total / $limit) : 0,
    ],
]);
