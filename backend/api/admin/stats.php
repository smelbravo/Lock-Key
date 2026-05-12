<?php
/**
 * Lock & Key - API Admin: Estatísticas do Sistema
 * 
 * GET /admin/stats.php → métricas globais para o painel admin
 * 
 * Acesso: admin | admin_master
 */

define('LK_APP', true);
require_once dirname(__DIR__, 3) . '/bootstrap.php';

Response::requireMethod(['GET']);
$user = Auth::require();

if (!in_array($user['role'], ['admin', 'admin_master'])) {
    Response::forbidden('Acesso restrito a administradores.');
}

$db = Database::getInstance();

// Contagens gerais
$totals = $db->fetchOne("
    SELECT
        (SELECT COUNT(*) FROM users WHERE role = 'user')         AS total_users,
        (SELECT COUNT(*) FROM users WHERE role = 'admin')        AS total_admins,
        (SELECT COUNT(*) FROM users WHERE role = 'admin_master') AS total_masters,
        (SELECT COUNT(*) FROM users WHERE status = 'active')     AS active_users,
        (SELECT COUNT(*) FROM users WHERE status = 'suspended' OR status = 'banned') AS suspended_users,
        (SELECT COUNT(*) FROM users WHERE plan = 'free')         AS plan_free,
        (SELECT COUNT(*) FROM users WHERE plan = 'pro')          AS plan_pro,
        (SELECT COUNT(*) FROM users WHERE plan = 'unlimited')    AS plan_unlimited,
        (SELECT COUNT(*) FROM vault_entries)                     AS total_vault_entries,
        (SELECT COUNT(*) FROM secure_notes)                      AS total_notes,
        (SELECT COUNT(*) FROM sessions WHERE is_revoked = 0 AND expires_at > NOW()) AS active_sessions
");

// Novos registos nos últimos 30 dias (por dia)
$registrations = $db->fetchAll("
    SELECT DATE(created_at) AS day, COUNT(*) AS count
    FROM users
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    GROUP BY DATE(created_at)
    ORDER BY day ASC
");

// Últimos 10 logins
$recentLogins = $db->fetchAll("
    SELECT username, email, last_login, last_login_ip, role, plan, status
    FROM users
    WHERE last_login IS NOT NULL
    ORDER BY last_login DESC
    LIMIT 10
");

// Últimas entradas do audit log
$auditEntries = $db->fetchAll("
    SELECT a.action, a.ip_address, a.created_at, a.details,
           u.username, u.email
    FROM audit_log a
    LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC
    LIMIT 20
");

// Top 5 utilizadores com mais entradas
$topUsers = $db->fetchAll("
    SELECT u.username, u.email, u.plan, u.role,
           COUNT(v.id) AS vault_count
    FROM users u
    LEFT JOIN vault_entries v ON v.user_id = u.id
    GROUP BY u.id
    ORDER BY vault_count DESC
    LIMIT 5
");

Response::success([
    'totals'        => $totals,
    'registrations' => $registrations,
    'recent_logins' => $recentLogins,
    'audit_log'     => $auditEntries,
    'top_users'     => $topUsers,
]);
