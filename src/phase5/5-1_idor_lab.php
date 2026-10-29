<?php
declare(strict_types=1);
session_start();

// データベース接続（MySQL）
$dbHost = 'mysql';
$dbName = 'security_lab';
$dbUser = 'lab_user';
$dbPass = 'lab_password';

try {
    $pdo = new PDO(
        "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
        $dbUser,
        $dbPass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
} catch (PDOException $e) {
    die("DB接続エラー: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
}

// 演習用テーブルの自動初期化
$pdo->exec("
    CREATE TABLE IF NOT EXISTS users_5_1 (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL,
        role VARCHAR(20) NOT NULL,
        email VARCHAR(100) NOT NULL
    );
    CREATE TABLE IF NOT EXISTS orders_5_1 (
        id INT PRIMARY KEY,
        user_id INT NOT NULL,
        product_name VARCHAR(100) NOT NULL,
        price INT NOT NULL,
        secret_notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
");

// 初期シードデータ投入（未登録時のみ）
$stmt = $pdo->query("SELECT COUNT(*) FROM users_5_1");
if ((int)$stmt->fetchColumn() === 0) {
    $pdo->exec("
        INSERT INTO users_5_1 (id, username, role, email) VALUES
        (1, 'alice', 'user', 'alice@example.com'),
        (2, 'bob', 'user', 'bob@example.com'),
        (3, 'admin_user', 'admin', 'admin@example.com');

        INSERT INTO orders_5_1 (id, user_id, product_name, price, secret_notes) VALUES
        (101, 1, 'MacBook Pro 14インチ', 300000, 'Alice自宅配送: 置き配指定'),
        (102, 1, 'Webセキュリティ入門書', 3500, 'Alice通常便'),
        (103, 2, '社内健康診断・精密検査キット', 55000, '【極秘個人情報】Bobの機密医療データが含まれます。社外秘。'),
        (104, 3, '全社クラウドインフラ年間ライセンス', 12000000, '【管理者専属】ルートアカウント一式');
    ");
}

// ユーザー切り替え（ログインシミュレーション）
if (isset($_GET['switch_user'])) {
    $_SESSION['initialized'] = true;
    $userId = (int)$_GET['switch_user'];
    if ($userId === 0) {
        unset($_SESSION['user']); // ログアウト（ゲスト / 未ログイン）
    } else {
        $stmt = $pdo->prepare("SELECT * FROM users_5_1 WHERE id = :id");
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();
        if ($user) {
            $_SESSION['user'] = $user;
        }
    }
    $targetMode = $_GET['mode'] ?? 'vulnerable';
    header("Location: 5-1_idor_lab.php?mode={$targetMode}");
    exit;
}

$message = '';
$messageType = '';
$orderDetail = null;

// データ初期化アクション
if (isset($_POST['reset_database'])) {
    $pdo->exec("
        DELETE FROM orders_5_1;
        INSERT INTO orders_5_1 (id, user_id, product_name, price, secret_notes) VALUES
        (101, 1, 'MacBook Pro 14インチ', 300000, 'Alice自宅配送: 置き配指定'),
        (102, 1, 'Webセキュリティ入門書', 3500, 'Alice通常便'),
        (103, 2, '社内健康診断・精密検査キット', 55000, '【極秘個人情報】Bobの機密医療データが含まれます。社外秘。'),
        (104, 3, '全社クラウドインフラ年間ライセンス', 12000000, '【管理者専属】ルートアカウント一式');
    ");
    $message = "注文データを初期状態（101〜104）にリセットしました！";
    $messageType = "success";
}

// 初回アクセス時のみ Alice (user_id = 1) で初期ログイン
if (!isset($_SESSION['initialized'])) {
    $_SESSION['initialized'] = true;
    $stmt = $pdo->prepare("SELECT * FROM users_5_1 WHERE id = 1");
    $stmt->execute();
    $_SESSION['user'] = $stmt->fetch();
}

$currentUser = $_SESSION['user'] ?? null;

// モード管理（デフォルト: vulnerable）
$mode = $_GET['mode'] ?? 'vulnerable';
if (!in_array($mode, ['vulnerable', 'secure'], true)) {
    $mode = 'vulnerable';
}

// =============================================================================
// 【課題 1: 水平権限昇格（IDOR / BOLA）の実装】
// =============================================================================
$requestedOrderId = isset($_GET['order_id']) ? (int)$_GET['order_id'] : null;

if ($requestedOrderId !== null) {
    if ($mode === 'vulnerable') {
        // ❌ 脆弱な実装: 注文IDだけで検索し、所有者（user_id）の認可チェックを一切しない！
        $stmt = $pdo->prepare("SELECT * FROM orders_5_1 WHERE id = :order_id");
        $stmt->execute([':order_id' => $requestedOrderId]);
        $orderDetail = $stmt->fetch();

        if (!$orderDetail) {
            $message = "注文ID {$requestedOrderId} は見つかりませんでした。";
            $messageType = "danger";
        }
    } else {
        // =========================================================================
        // 【TODO 1: 安全な注文詳細取得ロジックを実装してください（パターンC推奨）】
        //
        // 【要件】
        // 1. ログイン中のユーザーID（$currentUser['id']）に所有権がある注文のみを取得してください。
        //    SQLの WHERE 句に `id = :order_id AND user_id = :user_id` を必ず含めること。
        //    ※ または、取得後に $orderDetail['user_id'] === $currentUser['id'] を検証する。
        // 2. 他人の注文IDが指定された場合、または存在しない場合は $orderDetail を null のままにし、
        //    「指定された注文は存在しないか、閲覧権限がありません。」というエラーメッセージを設定してください。
        // =========================================================================
        if ($currentUser === null) {
            $orderDetail = null;
            $message = "ログインが必要です。";
            $messageType = "danger";
        } elseif ($currentUser['role'] === 'admin') {
            $stmt = $pdo->prepare("SELECT * FROM orders_5_1 WHERE id = :order_id");
            $stmt->execute([':order_id' => $requestedOrderId]);
            $orderDetail = $stmt->fetch();
        } else {
            $stmt = $pdo->prepare("SELECT * FROM orders_5_1 WHERE id = :order_id AND user_id = :user_id");
            $stmt->execute([':order_id' => $requestedOrderId, ':user_id' => $currentUser['id']]);
            $orderDetail = $stmt->fetch();
        }

        if ($currentUser !== null && !$orderDetail) {
            $message = "注文ID {$requestedOrderId} の注文は存在しないか、閲覧権限がありません。";
            $messageType = "danger";
        }
    }
}

// =============================================================================
// 【課題 2: 垂直権限昇格（Vertical Privilege Escalation）の実装】
// =============================================================================
if (isset($_POST['admin_delete_order'])) {
    $targetDeleteId = (int)$_POST['delete_order_id'];

    if ($mode === 'vulnerable') {
        // ❌ 脆弱な実装: 認証状態の有無やロール（管理者権限: admin）の認可チェックを行わずに削除を実行してしまう！
        $stmt = $pdo->prepare("DELETE FROM orders_5_1 WHERE id = :id");
        $stmt->execute([':id' => $targetDeleteId]);
        $message = "【管理者操作】注文ID {$targetDeleteId} を削除しました。（認可チェックがないため、一般ユーザーや未認証でも実行できてしまいました！）";
        $messageType = "danger";
    } else {
        // =========================================================================
        // 【TODO 2: 安全な管理者権限（RBAC）認可チェックを実装してください】
        //
        // 【要件】
        // 1. ログイン中のユーザーが管理者（$currentUser['role'] === 'admin'）であるか厳格に検証してください。
        // 2. 管理者ではない一般ユーザーが削除を実行しようとした場合は、HTTP 403 Forbidden を設定し、
        //    削除処理は一切実行せずに「管理者権限が必要です。アクセスが拒絶されました。」と表示してください。
        // 3. 管理者の場合のみ、DELETEクエリを実行してください。
        // =========================================================================

        $isAdminRole = ($currentUser !== null && $currentUser['role'] === 'admin');
        if ($isAdminRole) {
            $stmt = $pdo->prepare("DELETE FROM orders_5_1 WHERE id = :id");
            $stmt->execute([':id' => $targetDeleteId]);
            $message = "【管理者操作】管理者として注文ID {$targetDeleteId} を正常に削除しました。";
            $messageType = "success";
        }
        
        if (!$isAdminRole) {
            http_response_code(403);
            $message = "【管理者操作】管理者権限（admin）が必要です。アクセスが拒絶されました。";
            $messageType = "danger";
        }
    }
}

// 現在の注文一覧を取得
$stmt = $pdo->prepare("SELECT * FROM orders_5_1 ORDER BY id ASC");
$stmt->execute();
$allOrders = $stmt->fetchAll();

?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 5-1: 認可制御の不備（BOLA / IDOR / 垂直昇格）演習</title>
    <style>
        body { font-family: sans-serif; max-width: 950px; margin: 30px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 22px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-vulnerable { background: #fee2e2; color: #991b1b; }
        .badge-secure { background: #dcfce7; color: #166534; }
        .badge-admin { background: #7c3aed; color: white; }
        .badge-user { background: #0284c7; color: white; }
        .alert { padding: 14px; border-radius: 6px; margin-bottom: 15px; }
        .alert-success { background: #dcfce7; border-left: 5px solid #16a34a; color: #166534; }
        .alert-danger { background: #fee2e2; border-left: 5px solid #dc2626; color: #991b1b; }
        .alert-warning { background: #fef3c7; border-left: 5px solid #d97706; color: #92400e; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.95em; }
        th, td { border: 1px solid #e2e8f0; padding: 9px 12px; text-align: left; }
        th { background: #f1f5f9; }
        .btn { display: inline-block; padding: 7px 14px; border-radius: 4px; text-decoration: none; font-weight: bold; font-size: 0.85em; cursor: pointer; border: none; }
        .btn-primary { background: #2563eb; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        .btn-secondary { background: #64748b; color: white; }
        .user-switch-bar { display: flex; gap: 10px; align-items: center; background: #e2e8f0; padding: 10px 15px; border-radius: 6px; margin-bottom: 15px; }
    </style>
</head>
<body>

    <h1>Phase 5-1: 認可制御の不備（BOLA / IDOR / 垂直昇格）演習</h1>
    <p>「認証（ログイン確認）」と「認可（権限確認）」の混同から生じる、他者データの窃取（IDOR）と権限昇格を検証します。</p>

    <!-- ログインユーザー切り替えバー -->
    <div class="user-switch-bar">
        <strong>👤 現在ログイン中:</strong>
        <?php if ($currentUser !== null): ?>
            <span style="font-size: 1.1em; font-weight: bold;">
                <?= htmlspecialchars($currentUser['username'], ENT_QUOTES, 'UTF-8') ?>
            </span>
            <span class="badge <?= $currentUser['role'] === 'admin' ? 'badge-admin' : 'badge-user' ?>">
                権限ロール: <?= htmlspecialchars($currentUser['role'], ENT_QUOTES, 'UTF-8') ?>
            </span>
            <span style="color: #64748b; font-size: 0.9em;">(User ID: <?= $currentUser['id'] ?>)</span>
        <?php else: ?>
            <span style="font-size: 1.1em; font-weight: bold; color: #dc2626;">
                ゲスト (未ログイン)
            </span>
            <span class="badge" style="background: #94a3b8; color: white;">
                未認証
            </span>
        <?php endif; ?>

        <span style="margin-left: auto;">切り替え:</span>
        <a href="?switch_user=1&mode=<?= $mode ?>" class="btn btn-secondary" style="<?= ($currentUser && $currentUser['id'] == 1) ? 'background:#0f172a;' : '' ?>">Alice (一般)</a>
        <a href="?switch_user=2&mode=<?= $mode ?>" class="btn btn-secondary" style="<?= ($currentUser && $currentUser['id'] == 2) ? 'background:#0f172a;' : '' ?>">Bob (一般)</a>
        <a href="?switch_user=3&mode=<?= $mode ?>" class="btn btn-secondary" style="<?= ($currentUser && $currentUser['id'] == 3) ? 'background:#7c3aed;' : '' ?>">Admin (管理者)</a>
        <a href="?switch_user=0&mode=<?= $mode ?>" class="btn btn-secondary" style="<?= ($currentUser === null) ? 'background:#dc2626;' : '' ?>">ログアウト (未ログイン)</a>
    </div>

    <!-- モード切り替え -->
    <div class="card">
        <h3>現在の判定モード:
            <?php if ($mode === 'vulnerable'): ?>
                <span class="badge badge-vulnerable">モード A: 脆弱 (Vulnerable - 認可チェック不備)</span>
            <?php else: ?>
                <span class="badge badge-secure">モード B: 安全 (Secure - 厳格な認可制御)</span>
            <?php endif; ?>
        </h3>
        <p>
            モード切り替え:
            <a href="?mode=vulnerable&order_id=<?= $requestedOrderId ?? '' ?>" class="btn <?= $mode === 'vulnerable' ? 'btn-danger' : 'btn-secondary' ?>">モード A (脆弱) に切替</a>
            <a href="?mode=secure&order_id=<?= $requestedOrderId ?? '' ?>" class="btn <?= $mode === 'secure' ? 'btn-primary' : 'btn-secondary' ?>">モード B (安全) に切替</a>
        </p>
    </div>

    <!-- 通知メッセージ -->
    <?php if (!empty($message)): ?>
        <div class="alert alert-<?= $messageType ?>">
            <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <!-- 攻撃・検証シミュレーター -->
    <div class="card" style="border: 2px solid #3b82f6;">
        <h3 style="color: #1d4ed8; margin-top: 0;">🎯 攻撃シミュレーター（認可不備を突く攻撃）</h3>
        <p style="background: #eff6ff; padding: 8px 12px; border-radius: 4px; color: #1e40af; font-size: 0.9em; margin-bottom: 12px;">
            ℹ️ <strong>前提条件:</strong> 以下のシミュレーターボタンは、一般ユーザー <strong>【Alice (User ID: 1)】</strong> でログインしている状態を前提とした攻撃・検証シナリオです。
        </p>

        <div style="display: flex; flex-direction: column; gap: 8px;">
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <a href="?mode=<?= $mode ?>&order_id=101" class="btn btn-primary">
                    🏢 正規アクセス: Aliceの注文 101 を閲覧 (本人のデータ)
                </a>
                <a href="?mode=<?= $mode ?>&order_id=103" class="btn btn-danger">
                    🚨 水平昇格 (IDOR): Aliceでログイン中に Bobの極秘注文 103 を閲覧
                </a>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <form method="POST" style="margin: 0; display: inline;">
                    <input type="hidden" name="delete_order_id" value="101">
                    <button type="submit" name="admin_delete_order" class="btn btn-danger" onclick="return confirm('本当に削除しますか？');">
                        🚨 垂直昇格: 一般ユーザーなのに管理者専用「注文一括削除API」を実行
                    </button>
                </form>
            </div>
        </div>
    </div>

    <!-- 領収書・注文詳細表示エリア -->
    <?php if ($requestedOrderId !== null): ?>
        <div class="card">
            <h3>📄 注文詳細・領収書 (Order ID: <?= $requestedOrderId ?>)</h3>
            <?php if ($orderDetail): ?>
                <?php
                    $isLeak = ($currentUser === null || ($orderDetail['user_id'] !== $currentUser['id'] && $currentUser['role'] !== 'admin'));
                ?>
                <?php if ($isLeak): ?>
                    <div class="alert alert-danger">
                        <h4>🚨 【IDOR脆弱性により他人のデータが漏洩！】</h4>
                        <p>あなたは <strong><?= $currentUser ? htmlspecialchars($currentUser['username'], ENT_QUOTES, 'UTF-8') : 'ゲスト(未ログイン)' ?></strong> ですが、
                        <strong>User ID: <?= $orderDetail['user_id'] ?> (Bob)</strong> の注文データが丸見えになっています！</p>
                    </div>
                <?php else: ?>
                    <div class="alert alert-success">
                        ✅ 正常な注文詳細表示（所有権または管理者権限が確認されました）
                    </div>
                <?php endif; ?>

                <table>
                    <tr><th>注文番号</th><td>#<?= $orderDetail['id'] ?></td></tr>
                    <tr><th>注文者 User ID</th><td><strong>User ID: <?= $orderDetail['user_id'] ?></strong></td></tr>
                    <tr><th>商品名</th><td><?= htmlspecialchars($orderDetail['product_name'], ENT_QUOTES, 'UTF-8') ?></td></tr>
                    <tr><th>金額</th><td>¥<?= number_format($orderDetail['price']) ?></td></tr>
                    <tr><th>社外秘メモ・備考</th><td style="color: #dc2626; font-weight: bold;"><?= htmlspecialchars($orderDetail['secret_notes'], ENT_QUOTES, 'UTF-8') ?></td></tr>
                </table>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- 全注文一覧（観察用データベース） -->
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h3 style="margin: 0;">📦 データベース内の全注文一覧 (観察用)</h3>
            <form method="POST" style="margin: 0;">
                <button type="submit" name="reset_database" class="btn btn-secondary" onclick="return confirm('注文データを初期状態にリセットしますか？');">
                    🔄 注文データを初期状態にリセット
                </button>
            </form>
        </div>
        <table>
            <thead>
                <tr>
                    <th>注文ID</th>
                    <th>所有者 (User ID)</th>
                    <th>商品名</th>
                    <th>金額</th>
                    <th>社外秘メモ</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($allOrders as $o): ?>
                    <tr style="<?= ($requestedOrderId === (int)$o['id']) ? 'background: #fef08a;' : '' ?>">
                        <td>#<?= $o['id'] ?></td>
                        <td>
                            User ID: <?= $o['user_id'] ?>
                            <?php if ($currentUser !== null && $o['user_id'] === $currentUser['id']): ?>
                                <span class="badge badge-user">あなた</span>
                            <?php endif; ?>
                        </td>
                        <td><?= htmlspecialchars($o['product_name'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td>¥<?= number_format($o['price']) ?></td>
                        <td style="font-size: 0.85em; color: #475569;"><?= htmlspecialchars($o['secret_notes'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td>
                            <a href="?mode=<?= $mode ?>&order_id=<?= $o['id'] ?>" class="btn btn-secondary" style="font-size:0.75em; padding: 4px 8px;">閲覧</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

</body>
</html>

