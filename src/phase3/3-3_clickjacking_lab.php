<?php
session_start();

// 防御モード（デフォルトOFFで脆弱性をまず確認）
if (!isset($_SESSION['defense_mode_clickjacking'])) {
    $_SESSION['defense_mode_clickjacking'] = false;
}
if (!isset($_SESSION['defense_mode_redirect'])) {
    $_SESSION['defense_mode_redirect'] = false;
}

// モード切替ハンドラ
if (isset($_POST['toggle_cj'])) {
    $_SESSION['defense_mode_clickjacking'] = !$_SESSION['defense_mode_clickjacking'];
    header('Location: 3-3_clickjacking_lab.php');
    exit;
}
if (isset($_POST['toggle_rd'])) {
    $_SESSION['defense_mode_redirect'] = !$_SESSION['defense_mode_redirect'];
    header('Location: 3-3_clickjacking_lab.php');
    exit;
}

$cjDefense = $_SESSION['defense_mode_clickjacking'];
$rdDefense = $_SESSION['defense_mode_redirect'];

// =========================================================================
// 【演習 1: クリックジャッキング防御ヘッダー】
// =========================================================================
if ($cjDefense) {
    // =========================================================================
    // 【TODO 1: クリックジャッキング防御ヘッダーの送出】
    // 他サイト (例: ポート 8081 の攻撃者サイト) の <iframe> 内に
    // 本ページが埋め込まれるのを防ぐヘッダーを出力してください。
    //
    // ヒント:
    // 1. レガシーヘッダー: X-Frame-Options (DENY または SAMEORIGIN)
    // 2. 現代標準ヘッダー: Content-Security-Policy の frame-ancestors ('self' または 'none')
    // =========================================================================
    // header('X-Frame-Options: ...');
    // header("Content-Security-Policy: frame-ancestors ...;");
    header("Content-Security-Policy: frame-ancestors 'none';");
}

// 所持ポイント管理（クリックジャッキング被害の可視化用）
if (!isset($_SESSION['user_points'])) {
    $_SESSION['user_points'] = 10000;
}

$message = '';
$messageType = '';

// 送金・寄付処理（クリックジャッキングで不正実行させられる重要アクション）
if (isset($_POST['donate_points'])) {
    if ($_SESSION['user_points'] >= 10000) {
        $_SESSION['user_points'] -= 10000;
        $message = "全ポイント（10,000pt）の寄付が完了しました！現在の残高: " . number_format($_SESSION['user_points']) . "pt";
        $messageType = "danger";
    } else {
        $message = "ポイント残高が不足しています。";
        $messageType = "warning";
    }
}
if (isset($_POST['reset_points'])) {
    $_SESSION['user_points'] = 10000;
    header('Location: 3-3_clickjacking_lab.php');
    exit;
}

// =========================================================================
// 【演習 2: オープンリダイレクト】
// =========================================================================
$redirectError = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $returnTo = trim($_POST['return_to'] ?? '');

    if ($rdDefense) {
        // =========================================================================
        // 【TODO 2: 安全なリダイレクト先URLの検証】
        // 攻撃者が渡した外部URL (例: https://evil.com や //evil.com) を拒絶し、
        // 自サイト内の安全な相対パス (例: /phase3/mypage.php) のみに限定してください。
        //
        // ヒント:
        // - '/' から始まっているか？ (str_starts_with)
        // - '//' から始まっていないか？ (!str_starts_with) ※プロトコル相対URLのバイパス防止
        // =========================================================================
        // TODO: ここを安全な判定ロジックに修正してください
        $isValidUrl = str_starts_with($returnTo, "/") && !str_starts_with($returnTo, "//");

        if ($isValidUrl) {
            header("Location: " . $returnTo);
            exit;
        } else {
            $redirectError = "不正なリダイレクト先URLが検出されたため、外部への転送をブロックしました: " . htmlspecialchars($returnTo, ENT_QUOTES, 'UTF-8');
        }
    } else {
        // 防御OFF: 何も検証せずに受け取ったURLへ即座にリダイレクト（脆弱！）
        if (!empty($returnTo)) {
            header("Location: " . $returnTo);
            exit;
        }
    }
}

// 罠サイト埋め込み時用の簡易表示モード
$isEmbed = isset($_GET['embed']);
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 3-3: クリックジャッキング & オープンリダイレクト演習</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 20px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-success { background: #dcfce7; color: #166534; }
        .alert-warning { background: #fef9c3; color: #854d0e; }
        .alert-danger { background: #fee2e2; color: #991b1b; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-on { background: #22c55e; color: white; }
        .badge-off { background: #ef4444; color: white; }
        button { cursor: pointer; padding: 8px 16px; border-radius: 4px; border: none; font-weight: bold; }
        .btn-primary { background: #2563eb; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        .btn-secondary { background: #64748b; color: white; }
        input[type="text"] { width: 100%; padding: 8px; margin: 6px 0 14px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 4px; }
        code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; }
        
        /* 罠と位置をピッタリ一致させるためのターゲットボタン配置 */
        .victim-action-area {
            margin-top: 50px;
            text-align: center;
        }
        .btn-victim {
            width: 300px;
            padding: 18px;
            font-size: 1.3em;
            background: #dc2626;
            color: white;
            border-radius: 50px;
        }
    </style>
</head>
<body style="<?= $isEmbed ? 'background: white; margin: 0; padding: 10px;' : '' ?>">

    <?php if (!$isEmbed): ?>
        <h1>Phase 3-3: クリックジャッキング & オープンリダイレクト演習</h1>

        <!-- コントロールパネル -->
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div>
                    <strong>① クリックジャッキング防御 (X-Frame-Options / CSP):</strong>
                    <?php if ($cjDefense): ?>
                        <span class="badge badge-on">ON (iframe拒否ヘッダー出力中)</span>
                    <?php else: ?>
                        <span class="badge badge-off">OFF (脆弱: ヘッダー未設定)</span>
                    <?php endif; ?>
                </div>
                <form method="POST" style="margin: 0;">
                    <button type="submit" name="toggle_cj" class="btn-secondary">
                        CJ防御切替 (現在: <?= $cjDefense ? 'ON' : 'OFF' ?>)
                    </button>
                </form>
            </div>

            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong>② オープンリダイレクト防御 (URL検証):</strong>
                    <?php if ($rdDefense): ?>
                        <span class="badge badge-on">ON (相対パス検証有効)</span>
                    <?php else: ?>
                        <span class="badge badge-off">OFF (脆弱: 無検証転送)</span>
                    <?php endif; ?>
                </div>
                <form method="POST" style="margin: 0;">
                    <button type="submit" name="toggle_rd" class="btn-secondary">
                        リダイレクト防御切替 (現在: <?= $rdDefense ? 'ON' : 'OFF' ?>)
                    </button>
                </form>
            </div>
        </div>
    <?php endif; ?>

    <!-- メッセージ表示 -->
    <?php if ($message): ?>
        <div class="alert alert-<?= $messageType ?>">
            <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <!-- ========================================================================= -->
    <!-- 演習 1: クリックジャッキング標的画面 -->
    <!-- ========================================================================= -->
    <div class="card">
        <h2>演習 1: 標的サービス（会員マイページ）</h2>
        <p>現在の所持ポイント: <strong style="font-size: 1.3em; color: #2563eb;"><?= number_format($_SESSION['user_points']) ?> pt</strong></p>

        <!-- 攻撃者がクリックさせたいボタン（罠ページの偽ボタンと座標が一致） -->
        <div class="victim-action-area">
            <form method="POST">
                <button type="submit" name="donate_points" class="btn-victim">
                    💸 全10,000ptを寄付する
                </button>
            </form>
            <p style="color: #64748b; font-size: 0.9em; margin-top: 10px;">
                ※ 本来ユーザーが意図して押すはずのない重要ボタンです
            </p>
        </div>

        <?php if (!$isEmbed): ?>
            <div style="margin-top: 20px; border-top: 1px solid #e2e8f0; padding-top: 15px; display: flex; justify-content: space-between; align-items: center;">
                <form method="POST" style="margin: 0;">
                    <button type="submit" name="reset_points" class="btn-secondary">ポイントを10,000ptに戻す</button>
                </form>
                <div>
                    🔗 <a href="http://localhost:8081/clickjacking_trap.html" target="_blank" style="color: #db2777; font-weight: bold;">
                        別オリジンの攻撃者罠サイトを開く（ポート 8081）➔
                    </a>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- ========================================================================= -->
    <!-- 演習 2: オープンリダイレクト標的画面 -->
    <!-- ========================================================================= -->
    <?php if (!$isEmbed): ?>
        <div class="card">
            <h2>演習 2: ログイン後リダイレクト（オープンリダイレクト）</h2>

            <?php if ($redirectError): ?>
                <div class="alert alert-danger">
                    <?= htmlspecialchars($redirectError, ENT_QUOTES, 'UTF-8') ?>
                </div>
            <?php endif; ?>

            <p>ログイン成功後に、パラメータで指定されたページ（<code>return_to</code>）へ転送します。</p>

            <form method="POST">
                <label>リダイレクト先URL (<code>return_to</code>):</label>
                <input type="text" name="return_to" value="<?= htmlspecialchars($_GET['return_to'] ?? '/phase3/3-3_clickjacking_lab.php?logged_in=1', ENT_QUOTES, 'UTF-8') ?>">

                <button type="submit" name="login" class="btn-primary">ログインしてリダイレクト</button>
            </form>

            <div style="margin-top: 15px; font-size: 0.9em; color: #64748b;">
                <strong>攻撃リンクのテスト例:</strong>
                <ul>
                    <li><a href="?return_to=https://google.com">外部ドメイン転送 (https://google.com)</a></li>
                    <li><a href="?return_to=//google.com">プロトコル相対URL転送 (//google.com)</a></li>
                    <li><a href="?return_to=/phase3/3-3_clickjacking_lab.php?success=1">安全な自サイト内相対パス</a></li>
                </ul>
            </div>
        </div>
    <?php endif; ?>

</body>
</html>
