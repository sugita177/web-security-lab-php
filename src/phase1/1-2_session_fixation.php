<?php
declare(strict_types=1);

// セッションの開始
session_start();

$message = '';
$action = $_GET['action'] ?? '';

// ログイン処理
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $secureMode = isset($_POST['secure_mode']); // セキュアモード（チェックボックス）

    // 簡易認証（学習用: パスワードは何でもOK）
    if ($username !== '') {
        if ($secureMode) {
            // =========================================================================
            // TODO 1: 【セキュアモード】セッション固定化を防ぐ処理を実装してください
            // 要件:
            //   - セッションIDを新しく再生成し、かつ古いセッションデータを完全に削除すること
            // =========================================================================
            
            session_regenerate_id(true);
            $message = '【安全にログイン】セッションIDを再生成しました！';
        } else {
            // =========================================================================
            // TODO 2: 【脆弱モード】
            // セッションIDの再生成を行わずにログイン状態を記録してください
            // （＝セッション固定化脆弱性がある状態）
            // =========================================================================
            
            $message = '【脆弱なログイン】セッションIDを変更せずにログインしました（固定化攻撃の危険あり）。';
        }

        // ログイン成功情報をセッションに保存
        $_SESSION['authenticated_user'] = $username;
        $_SESSION['login_time'] = date('Y-m-d H:i:s');
    }
}

// ログアウト処理
if ($action === 'logout') {
    // =========================================================================
    // TODO 3: 安全なログアウト処理を実装してください
    // 要件:
    //   1. $_SESSION の全データをクリアする
    //   2. サーバー側のセッションファイルを破棄する（session_destroy）
    //   3. （可能なら）ブラウザのセッションCookieも過去期限にして無効化する
    // =========================================================================
    
    // 1. セッション変数の全クリア
    $_SESSION = [];
    // 2. サーバー側セッションファイルの破棄
    session_destroy();
    // 3. ブラウザのCookie破棄
    setcookie("PHPSESSID", "", [
        'expires' => time() - 3600,
        'path' => '/',
    ]);
    // リダイレクトしてURLから ?action=logout を除去（PRGパターン）
    header('Location: 1-2_session_fixation.php?logged_out=1');
    exit;
}

if (isset($_GET['logged_out'])) {
    $message = 'ログアウトしました。';
}


$currentSessionId = session_id();
$currentUser = $_SESSION['authenticated_user'] ?? null;
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 1-2: セッション固定化攻撃（Session Fixation）実験室</title>
    <style>
        body { font-family: sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }
        .box { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-info { background: #e0f2fe; color: #0369a1; }
        .alert-success { background: #dcfce7; color: #15803d; }
        .id-badge { font-family: monospace; font-size: 1.1em; background: #0f172a; color: #38bdf8; padding: 4px 8px; border-radius: 4px; }
        .btn { padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn-danger { background: #dc2626; }
        input[type="text"] { padding: 6px; border: 1px solid #cbd5e1; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>Phase 1-2: セッション固定化攻撃（Session Fixation）実験室</h1>

    <?php if ($message): ?>
        <div class="alert alert-info"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <div class="box">
        <h2>現在のセッション状態</h2>
        <p>あなたのセッションID (PHPSESSID): <span class="id-badge"><?= htmlspecialchars($currentSessionId, ENT_QUOTES, 'UTF-8') ?></span></p>
        <p>ログイン状態: 
            <?php if ($currentUser): ?>
                <strong style="color: #15803d;">ログイン中（ユーザー名: <?= htmlspecialchars($currentUser, ENT_QUOTES, 'UTF-8') ?>）</strong>
                [ログイン日時: <?= htmlspecialchars($_SESSION['login_time'] ?? '', ENT_QUOTES, 'UTF-8') ?>]
                <br><br>
                <a href="?action=logout" style="color: #dc2626; font-weight: bold;">ログアウトする</a>
            <?php else: ?>
                <span style="color: #64748b;">未ログイン（ゲスト状態）</span>
            <?php endif; ?>
        </p>
    </div>

    <?php if (!$currentUser): ?>
        <div class="box">
            <h2>ログインフォーム</h2>
            <form method="POST" action="?action=login">
                <p>
                    <label>ユーザー名: <input type="text" name="username" value="alice" required></label>
                </p>
                <p>
                    <label>パスワード: <input type="text" name="password" value="password123"></label>
                </p>
                <p>
                    <label style="color: #2563eb; font-weight: bold;">
                        <input type="checkbox" name="secure_mode" value="1">
                        【防御策】session_regenerate_id(true) を実行する（セキュアモード）
                    </label>
                </p>
                <button type="submit" class="btn">ログイン</button>
            </form>
            <p style="font-size: 0.9em; color: #64748b;">※ チェックを外してログインすると、現在のセッションIDを引き継いだままログインします（脆弱モード）。</p>
        </div>
    <?php endif; ?>
</body>
</html>
