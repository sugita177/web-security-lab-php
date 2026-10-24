<?php
session_start();

// ログアウト処理
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    unset($_SESSION['logged_in_user']);
    // 現代ブラウザ向け: bfcacheを含むキャッシュを全消去
    header('Clear-Site-Data: "cache", "storage"');
    header('Location: 3-4_login.php?logged_out=1');
    exit;
}

// ログイン処理
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $_SESSION['logged_in_user'] = 'yamada_taro';
    header('Location: 3-4_mypage.php');
    exit;
}

$isLoggedOut = isset($_GET['logged_out']);
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 3-4: ログイン画面</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 25px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-info { background: #e0f2fe; color: #0369a1; }
        .alert-warning { background: #fef9c3; color: #854d0e; }
        button { cursor: pointer; padding: 10px 20px; border-radius: 4px; border: none; font-weight: bold; background: #2563eb; color: white; width: 100%; font-size: 1em; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 6px 0 16px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 4px; }
    </style>
</head>
<body>

    <div class="card">
        <h2>🔑 サービスログイン画面</h2>

        <?php if ($isLoggedOut): ?>
            <div class="alert alert-info">
                🔒 ログアウトしました（セッションは完全に破棄されました）。
            </div>
            <div class="alert alert-warning" style="font-size: 0.95em;">
                👉 <strong>ここでブラウザの「戻るボタン（←）」を押してみてください！</strong><br>
                ・防御OFFの場合: キャッシュから前のマイページ（個人情報）がそのまま復元されてしまいます。<br>
                ・防御ONの場合: キャッシュがないため再検証が走り、未ログインとしてログイン画面へ戻されます。
            </div>
        <?php endif; ?>

        <form method="POST">
            <label>ユーザー名:</label>
            <input type="text" name="username" value="yamada_taro" required>

            <label>パスワード:</label>
            <input type="password" name="password" value="dummy123" required>

            <button type="submit" name="login">ログインしてマイページを開く</button>
        </form>
    </div>

</body>
</html>
