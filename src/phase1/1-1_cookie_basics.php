<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');

$action = $_GET['action'] ?? '';
$message = '';

if ($action === 'set') {
    // =========================================================================
    // TODO 1: 通常のCookieを発行してください
    // 要件:
    //   - 名前: 'lab_user'
    //   - 値: 'alice'
    //   - 有効期限: 現在から 1時間後
    //   - Path: '/'
    // ※ setcookie() 関数、または raw header('Set-Cookie: ...') を使用
    // =========================================================================
    setcookie('lab_user', 'alice', [
        'expires' => time() + 3600,
        'path' => '/',
    ]);

    // =========================================================================
    // TODO 2: Pathを限定したCookieを発行してください
    // 要件:
    //   - 名前: 'admin_token'
    //   - 値: 'secret_admin_value_999'
    //   - 有効期限: ブラウザ終了時まで（セッションCookie）
    //   - Path: '/admin'
    // =========================================================================
    setcookie('admin_token', 'secret_admin_value_999', [
        'expires' => 0,
        'path' => '/admin',
    ]);

    $message = 'Cookieを発行しました（Set-Cookie ヘッダーを送出）。';
} elseif ($action === 'delete') {
    // =========================================================================
    // TODO 3: 'lab_user' Cookie をブラウザに削除させる命令を発行してください
    // ヒント: 有効期限をどう設定するか？
    // =========================================================================
    setcookie('lab_user', '', [
        'expires' => time() - 3600,
        'path' => '/',
    ]);

    $message = 'Cookie削除命令を発行しました。';
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 1-1: Cookieと生HTTPヘッダー観察</title>
    <style>
        body { font-family: sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }
        .box { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        pre { background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; overflow-x: auto; }
        .btn { display: inline-block; padding: 8px 16px; background: #2563eb; color: white; text-decoration: none; border-radius: 4px; margin-right: 10px; }
        .btn-del { background: #dc2626; }
    </style>
</head>
<body>
    <h1>Phase 1-1: 生HTTPヘッダーとCookie挙動の観察</h1>

    <?php if ($message): ?>
        <p style="color: green; font-weight: bold;"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></p>
    <?php endif; ?>

    <div class="box">
        <h2>アクション</h2>
        <a class="btn" href="?action=set">1. Cookieを発行する (Set-Cookie)</a>
        <a class="btn btn-del" href="?action=delete">2. Cookieを削除する</a>
        <a class="btn" href="?">3. リロード（現在のCookie確認）</a>
    </div>

    <div class="box">
        <h2>ブラウザから届いた生の `Cookie` リクエストヘッダー</h2>
        <p>PHPの <code>$_SERVER['HTTP_COOKIE']</code> の中身:</p>
        <pre><?= htmlspecialchars($_SERVER['HTTP_COOKIE'] ?? '(Cookieヘッダーは送信されていません)', ENT_QUOTES, 'UTF-8') ?></pre>
    </div>

    <div class="box">
        <h2>PHPが解釈した <code>$_COOKIE</code> スーパーグローバル配列</h2>
        <pre><?php print_r($_COOKIE); ?></pre>
    </div>
</body>
</html>
