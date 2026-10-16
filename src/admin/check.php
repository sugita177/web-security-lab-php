<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>/admin 配下のCookie確認</title>
    <style>
        body { font-family: sans-serif; margin: 30px; background: #fef2f2; color: #1e293b; }
        .box { background: white; border: 1px solid #f87171; border-radius: 8px; padding: 20px; }
        pre { background: #0f172a; color: #f87171; padding: 15px; border-radius: 6px; }
        a { color: #2563eb; }
    </style>
</head>
<body>
    <h1>ここは <code>/admin/check.php</code> です</h1>
    <p><a href="/phase1/1-1_cookie_basics.php">← 元のページに戻る</a></p>

    <div class="box">
        <h2>ブラウザから届いた生の `Cookie` ヘッダー</h2>
        <pre><?= htmlspecialchars($_SERVER['HTTP_COOKIE'] ?? '(Cookieなし)', ENT_QUOTES, 'UTF-8') ?></pre>

        <h2>PHPが解釈した <code>$_COOKIE</code></h2>
        <pre><?php print_r($_COOKIE); ?></pre>
    </div>
</body>
</html>
