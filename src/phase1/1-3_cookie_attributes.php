<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');

$action = $_GET['action'] ?? '';
$message = '';

if ($action === 'issue') {
    $httpOnly = isset($_POST['httponly']);
    $secure = isset($_POST['secure']);
    $sameSite = $_POST['samesite'] ?? 'Lax'; // 'Lax', 'Strict', 'None'

    // =========================================================================
    // TODO: フォームで選択された設定に応じてCookieを発行してください
    // 要件:
    //   - 名前: 'shield_token'
    //   - 値: 'secret_token_val_' . bin2hex(random_bytes(4))
    //   - 有効期限: 現在から 1時間後
    //   - Path: '/'
    //   - HttpOnly: $httpOnly（true または false）
    //   - Secure: $secure（true または false）
    //   - SameSite: $sameSite（'Lax', 'Strict', または 'None'）
    // ヒント: setcookie('名前', '値', [ オプション配列 ]) を使用
    // =========================================================================
    setcookie('shield_token', 'secret_token_val_' . bin2hex(random_bytes(4)), [
        'expires' => time() + 3600,
        'path' => '/',
        'httponly' => $httpOnly,
        'secure' => $secure,
        'samesite' => $sameSite,
    ]);

    $message = "Cookie 'shield_token' を発行しました！";
} elseif ($action === 'clear') {
    setcookie('shield_token', '', [
        'expires' => time() - 3600,
        'path' => '/',
    ]);
    header('Location: 1-3_cookie_attributes.php?cleared=1');
    exit;
}

if (isset($_GET['cleared'])) {
    $message = 'Cookieを削除しました。';
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 1-3: Cookieセキュリティ属性実験室</title>
    <style>
        body { font-family: sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }
        .box { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .alert { background: #dcfce7; color: #15803d; padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        pre { background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; overflow-x: auto; }
        .btn { padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-danger { background: #dc2626; }
        .btn-test { background: #059669; }
        label { display: block; margin-bottom: 10px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Phase 1-3: Cookie保護属性（HttpOnly, Secure, SameSite）実験室</h1>

    <?php if ($message): ?>
        <div class="alert"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <div class="box">
        <h2>1. Cookie属性を指定して発行</h2>
        <form method="POST" action="?action=issue">
            <label>
                <input type="checkbox" name="httponly" value="1" checked>
                🛡️ HttpOnly 属性を付与する（JavaScriptからのアクセス遮断）
            </label>
            <label>
                <input type="checkbox" name="secure" value="1" checked>
                🔒 Secure 属性を付与する（暗号化通信時のみ送信）
            </label>
            <label>
                🌐 SameSite 属性:
                <select name="samesite" style="padding: 4px 8px; margin-left: 8px;">
                    <option value="Lax" selected>Lax（モダンブラウザ標準）</option>
                    <option value="Strict">Strict（最も厳格）</option>
                    <option value="None">None（クロスサイト無制限 ※Secure必須）</option>
                </select>
            </label>
            <br>
            <button type="submit" class="btn">Cookieを発行する</button>
            <a href="?action=clear" class="btn btn-danger">Cookieを削除</a>
        </form>
    </div>

    <div class="box">
        <h2>2. JavaScriptからの窃取テスト（XSSシミュレーション）</h2>
        <p>JavaScriptの <code>document.cookie</code> でブラウザに保存されているCookieを読み取れるかテストします：</p>
        <button type="button" class="btn btn-test" onclick="testJsAccess()">document.cookie を読み取る</button>
        <div id="js-result" style="margin-top: 15px; font-weight: bold;"></div>
    </div>

    <div class="box">
        <h2>3. サーバー側（PHP）で受信したCookie</h2>
        <pre><?php print_r($_COOKIE); ?></pre>
    </div>

    <script>
    function testJsAccess() {
        const cookies = document.cookie;
        const resultDiv = document.getElementById('js-result');
        if (!cookies) {
            resultDiv.innerHTML = '<span style="color: #dc2626;">❌ document.cookie は空です（HttpOnlyによって隠蔽されているか、Cookieがありません）</span>';
        } else if (cookies.includes('shield_token')) {
            resultDiv.innerHTML = '<span style="color: #dc2626;">⚠️ 危険！ shield_token がJavaScriptから読み取れました！<br><code>' + cookies + '</code></span>';
        } else {
            resultDiv.innerHTML = '<span style="color: #059669;">🛡️ 安全！ shield_token は HttpOnly で保護されているため JavaScript からは見えません！<br>（他のCookie: <code>' + cookies + '</code>）</span>';
        }
    }
    </script>
</body>
</html>
