<?php
session_start();

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['SERVER_PORT'] == 8443);
$currentPort = $_SERVER['SERVER_PORT'] ?? '80';
$protocol = $isHttps ? 'HTTPS' : 'HTTP';

// HSTSヘッダー設定のモード管理（デフォルトOFF）
$hstsFile = __DIR__ . '/hsts_config.json';
function getHstsMode(string $file): bool {
    if (!file_exists($file)) return false;
    $cfg = json_decode(file_get_contents($file), true);
    return (bool)($cfg['hsts_enabled'] ?? false);
}
if (isset($_POST['toggle_hsts'])) {
    $current = getHstsMode($hstsFile);
    file_put_contents($hstsFile, json_encode(['hsts_enabled' => !$current]));
    $host = $_SERVER['HTTP_HOST'] ?? ($isHttps ? 'localhost:8443' : 'localhost:8080');
    $scheme = $isHttps ? 'https' : 'http';
    header("Location: {$scheme}://{$host}/phase4/4-2_https_lab.php");
    exit;
}
$hstsEnabled = getHstsMode($hstsFile);

// =========================================================================
// 【演習 1: HSTS (Strict-Transport-Security) ヘッダーの送出】
// =========================================================================
if ($isHttps && $hstsEnabled) {
    // =========================================================================
    // 【TODO 1: HSTS ヘッダーを出力してください】
    // ブラウザに対し、今後このドメインへは平文HTTPでのアクセスを禁止し、
    // 強制的に HTTPS で接続するよう指示するレスポンスヘッダーを出力してください。
    //
    // ヒント:
    // ヘッダー名: Strict-Transport-Security
    // ディレクティブ: max-age=31536000 (1年間)
    // =========================================================================
    // header('Strict-Transport-Security: max-age=...');
    header('Strict-Transport-Security: max-age=31536000;');
}

$message = '';
$messageType = '';

// Cookie発行アクション
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['issue_cookies'])) {
    $dummyToken = bin2hex(random_bytes(16));

    // ① 脆弱なCookie（Secure属性なし）
    setcookie('session_insecure', 'INSECURE_' . $dummyToken, [
        'expires' => time() + 3600,
        'path' => '/',
        'secure' => false,      // ★ Secure属性なし（危険！）
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    // ② 安全なCookie（Secure属性あり）
    setcookie('session_secure', 'SECURE_' . $dummyToken, [
        'expires' => time() + 3600,
        'path' => '/',
        'secure' => true,       // ★ Secure属性あり
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    $message = "2種類のCookie（session_insecure と session_secure）を発行しました！";
    $messageType = "success";
    $host = $_SERVER['HTTP_HOST'] ?? ($isHttps ? 'localhost:8443' : 'localhost:8080');
    $scheme = $isHttps ? 'https' : 'http';
    header("Location: {$scheme}://{$host}/phase4/4-2_https_lab.php?issued=1");
    exit;
}

// Cookie全消去アクション
if (isset($_POST['clear_cookies'])) {
    // 発行時と同じ属性で期限切れにして消去する
    setcookie('session_insecure', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    setcookie('session_secure', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    $host = $_SERVER['HTTP_HOST'] ?? ($isHttps ? 'localhost:8443' : 'localhost:8080');
    $scheme = $isHttps ? 'https' : 'http';
    header("Location: {$scheme}://{$host}/phase4/4-2_https_lab.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 4-2: HTTPS、Secure属性、HSTS演習</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 30px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-success { background: #dcfce7; color: #166534; }
        .alert-warning { background: #fef9c3; color: #854d0e; }
        .alert-danger { background: #fee2e2; color: #991b1b; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-https { background: #10b981; color: white; }
        .badge-http { background: #ef4444; color: white; }
        button { cursor: pointer; padding: 10px 18px; border-radius: 4px; border: none; font-weight: bold; }
        .btn-primary { background: #2563eb; color: white; }
        .btn-secondary { background: #64748b; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }
        th { background: #f1f5f9; }
        code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; }
        pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>

    <!-- 通信状態ヘッダー -->
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h2>Phase 4-2: HTTPS & Cookie保護演習</h2>
            <?php if ($isHttps): ?>
                <span class="badge badge-https">🔒 現在の接続: HTTPS (暗号化通信 :8443)</span>
            <?php else: ?>
                <span class="badge badge-http">⚠️ 現在の接続: 平文 HTTP (盗聴可能 :8080)</span>
            <?php endif; ?>
        </div>
        <p>現在のプロトコル: <strong><?= $protocol ?></strong> (ポート: <?= htmlspecialchars($currentPort, ENT_QUOTES, 'UTF-8') ?>)</p>

        <div style="display: flex; gap: 10px; margin-top: 15px; flex-wrap: wrap;">
            <a href="https://127.0.0.1:8443/phase4/4-2_https_lab.php" style="text-decoration: none; padding: 8px 14px; background: #dcfce7; color: #166534; border-radius: 4px; font-weight: bold; font-size: 0.9em;">
                🔒 暗号化 HTTPS (127.0.0.1:8443) へ切り替え
            </a>
            <a href="http://127.0.0.1:8080/phase4/4-2_https_lab.php" style="text-decoration: none; padding: 8px 14px; background: #fee2e2; color: #991b1b; border-radius: 4px; font-weight: bold; font-size: 0.9em;">
                🔓 平文 HTTP (127.0.0.1:8080) へ切り替え ★特例解除で検証
            </a>
        </div>
        <small style="color: #64748b; display: block; margin-top: 8px;">
            ※ Chromeは <code>localhost</code> というドメインを「安全な環境」と特別扱いするため、<strong><code>127.0.0.1</code> を使うことで特例を解除し、ブラウザによる平文ブロック動作を厳格に検証できます。</strong>
        </small>
    </div>

    <!-- HSTS設定カード -->
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <strong>HSTS (Strict-Transport-Security):</strong>
                <?php if ($hstsEnabled): ?>
                    <span class="badge badge-https">ON (強制HTTPS指示ヘッダー出力中)</span>
                <?php else: ?>
                    <span class="badge badge-http">OFF (未設定)</span>
                <?php endif; ?>
            </div>
            <form method="POST" style="margin: 0;">
                <button type="submit" name="toggle_hsts" class="btn-secondary">
                    HSTS切替 (現在: <?= $hstsEnabled ? 'ON' : 'OFF' ?>)
                </button>
            </form>
        </div>
    </div>

    <!-- Cookie操作と現在の受信状況 -->
    <div class="card">
        <h3>🍪 Cookieの受信状況（サーバーが受け取ったCookie一覧）</h3>
        <p>ブラウザがこのサーバーに送信してきた Cookie です：</p>

        <table>
            <thead>
                <tr>
                    <th>Cookie名</th>
                    <th>サーバーが受信した値</th>
                    <th>Secure属性</th>
                    <th>ブラウザ送信 & サーバー受信ステータス</th>
                </tr>
            </thead>
            <tbody>
                <?php
                    $insecureReceived = isset($_COOKIE['session_insecure']);
                    $secureReceived = isset($_COOKIE['session_secure']);
                ?>
                <tr>
                    <td><code>session_insecure</code></td>
                    <td><?= $insecureReceived ? htmlspecialchars($_COOKIE['session_insecure'], ENT_QUOTES, 'UTF-8') : '<em style="color:#94a3b8;">(未送信)</em>' ?></td>
                    <td><span style="color: #dc2626; font-weight: bold;">なし (false)</span></td>
                    <td>
                        <?php if ($insecureReceived): ?>
                            <?php if (!$isHttps): ?>
                                <span style="color: #dc2626; font-weight: bold;">🚨 【ブラウザが送信 ➔ サーバーが平文受信】 盗聴リスクあり！</span>
                            <?php else: ?>
                                <span style="color: #10b981; font-weight: bold;">🛡️ 【ブラウザが送信 ➔ サーバーが暗号化受信】 暗号化通信中</span>
                            <?php endif; ?>
                        <?php else: ?>
                            <span style="color: #94a3b8;">⚪ 【ブラウザ未送信 / サーバー未受信】</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><code>session_secure</code></td>
                    <td><?= $secureReceived ? htmlspecialchars($_COOKIE['session_secure'], ENT_QUOTES, 'UTF-8') : '<em style="color:#94a3b8;">(未送信)</em>' ?></td>
                    <td><span style="color: #10b981; font-weight: bold;">あり (true)</span></td>
                    <td>
                        <?php if ($secureReceived): ?>
                            <?php if ($isHttps): ?>
                                <span style="color: #10b981; font-weight: bold;">🛡️ 【ブラウザが送信 ➔ サーバーが暗号化受信】 Secure属性で保護</span>
                            <?php else: ?>
                                <span style="color: #dc2626; font-weight: bold;">🚨 【ブラウザが送信 ➔ サーバーが平文受信】 ※localhost特例で漏洩</span>
                            <?php endif; ?>
                        <?php else: ?>
                            <?php if ($insecureReceived && !$isHttps): ?>
                                <span style="color: #10b981; font-weight: bold;">🛡️ 【ブラウザが送信を拒絶 ➔ サーバー未到達】 平文漏洩を完全防御！</span>
                            <?php else: ?>
                                <span style="color: #94a3b8;">⚪ 【ブラウザ未送信 / サーバー未受信】</span>
                            <?php endif; ?>
                        <?php endif; ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <div style="margin-top: 20px; display: flex; gap: 10px;">
            <form method="POST" style="margin: 0;">
                <button type="submit" name="issue_cookies" class="btn-primary">
                    Cookieを新規発行する
                </button>
            </form>
            <form method="POST" style="margin: 0;">
                <button type="submit" name="clear_cookies" class="btn-danger">
                    Cookieを消去する
                </button>
            </form>
        </div>
    </div>

    <!-- 生ヘッダー確認用ガイド -->
    <div class="card">
        <h3>ターミナルからの生HTTPレスポンスヘッダー確認</h3>
        <p><strong>① 平文HTTP (8080) のヘッダー:</strong></p>
        <pre>curl -I http://localhost:8080/phase4/4-2_https_lab.php</pre>

        <p><strong>② 暗号化HTTPS (8443) のヘッダー (HSTS確認):</strong></p>
        <pre>curl -k -I https://localhost:8443/phase4/4-2_https_lab.php</pre>
    </div>

</body>
</html>
