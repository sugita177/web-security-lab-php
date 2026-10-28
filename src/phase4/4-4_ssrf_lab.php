<?php
session_start();

// モード管理（デフォルト: vulnerable）
$mode = $_GET['mode'] ?? 'vulnerable';
if (!in_array($mode, ['vulnerable', 'secure'], true)) {
    $mode = 'vulnerable';
}

$url = $_GET['url'] ?? '';
$fetchResult = null;
$fetchError = null;
$resolvedIp = null;

/**
 * 脆弱なURLフェッチ処理（モード A）
 * - スキームの検証なし (file:// などを許可してしまう)
 * - ホスト名/IPアドレスの検証なし (内部ネットワーク 127.0.0.1, 10.x, 172.x などを許可してしまう)
 * - リダイレクト無制限追従
 */
function fetchUrlVulnerable(string $url): array {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true, // ★ リダイレクトを無条件に追従（危険！）
        CURLOPT_TIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
    ]);

    $content = curl_exec($ch);
    $error = curl_error($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $primaryIp = curl_getinfo($ch, CURLINFO_PRIMARY_IP);

    if ($content === false) {
        return ['success' => false, 'error' => $error ?: '接続に失敗しました', 'ip' => $primaryIp];
    }
    return [
        'success' => true,
        'content' => $content,
        'http_code' => $httpCode,
        'effective_url' => $effectiveUrl,
        'ip' => $primaryIp
    ];
}

/**
 * 【TODO 1: 安全なURLフェッチ処理を実装してください（モード B）】
 *
 * 【要件】
 * 1. スキーム（プロトコル）の検証:
 *    - parse_url() を使ってスキームを取得し、「http」または「https」のみを許可してください。
 *    - file:// や gopher:// などの危険なスキームは例外（InvalidArgumentException）を投げてください。
 *
 * 2. ホスト名の取得とDNS名前解決:
 *    - parse_url() でホスト名を取得し、gethostbyname() でIPアドレスに変換してください。
 *
 * 3. プライベートIP / 予約済みIPの排除:
 *    - filter_var() と以下のフラグを使って、社内LAN（10.x, 172.x, 192.168.x）や
 *      ループバック（127.0.0.1）、クラウドメタデータ（169.254.169.254）を完全に遮断してください。
 *      FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
 *
 * 4. 安全なcURLリクエスト送信:
 *    - リダイレクト自動追従（CURLOPT_FOLLOWLOCATION）を false に設定してください。
 *      （リダイレクトによる内部ネットワーク誘導を防止）
 *
 * @throws InvalidArgumentException セキュリティ検証に失敗した場合
 */
function fetchUrlSecure(string $url): array {
    // =========================================================================
    // ここに安全なSSRF防御ロジックを実装してください
    // =========================================================================
    // 1. スキーム（プロトコル）の検証:
    $permittedUrlSchemes = ['http', 'https'];
    $urlScheme = parse_url($url, PHP_URL_SCHEME);
    if(!in_array($urlScheme, $permittedUrlSchemes, true)) {
        throw new InvalidArgumentException("URLのスキーム（: {$urlScheme}）が不正です。");
    }

    // 2. ホスト名の取得とDNS名前解決:
    $hostname = parse_url($url, PHP_URL_HOST);
    $ip = gethostbyname($hostname);

    // 3. プライベートIP / 予約済みIPの排除:
    $isValidateGlobalIp = filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
    if(!$isValidateGlobalIp) {
        throw new InvalidArgumentException("解決したIPアドレス（{$ip}）が不正です。プライベートIPまたは予約済みIPは許可されません。");
    }

    // 4. 安全なcURLリクエスト送信:
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false, // ★ リダイレクトを許可しない
        CURLOPT_TIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
    ]);

    $content = curl_exec($ch);
    $error = curl_error($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $primaryIp = curl_getinfo($ch, CURLINFO_PRIMARY_IP);

    if ($content === false) {
        return ['success' => false, 'error' => $error ?: '接続に失敗しました', 'ip' => $primaryIp];
    }
    return [
        'success' => true,
        'content' => $content,
        'http_code' => $httpCode,
        'effective_url' => $effectiveUrl,
        'ip' => $primaryIp
    ];
}

// URLが指定されている場合にフェッチを実行
if (!empty($url)) {
    try {
        if ($mode === 'secure') {
            $fetchResult = fetchUrlSecure($url);
        } else {
            $fetchResult = fetchUrlVulnerable($url);
        }
    } catch (InvalidArgumentException $e) {
        $fetchError = $e->getMessage();
    } catch (Throwable $e) {
        $fetchError = "エラーが発生しました: " . $e->getMessage();
    }
}

?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 4-4: SSRF（Server-Side Request Forgery）演習</title>
    <style>
        body { font-family: sans-serif; max-width: 900px; margin: 30px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-vulnerable { background: #fee2e2; color: #991b1b; }
        .badge-secure { background: #dcfce7; color: #166534; }
        .alert { padding: 15px; border-radius: 6px; margin-bottom: 15px; }
        .alert-success { background: #dcfce7; border-left: 5px solid #16a34a; color: #166534; }
        .alert-danger { background: #fee2e2; border-left: 5px solid #dc2626; color: #991b1b; }
        .btn { display: inline-block; padding: 8px 14px; border-radius: 4px; text-decoration: none; font-weight: bold; font-size: 0.9em; }
        .btn-vulnerable { background: #dc2626; color: white; }
        .btn-secure { background: #16a34a; color: white; }
        pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; max-height: 350px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }
        th { background: #f1f5f9; width: 30%; }
        input[type="text"] { width: 75%; padding: 8px; border: 1px solid #cbd5e1; border-radius: 4px; }
        button[type="submit"] { padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
    </style>
</head>
<body>

    <h1>Phase 4-4: SSRF（Server-Side Request Forgery）演習</h1>
    <p>Webサーバーを踏み台にして社内ネットワークやローカルファイルを探索・窃取する攻撃と、その多層防御を学びます。</p>

    <!-- モード切り替え -->
    <div class="card">
        <h3>現在の判定モード:
            <?php if ($mode === 'vulnerable'): ?>
                <span class="badge badge-vulnerable">モード A: 脆弱 (Vulnerable)</span>
            <?php else: ?>
                <span class="badge badge-secure">モード B: 安全 (Secure)</span>
            <?php endif; ?>
        </h3>
        <p>
            モード切り替え:
            <a href="?mode=vulnerable&url=<?= urlencode($url) ?>" class="btn btn-vulnerable" style="<?= $mode === 'vulnerable' ? 'opacity:0.6; pointer-events:none;' : '' ?>">モード A (脆弱) に切替</a>
            <a href="?mode=secure&url=<?= urlencode($url) ?>" class="btn btn-secure" style="<?= $mode === 'secure' ? 'opacity:0.6; pointer-events:none;' : '' ?>">モード B (安全) に切替</a>
        </p>
    </div>

    <!-- 攻撃・テスト用シミュレーター -->
    <div class="card" style="border: 2px solid #3b82f6;">
        <h3 style="color: #1d4ed8; margin-top: 0;">🎯 URLフェッチャー・SSRF攻撃シミュレーター</h3>
        <p>指定したURLのコンテンツをサーバーが代理で取得します。プリセットをクリックして各攻撃を実験してください：</p>

        <div style="display: flex; flex-direction: column; gap: 8px; margin-bottom: 15px;">
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <a href="?mode=<?= $mode ?>&url=<?= urlencode('http://nginx/phase4/internal_api.php') ?>" class="btn" style="background: #ef4444; color: white;">
                    🚨 攻撃①: 社内極秘APIへのSSRF (http://nginx/...)
                </a>
                <a href="?mode=<?= $mode ?>&url=<?= urlencode('http://127.0.0.1/phase4/internal_api.php') ?>" class="btn" style="background: #dc2626; color: white;">
                    🚨 攻撃②: ループバックへのSSRF (http://127.0.0.1/...)
                </a>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <a href="?mode=<?= $mode ?>&url=<?= urlencode('file:///etc/passwd') ?>" class="btn" style="background: #b91c1c; color: white;">
                    🚨 攻撃③: ローカルファイル窃取 (file:///etc/passwd)
                </a>
                <a href="?mode=<?= $mode ?>&url=<?= urlencode('http://169.254.169.254/latest/meta-data/') ?>" class="btn" style="background: #991b1b; color: white;">
                    🚨 攻撃④: クラウドメタデータ擬似アクセス (169.254.x.x)
                </a>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <a href="?mode=<?= $mode ?>&url=<?= urlencode('https://httpbin.org/get') ?>" class="btn" style="background: #10b981; color: white;">
                    🌐 正規: 外部の安全なWebサイト (https://httpbin.org/get)
                </a>
                <a href="?mode=<?= $mode ?>&url=" class="btn" style="background: #64748b; color: white;">
                    ⚪ リセット
                </a>
            </div>
        </div>

        <!-- 自由入力フォーム -->
        <form method="GET" style="background: #f1f5f9; padding: 12px; border-radius: 6px;">
            <input type="hidden" name="mode" value="<?= htmlspecialchars($mode, ENT_QUOTES, 'UTF-8') ?>">
            <label><strong>取得対象URL:</strong></label><br>
            <div style="margin-top: 5px;">
                <input type="text" name="url" value="<?= htmlspecialchars($url, ENT_QUOTES, 'UTF-8') ?>" placeholder="例: http://nginx/phase4/internal_api.php">
                <button type="submit">サーバーでフェッチ</button>
            </div>
        </form>
    </div>

    <!-- フェッチ結果表示エリア -->
    <div class="card">
        <h3>📥 サーバーによるフェッチ結果</h3>

        <?php if (!empty($url)): ?>
            <p><strong>リクエストURL:</strong> <code><?= htmlspecialchars($url, ENT_QUOTES, 'UTF-8') ?></code></p>
        <?php endif; ?>

        <?php if ($fetchError !== null): ?>
            <!-- 防御成功 / エラー表示 -->
            <div class="alert alert-danger">
                <h4>🛡️ 【アクセス遮断】セキュリティ検証によりブロックされました</h4>
                <p><strong>エラー理由:</strong> <?= htmlspecialchars($fetchError, ENT_QUOTES, 'UTF-8') ?></p>
                <p style="color: #166534; font-weight: bold; margin-top: 5px;">
                    ✅ 内部ネットワークへの不正アクセスが未然に阻止されました！
                </p>
            </div>
        <?php elseif ($fetchResult !== null): ?>
            <?php if ($fetchResult['success']): ?>
                <!-- 取得成功表示 -->
                <?php
                    $isInternalLeak = (str_contains($fetchResult['content'], 'FLAG{SSRF_') || str_contains($fetchResult['content'], 'root:x:'));
                ?>
                <div class="alert <?= $isInternalLeak ? 'alert-danger' : 'alert-success' ?>">
                    <?php if ($isInternalLeak): ?>
                        <h4>🚨 【SSRF成功 / 機密情報漏洩！】社内機密データの取得に成功してしまいました</h4>
                        <p style="color: #991b1b; font-weight: bold;">
                            サーバーが踏み台にされ、外部からはアクセスできないはずの内部データ（社内APIキーやシステムファイル）が奪われました！
                        </p>
                    <?php else: ?>
                        <h4>✅ 【正常取得】外部Webサイトのコンテンツを取得しました</h4>
                    <?php endif; ?>
                    <p><strong>接続先解決IP:</strong> <code><?= htmlspecialchars($fetchResult['ip'] ?? '(不明)', ENT_QUOTES, 'UTF-8') ?></code></p>
                    <p><strong>HTTPステータス:</strong> <code><?= htmlspecialchars($fetchResult['http_code'] ?? '200', ENT_QUOTES, 'UTF-8') ?></code></p>
                </div>

                <h4>取得されたレスポンス本文 (先頭2000文字):</h4>
                <pre><?= htmlspecialchars(mb_substr($fetchResult['content'], 0, 2000), ENT_QUOTES, 'UTF-8') ?></pre>
            <?php else: ?>
                <div class="alert alert-danger">
                    <h4>通信エラー</h4>
                    <p><?= htmlspecialchars($fetchResult['error'], ENT_QUOTES, 'UTF-8') ?></p>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <p style="color: #64748b;">上のシミュレーターボタンまたはURL入力フォームからURLを送信してください。</p>
        <?php endif; ?>
    </div>

</body>
</html>
