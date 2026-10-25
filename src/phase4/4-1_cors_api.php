<?php
session_start();

// ログ用ファイル
$logFile = __DIR__ . '/cors_request_log.json';

function getLogs(string $file): array
{
    if (!file_exists($file)) return [];
    $data = json_decode(file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function addLog(string $file, array $entry): void
{
    $logs = getLogs($file);
    array_unshift($logs, $entry); // 先頭に追加
    $logs = array_slice($logs, 0, 10); // 直近10件
    file_put_contents($file, json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

// ログリセット
if (isset($_POST['clear_logs'])) {
    if (file_exists($logFile)) unlink($logFile);
    header('Location: 4-1_cors_api.php');
    exit;
}

// CORSモード設定 (0: なし, 1: ワイルドカード*, 2: 具体的オリジン+Cookie+プリフライト)
// ※ Cookieを送らない単純リクエストでも共有できるよう、ファイルで永続化
$configFile = __DIR__ . '/cors_config.json';
function getCorsMode(string $file): int {
    if (!file_exists($file)) return 0;
    $cfg = json_decode(file_get_contents($file), true);
    return isset($cfg['cors_mode']) ? (int)$cfg['cors_mode'] : 0;
}

if (isset($_POST['set_cors_mode'])) {
    $newMode = (int)$_POST['cors_mode'];
    file_put_contents($configFile, json_encode(['cors_mode' => $newMode]));
    header('Location: 4-1_cors_api.php');
    exit;
}

$corsMode = getCorsMode($configFile);

// 疑似ログイン（Cookie発行確認用）
if (!isset($_SESSION['user_secret'])) {
    $_SESSION['user_secret'] = [
        'username' => 'yamada_taro',
        'account_number' => '9876-5432-1098',
        'secret_balance' => '¥5,000,000',
        'token' => 'SECRET_API_TOKEN_XYZ999'
    ];
}

// =========================================================================
// 【CORS ヘッダー制御ロジック】
// =========================================================================
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($corsMode === 1) {
    // モード 1: 安易なワイルドカード（*）
    header('Access-Control-Allow-Origin: *');
} elseif ($corsMode === 2) {
    // =========================================================================
    // 【TODO 1: 安全なCORS許可ヘッダーの実装】
    // 信頼できるオリジン (http://localhost:8081) からのアクセスを許可し、
    // かつ Cookie (credentials) の送受信を許可するヘッダーを出力してください。
    //
    // ヒント:
    // 1. Access-Control-Allow-Origin: 許可する具体的なオリジン
    // 2. Access-Control-Allow-Credentials: 'true'
    // =========================================================================
    // header('Access-Control-Allow-Origin: ...');
    // header('Access-Control-Allow-Credentials: ...');
    header('Access-Control-Allow-Origin: http://localhost:8081');
    header('Access-Control-Allow-Credentials: true');

    // =========================================================================
    // 【TODO 2: プリフライト (OPTIONS) リクエストへの応答】
    // ブラウザが本番リクエストの前に送信してくる事前伺い (OPTIONS) に対して、
    // 許可する HTTP メソッドと、許可するリクエストヘッダーを指定して即時終了してください。
    //
    // ヒント:
    // 1. $requestMethod === 'OPTIONS' か判定
    // 2. Access-Control-Allow-Methods: GET, POST, OPTIONS
    // 3. Access-Control-Allow-Headers: Content-Type, X-Custom-Header
    // 4. HTTPステータス 204 No Content (または 200) で exit;
    // =========================================================================
    // if ($requestMethod === 'OPTIONS') { ... }
    if ($requestMethod === 'OPTIONS') {
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-Custom-Header');
        header('HTTP/1.1 204 No Content');
        exit;
    }
}

// サーバーログへの記録（外部オリジンからのアクセスを可視化）
// ※ 直接URLアクセス時は Sec-Fetch-Site: none となるため除外
$isFetchRequest = !empty($_SERVER['HTTP_ORIGIN']) 
    || (($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '') === 'cross-site')
    || ($requestMethod === 'OPTIONS');

if ($isFetchRequest) {
    $hasCookie = !empty($_COOKIE['PHPSESSID']);
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    addLog($logFile, [
        'time' => date('H:i:s'),
        'method' => $requestMethod,
        'origin' => $origin ?: '(同一オリジン/なし)',
        'cookie_sent' => $hasCookie ? 'あり (PHPSESSID送出)' : 'なし',
        'content_type' => $contentType,
        'cors_mode' => $corsMode
    ]);
}

// JSON APIとしてのリクエスト処理
// （?api=1 が付いているか、別オリジンからのfetch/プリフライトの場合）
if (isset($_GET['api']) || $isFetchRequest) {
    header('Content-Type: application/json; charset=UTF-8');

    // 認証情報があるか
    $isAuth = !empty($_COOKIE['PHPSESSID']);

    echo json_encode([
        'status' => 'success',
        'server_time' => date('Y-m-d H:i:s'),
        'message' => 'APIサーバーからの応答データです',
        'authenticated' => $isAuth,
        'user_data' => $isAuth ? $_SESSION['user_secret'] : [
            'notice' => 'Cookie (認証情報) が送信されていないため、公開データのみ返却します'
        ]
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// 通常のブラウザ閲覧用管理UI
$logs = getLogs($logFile);
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 4-1: 標的APIサーバー & CORS管理画面</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 30px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-0 { background: #64748b; color: white; }
        .badge-1 { background: #f59e0b; color: white; }
        .badge-2 { background: #10b981; color: white; }
        button { cursor: pointer; padding: 8px 16px; border-radius: 4px; border: none; font-weight: bold; }
        .btn-primary { background: #2563eb; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }
        th { background: #f1f5f9; }
        code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; }
        pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>

    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h2>🎯 標的APIサーバー (ポート 8080)</h2>
            <span style="background: #2563eb; color: white; padding: 4px 10px; border-radius: 20px; font-weight: bold; font-size: 0.9em;">
                オリジン: http://localhost:8080
            </span>
        </div>
        <p>このサーバーは会員の口座情報や機微APIデータを配信しています。</p>

        <!-- CORS設定切り替えフォーム -->
        <form method="POST" style="margin-top: 20px; background: #f1f5f9; padding: 15px; border-radius: 6px;">
            <strong>⚙️ 現在の CORS 設定モード:</strong><br><br>
            <label style="display: block; margin-bottom: 8px;">
                <input type="radio" name="cors_mode" value="0" <?= $corsMode === 0 ? 'checked' : '' ?>>
                <strong>モード 0: CORS ヘッダーなし</strong> (SOP デフォルト: 別オリジンからの読み取り完全禁止)
            </label>
            <label style="display: block; margin-bottom: 8px;">
                <input type="radio" name="cors_mode" value="1" <?= $corsMode === 1 ? 'checked' : '' ?>>
                <strong>モード 1: 安易なワイルドカード</strong> (<code>Access-Control-Allow-Origin: *</code>)
            </label>
            <label style="display: block; margin-bottom: 12px;">
                <input type="radio" name="cors_mode" value="2" <?= $corsMode === 2 ? 'checked' : '' ?>>
                <strong>モード 2: 具体的オリジン許可＋Cookie許可＋プリフライト対応</strong> (TODO実装対象)
            </label>
            <button type="submit" name="set_cors_mode" class="btn-primary">モードを変更して保存</button>
        </form>
    </div>

    <!-- サーバー側 リクエスト受信ログ -->
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h3>📡 サーバー側 受信ログ（直近10件）</h3>
            <form method="POST" style="margin: 0;">
                <button type="submit" name="clear_logs" class="btn-danger">ログ消去</button>
            </form>
        </div>
        <p style="font-size: 0.9em; color: #64748b;">
            ※ クライアント側で「CORSエラー」が表示されていても、<strong>ここにログが記録されていれば「サーバーにはリクエストが届いていた」</strong> という動かぬ証拠になります！
        </p>

        <table>
            <thead>
                <tr>
                    <th>時刻</th>
                    <th>メソッド</th>
                    <th>Origin (送信元)</th>
                    <th>Cookie (セッション)</th>
                    <th>Content-Type</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($logs)): ?>
                    <tr><td colspan="5" style="text-align: center; color: #94a3b8;">まだ外部からのリクエストはありません</td></tr>
                <?php else: ?>
                    <?php foreach ($logs as $l): ?>
                        <tr>
                            <td><?= htmlspecialchars($l['time'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td><strong><?= htmlspecialchars($l['method'], ENT_QUOTES, 'UTF-8') ?></strong></td>
                            <td><code><?= htmlspecialchars($l['origin'], ENT_QUOTES, 'UTF-8') ?></code></td>
                            <td><?= htmlspecialchars($l['cookie_sent'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td><small><?= htmlspecialchars($l['content_type'] ?: 'なし', ENT_QUOTES, 'UTF-8') ?></small></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

</body>
</html>
