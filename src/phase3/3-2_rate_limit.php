<?php
session_start();

// 防御モード（デフォルトON）
if (!isset($_SESSION['defense_mode'])) {
    $_SESSION['defense_mode'] = true;
}
if (isset($_POST['toggle_defense'])) {
    $_SESSION['defense_mode'] = !$_SESSION['defense_mode'];
    header('Location: 3-2_rate_limit.php');
    exit;
}

$attemptsFile = __DIR__ . '/login_attempts.json';

// 試行データのロード
function loadAttempts(string $file): array {
    if (!file_exists($file)) {
        return [];
    }
    $data = json_decode(file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

// 試行データの保存
function saveAttempts(string $file, array $data): void {
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

// 試行データの手動リセット
if (isset($_POST['reset_attempts'])) {
    if (file_exists($attemptsFile)) {
        unlink($attemptsFile);
    }
    header('Location: 3-2_rate_limit.php');
    exit;
}

// テスト用ユーザー定義（パスワードは Phase 3-1 と同様 password_hash 済み）
// admin: 'secret123'
// alice: 'pass456'
$users = [
    'admin' => '$2y$12$rxIAsRN1kLKup4/jg7jBcuGICyY3KPNYEqtcP.LxZhvqh0HwArTL6', // secret123
    'alice' => '$2y$12$bWDhjHeurap59NfYmxsOpuFiPPAiTj8oewvUwEqt2ZKSOvGdeaVUC', // pass456
];

$message = '';
$messageType = '';
$defenseMode = $_SESSION['defense_mode'];
$attempts = loadAttempts($attemptsFile);

// ロックアウトのパラメータ定義
$maxAttempts = 3;      // 許容失敗回数（3回失敗でロック）
$lockoutSeconds = 60;  // ロック時間（60秒間）

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    $currentTime = time();
    $userAttempt = $attempts[$username] ?? [
        'failed_count' => 0,
        'locked_until' => null,
    ];

    if ($defenseMode) {
        // =========================================================================
        // 【TODO 1: アカウントロック状態のチェック】
        // もし現在時刻 ($currentTime) が $userAttempt['locked_until'] より前であれば、
        // ロック中とみなしてログイン処理を行わずにエラーメッセージを設定してください。
        // （残り秒数: $userAttempt['locked_until'] - $currentTime を表示すると親切です）
        // =========================================================================
        // TODO: ここを修正してください (例: !empty(...) && ... > $currentTime)
        $isLocked = !empty($userAttempt['locked_until']) && $userAttempt['locked_until'] > $currentTime;

        if ($isLocked) {
            $remaining = $userAttempt['locked_until'] - $currentTime;
            $message = "このアカウントは連続認証失敗によりロックされています（残り {$remaining} 秒）";
            $messageType = "danger";
            goto end_login; // パスワード照合を行わずにスキップ
        }
    }

    // 認証判定
    if (isset($users[$username]) && password_verify($password, $users[$username])) {
        // 認証成功！
        if ($defenseMode) {
            // =========================================================================
            // 【TODO 2: 認証成功時のリセット】
            // ログインに成功したので、このユーザーの失敗カウントとロック状態をクリアしてください。
            // =========================================================================
            // TODO: $userAttempt['failed_count'] と $userAttempt['locked_until'] を初期化
            $userAttempt['failed_count'] = 0;
            $userAttempt['locked_until'] = null;
            $attempts[$username] = $userAttempt;
            saveAttempts($attemptsFile, $attempts);
        }

        $message = "ログインに成功しました！ようこそ、" . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . " さん。";
        $messageType = "success";
    } else {
        // 認証失敗...
        if ($defenseMode) {
            // =========================================================================
            // 【TODO 3: 認証失敗の記録とロックアウト判定】
            // 1. $userAttempt['failed_count'] を 1 増やす
            // 2. もし失敗回数が $maxAttempts に達したら、
            //    $userAttempt['locked_until'] に ($currentTime + $lockoutSeconds) をセット
            // =========================================================================
            // TODO: ここにカウントアップとロック判定を実装してください
            $userAttempt['failed_count']++;
            if ($userAttempt['failed_count'] >= $maxAttempts) {
                $userAttempt['locked_until'] = $currentTime + $lockoutSeconds;
            }
            $attempts[$username] = $userAttempt;
            saveAttempts($attemptsFile, $attempts);

            // ロックされた直後かどうかのメッセージ分岐
            if (!empty($userAttempt['locked_until']) && $userAttempt['locked_until'] > $currentTime) {
                $message = "ログインに失敗しました。連続失敗回数が上限({$maxAttempts}回)に達したため、アカウントを{$lockoutSeconds}秒間ロックしました。";
                $messageType = "danger";
            } else {
                $remains = $maxAttempts - $userAttempt['failed_count'];
                $message = "ユーザー名またはパスワードが違います（あと {$remains} 回失敗するとロックされます）";
                $messageType = "warning";
            }
        } else {
            // 防御OFF：何回失敗しても警告するだけでロックしない
            $message = "ユーザー名またはパスワードが違います（防御OFFのため何度でも試行可能）";
            $messageType = "warning";
        }
    }

    end_login:
}

// 再読込
$attempts = loadAttempts($attemptsFile);
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 3-2: ブルートフォース & レートリミット演習</title>
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
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 6px 0 14px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 4px; }
        button { cursor: pointer; padding: 8px 16px; border-radius: 4px; border: none; font-weight: bold; }
        .btn-primary { background: #2563eb; color: white; }
        .btn-secondary { background: #64748b; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #e2e8f0; padding: 8px; text-align: left; }
        th { background: #f1f5f9; }
        code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; }
        pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>

    <h1>Phase 3-2: ブルートフォース・レートリミット演習</h1>

    <!-- 防御状態・コントロール -->
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <strong>アプリケーション層 防御モード:</strong>
                <?php if ($defenseMode): ?>
                    <span class="badge badge-on">ON（アカウントロック有効）</span>
                <?php else: ?>
                    <span class="badge badge-off">OFF（無制限試行許可）</span>
                <?php endif; ?>
            </div>
            <div style="display: flex; gap: 8px;">
                <form method="POST" style="margin: 0;">
                    <button type="submit" name="toggle_defense" class="btn-secondary">
                        モード切替 (現在: <?= $defenseMode ? 'ON' : 'OFF' ?>)
                    </button>
                </form>
                <form method="POST" style="margin: 0;">
                    <button type="submit" name="reset_attempts" class="btn-danger">
                        ロック試行履歴リセット
                    </button>
                </form>
            </div>
        </div>
        <p style="margin: 10px 0 0; font-size: 0.9em; color: #64748b;">
            ※ NginxレイヤーのIPレートリミット（`2r/s, burst=5`）は常時有効です。
        </p>
    </div>

    <!-- メッセージ表示 -->
    <?php if ($message): ?>
        <div class="alert alert-<?= $messageType ?>">
            <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <!-- ログインフォーム -->
    <div class="card">
        <h2>ログイン</h2>
        <form method="POST">
            <label>ユーザー名 (登録例: <code>admin</code> / <code>alice</code>):</label>
            <input type="text" name="username" value="<?= htmlspecialchars($_POST['username'] ?? 'admin', ENT_QUOTES, 'UTF-8') ?>" required>

            <label>パスワード (adminの正解: <code>secret123</code>):</label>
            <input type="password" name="password" required>

            <button type="submit" name="login" class="btn-primary">ログイン試行</button>
        </form>
    </div>

    <!-- サーバー側 試行・ロック管理テーブル -->
    <div class="card">
        <h3>サーバー側の試行管理状態 (<code>login_attempts.json</code>)</h3>
        <table>
            <thead>
                <tr>
                    <th>ユーザー名</th>
                    <th>失敗回数</th>
                    <th>ロック状態 / 残り秒数</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($attempts)): ?>
                    <tr><td colspan="3" style="text-align: center; color: #94a3b8;">記録された試行データはありません</td></tr>
                <?php else: ?>
                    <?php foreach ($attempts as $u => $info): ?>
                        <?php
                            $now = time();
                            $locked = !empty($info['locked_until']) && $info['locked_until'] > $now;
                            $remain = $locked ? ($info['locked_until'] - $now) : 0;
                        ?>
                        <tr>
                            <td><strong><?= htmlspecialchars($u, ENT_QUOTES, 'UTF-8') ?></strong></td>
                            <td><?= (int)($info['failed_count'] ?? 0) ?> / <?= $maxAttempts ?></td>
                            <td>
                                <?php if ($locked): ?>
                                    <span style="color: #dc2626; font-weight: bold;">🔒 ロック中 (残り <?= $remain ?> 秒)</span>
                                <?php else: ?>
                                    <span style="color: #16a34a;">正常 (ロックなし)</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- 攻撃実証用コマンドガイド -->
    <div class="card">
        <h3>ターミナルからの攻撃実証（スクリプトによる総当たり）</h3>
        <p>以下のコマンドを実行して、Nginx（HTTP 429）およびPHP（アカウントロック）の挙動を検証できます。</p>
        
        <p><strong>① Nginx IPレートリミット実証（秒間10回リクエストでHTTP 429が返るか）:</strong></p>
        <pre>for i in {1..10}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/phase3/3-2_rate_limit.php; done</pre>

        <p><strong>② ブルートフォース（辞書総当たり）試行（0.6秒間隔で順に試行）:</strong></p>
        <pre>for pass in 123456 password admin123 secret123; do
  echo "=== 試行パスワード: $pass ==="
  curl -s -X POST http://localhost:8080/phase3/3-2_rate_limit.php \
    -d "username=admin&password=$pass&login=1" | sed -n '/class="alert alert-/,/&lt;\/div&gt;/p' | tr -d '\n'
  echo -e "\n"
  sleep 0.6
done</pre>
    </div>

</body>
</html>
