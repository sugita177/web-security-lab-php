<?php
declare(strict_types=1);

// CSRFの検証をより明確にするため、セッションCookieのSameSiteをNoneに設定（従来の挙動）
// ※実務ではLaxが標準ですが、ここでは純粋なCSRFトークンの防御効果を観察するため明示
session_set_cookie_params([
    'path' => '/',
    'httponly' => true,
    'samesite' => 'None',
    'secure' => true, // localhost特例で動作
]);
session_start();

// 初回アクセス時の初期化（アリスの銀行口座）
if (!isset($_SESSION['user'])) {
    $_SESSION['user'] = 'alice';
    $_SESSION['balance'] = 1000000; // 残高 100万円
    $_SESSION['history'] = [];
}

// CSRF防御のON/OFF（セッションに保存して攻撃者のクエリなしPOSTでも状態を維持）
if (isset($_GET['protect'])) {
    $_SESSION['csrf_protection'] = (bool)$_GET['protect'];
}
$protectionEnabled = $_SESSION['csrf_protection'] ?? false;
$message = '';
$messageType = '';


// 送金処理
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['to_account'], $_POST['amount'])) {
    $toAccount = trim((string)$_POST['to_account']);
    $amount = (int)$_POST['amount'];
    $submittedToken = (string)($_POST['csrf_token'] ?? '');

    $canTransfer = true;

    if ($protectionEnabled) {
        // =========================================================================
        // TODO 2: 送信されたCSRFトークンを検証してください
        // 要件:
        //   - セッションに保存されているトークンと、フォームから届いたトークンを比較
        //   - タイミング攻撃を防ぐ安全な関数 `hash_equals()` を使用すること
        //   - トークンが空、または不一致の場合は送金を拒否し、メッセージを設定すること
        // =========================================================================
        $sessionToken = $_SESSION['csrf_token'] ?? '';
        
        // ここを実装してください（$canTransfer = false; にする）
        if (!hash_equals($sessionToken, $submittedToken)) {
            $canTransfer = false;
            $message = '【CSRF攻撃を検知・遮断】不正なリクエスト（無効または欠落したCSRFトークン）のため送金を拒否しました！';
            $messageType = 'danger';
        }
    }

    if ($canTransfer) {
        if ($amount > 0 && $amount <= $_SESSION['balance']) {
            $_SESSION['balance'] -= $amount;
            $_SESSION['history'][] = [
                'time' => date('H:i:s'),
                'to' => $toAccount,
                'amount' => $amount,
                'source' => ($_SERVER['HTTP_REFERER'] ?? 'Unknown'),
            ];
            $message = "【送金完了】{$toAccount} へ {$amount} 円を送金しました！";
            $messageType = 'success';
        } else {
            $message = "送金に失敗しました（残高不足または無効な金額）。";
            $messageType = 'danger';
        }
    }
}

// 口座リセット
if (isset($_GET['reset'])) {
    $_SESSION['balance'] = 1000000;
    $_SESSION['history'] = [];
    header('Location: 2-2_csrf_lab.php' . ($protectionEnabled ? '?protect=1' : ''));
    exit;
}

// =============================================================================
// TODO 1: 暗号学的に安全なCSRFトークンを生成し、セッションに保存してください
// 要件:
//   - セッションにトークンが未発行、または空の場合に生成すること
//   - 暗号学的に安全な乱数 `random_bytes(32)` と `bin2hex()` を使用すること
// =============================================================================
if (empty($_SESSION['csrf_token'])) {
    // ここを実装してください: $_SESSION['csrf_token'] = ...
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'] ?? '';
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 2-2: CSRF（クロスサイトリクエストフォージェリ）銀行</title>
    <style>
        body { font-family: sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }
        .box { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-success { background: #dcfce7; color: #15803d; }
        .alert-danger { background: #fee2e2; color: #b91c1c; }
        .btn { padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-danger { background: #dc2626; }
        .btn-trap { background: #e11d48; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; }
        th { background: #f1f5f9; }
    </style>
</head>
<body>
    <h1>🏦 Web Security Bank (localhost:8080)</h1>

    <?php if ($message): ?>
        <div class="alert alert-<?= $messageType ?>"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <div class="box">
        <h2>口座情報（<?= htmlspecialchars($_SESSION['user'], ENT_QUOTES, 'UTF-8') ?> 様）</h2>
        <p style="font-size: 1.3em;">口座残高: <strong><?= number_format($_SESSION['balance']) ?> 円</strong></p>
        <p>
            現在の防御状態: 
            <?php if ($protectionEnabled): ?>
                <strong style="color: #15803d;">🛡️ CSRFトークン検証 有効</strong>
            <?php else: ?>
                <strong style="color: #dc2626;">⚠️ 脆弱（CSRFトークン検証 なし）</strong>
            <?php endif; ?>
        </p>
        <p>
            <a class="btn" href="?protect=0">1. 【危険】脆弱モード</a>
            <a class="btn" href="?protect=1">2. 【防御】CSRFトークン検証モード</a>
            <a class="btn btn-danger" href="?reset=1<?= $protectionEnabled ? '&protect=1' : '' ?>">残高リセット</a>
        </p>
    </div>

    <div class="box">
        <h2>送金フォーム（正規の送金画面）</h2>
        <form method="POST" action="?protect=<?= $protectionEnabled ? '1' : '0' ?>">
            <!-- ================================================================= -->
            <!-- TODO 3: フォーム内にCSRFトークンをhiddenフィールドとして埋め込んでください -->
            <!-- 要件: name="csrf_token" value="$csrfToken"                       -->
            <!-- ================================================================= -->
            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

            <p>
                送金先口座: <input type="text" name="to_account" value="bob" required>
            </p>
            <p>
                送金金額: <input type="number" name="amount" value="10000" required> 円
            </p>
            <button type="submit" class="btn">送金を実行する</button>
        </form>
    </div>

    <div class="box">
        <h2>最近の送金履歴</h2>
        <?php if (empty($_SESSION['history'])): ?>
            <p style="color: #64748b;">送金履歴はありません。</p>
        <?php else: ?>
            <table>
                <tr>
                    <th>時刻</th>
                    <th>送金先</th>
                    <th>金額</th>
                    <th>リクエスト送信元 (Referer)</th>
                </tr>
                <?php foreach (array_reverse($_SESSION['history']) as $h): ?>
                    <tr>
                        <td><?= htmlspecialchars($h['time'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><?= htmlspecialchars($h['to'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><?= number_format($h['amount']) ?> 円</td>
                        <td style="<?= str_contains($h['source'], '8081') ? 'color: red; font-weight: bold;' : '' ?>">
                            <?= htmlspecialchars($h['source'], ENT_QUOTES, 'UTF-8') ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </table>
        <?php endif; ?>
    </div>

    <div class="box" style="border: 2px dashed #e11d48; background: #fff1f2;">
        <h2>⚠️ 攻撃者の罠サイトシミュレーション</h2>
        <p>独立した別オリジンの攻撃サイト（ポート 8081）を開いて、不正送金を試みます：</p>
        <a class="btn btn-trap" href="http://localhost:8081/" target="_blank">
            攻撃者の罠サイト（localhost:8081）を開く ↗
        </a>
    </div>
</body>
</html>
