<?php
declare(strict_types=1);

// 簡易ユーザーデータ保存先（JSON）
$userDbFile = __DIR__ . '/users_auth.json';
if (!file_exists($userDbFile)) {
    // 初期データ（MD5で保存されてしまった古いユーザーと、平文ユーザー）
    file_put_contents($userDbFile, json_encode([
        'alice' => [
            'type' => 'md5',
            'password_hash' => md5('password123'), // 危険なMD5
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

$users = json_decode((string)file_get_contents($userDbFile), true) ?: [];
$message = '';
$action = $_GET['action'] ?? '';

// 1. ユーザー新規登録
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'register') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username !== '' && $password !== '') {
        // =====================================================================
        // TODO 1: 暗号学的に安全なパスワードハッシュを生成してください
        // 要件:
        //   - password_hash() 関数を使用
        //   - アルゴリズム: PASSWORD_DEFAULT (または PASSWORD_BCRYPT)
        //   - オプション: BCRYPTのコストは 12 に設定 (['cost' => 12])
        // =====================================================================
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);

        $users[$username] = [
            'type' => 'secure_hash',
            'password_hash' => $hashedPassword,
        ];
        file_put_contents($userDbFile, json_encode($users, JSON_PRETTY_PRINT));
        $message = "ユーザー '{$username}' を安全なハッシュで登録しました！";
    }
}

// 2. ログイン認証
$loginSuccess = false;
$loginUser = '';
$rehashedNotice = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (isset($users[$username])) {
        $userData = $users[$username];
        $storedHash = $userData['password_hash'];

        // =====================================================================
        // TODO 2: 安全なパスワード照合を行ってください
        // 要件:
        //   - password_verify() 関数を使って平文パスワードとハッシュを照合
        //   - 一致した場合は $loginSuccess = true; にする
        // =====================================================================
        if (password_verify($password, $storedHash)) {
            $loginSuccess = true;
        }

        // =====================================================================
        // TODO 3: ハッシュの自動再生成（アップグレード）判定を実装してください
        // 要件:
        //   - ログイン成功時に、現在のハッシュが最新の推奨基準（cost=12等）を満たしているか
        //     password_needs_rehash() で確認
        //   - もし古い基準（または古いアルゴリズム）なら、新しいハッシュを生成してDB保存を更新
        // =====================================================================
        if ($loginSuccess) {
            $loginUser = $username;
            // ここに password_needs_rehash のロジックを実装
            if (password_needs_rehash($storedHash, PASSWORD_DEFAULT, ['cost' => 12])) {
                $newHash = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
                $users[$username]['password_hash'] = $newHash;
                file_put_contents($userDbFile, json_encode($users, JSON_PRETTY_PRINT));
                $rehashedNotice = true;
            }
        }
    }

    if (!$loginSuccess) {
        $message = "ユーザー名またはパスワードが正しくありません。";
    }
}

// レインボーテーブル（簡易逆引き辞書）
$rainbowTable = [
    md5('123456')      => '123456',
    md5('password')    => 'password',
    md5('password123') => 'password123',
    md5('admin')       => 'admin',
    md5('qwerty')      => 'qwerty',
];
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 3-1: パスワード暗号学的ハッシュ化実験室</title>
    <style>
        body { font-family: sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }
        .box { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-success { background: #dcfce7; color: #15803d; }
        .alert-danger { background: #fee2e2; color: #b91c1c; }
        .btn { padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; }
        pre { background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; overflow-x: auto; }
        code { background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
        input[type="text"], input[type="password"] { padding: 6px; border: 1px solid #cbd5e1; border-radius: 4px; width: 250px; }
    </style>
</head>
<body>
    <h1>Phase 3-1: パスワード暗号学的ハッシュ化実験室</h1>

    <?php if ($message): ?>
        <div class="alert <?= $loginSuccess ? 'alert-success' : 'alert-danger' ?>"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <?php if ($loginSuccess): ?>
        <div class="alert alert-success">
            🎉 ログイン成功！ ようこそ <strong><?= htmlspecialchars($loginUser, ENT_QUOTES, 'UTF-8') ?></strong> 様！
            <?php if ($rehashedNotice): ?>
                <br>🛡️ <strong>【自動アップグレード実行】</strong> 古いハッシュを検知し、最新の安全なハッシュに自動更新しました！
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- 1. ユーザー登録 -->
    <div class="box">
        <h2>1. ユーザー新規登録（安全なハッシュで保存）</h2>
        <form method="POST" action="?action=register">
            <p>ユーザー名: <input type="text" name="username" placeholder="例: bob" required></p>
            <p>パスワード: <input type="password" name="password" placeholder="例: secretPass789" required></p>
            <button type="submit" class="btn">安全に登録する</button>
        </form>
    </div>

    <!-- 2. ログイン認証 -->
    <div class="box">
        <h2>2. ログイン認証</h2>
        <form method="POST" action="?action=login">
            <p>ユーザー名: <input type="text" name="username" value="alice" required></p>
            <p>パスワード: <input type="password" name="password" placeholder="パスワードを入力" required></p>
            <button type="submit" class="btn">ログイン</button>
        </form>
    </div>

    <!-- 3. DBの中身とレインボーテーブル解読実験 -->
    <div class="box">
        <h2>3. データベース（users_auth.json）の中身</h2>
        <p>サーバーに保存されている生のハッシュデータです：</p>
        <pre><?= htmlspecialchars((string)file_get_contents($userDbFile), ENT_QUOTES, 'UTF-8') ?></pre>

        <h3>⚠️ レインボーテーブルによる逆引き解読実験</h3>
        <p>初期登録されている Alice のハッシュ値（MD5）は、辞書テーブルで解読できるか？</p>
        <?php
        $aliceHash = $users['alice']['password_hash'] ?? '';
        if (isset($rainbowTable[$aliceHash])):
        ?>
            <p style="color: #dc2626; font-weight: bold;">
                🚨 逆引き成功！ AliceのMD5ハッシュ <code><?= htmlspecialchars($aliceHash, ENT_QUOTES, 'UTF-8') ?></code> の平文は 
                <span style="font-size: 1.2em; background: #fee2e2; padding: 2px 6px;">「<?= $rainbowTable[$aliceHash] ?>」</span> です！
            </p>
        <?php else: ?>
            <p style="color: #15803d; font-weight: bold;">
                🛡️ 解読失敗: このハッシュはレインボーテーブルでは逆引きできませんでした。
            </p>
        <?php endif; ?>
    </div>
</body>
</html>
