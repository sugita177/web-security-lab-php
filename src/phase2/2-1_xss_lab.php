<?php
declare(strict_types=1);

// 格納型XSS用のデータ保存先（簡易JSONファイル）
$storageFile = __DIR__ . '/comments.json';
if (!file_exists($storageFile)) {
    file_put_contents($storageFile, json_encode([
        ['name' => 'Alice', 'comment' => 'こんにちは！'],
    ], JSON_UNESCAPED_UNICODE));
}

// 防御トグル（クエリパラメータやチェックボックスで切り替え）
$escapeMode = isset($_GET['escape']); // 安全なエスケープを行うか
$cspMode = isset($_GET['csp']);       // CSPヘッダーを有効にするか

if ($cspMode) {
    // =========================================================================
    // TODO 3: 多層防御としての CSP (Content Security Policy) ヘッダーを送出してください
    // 要件:
    //   - レスポンスヘッダー: 'Content-Security-Policy'
    //   - ポリシー: 自サイトのリソースのみ許可し、インラインスクリプトの実行を禁止する
    //   - ヒント: "default-src 'self'"
    // =========================================================================
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'");
}

// 投稿処理（格納型XSS用）
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    $name = trim($_POST['name'] ?? '名無し');
    $comment = trim($_POST['comment'] ?? '');

    if ($comment !== '') {
        $comments = json_decode((string)file_get_contents($storageFile), true) ?: [];
        $comments[] = ['name' => $name, 'comment' => $comment];
        file_put_contents($storageFile, json_encode($comments, JSON_UNESCAPED_UNICODE));
    }
    header('Location: 2-1_xss_lab.php' . ($escapeMode ? '?escape=1' : '') . ($cspMode ? ($escapeMode ? '&csp=1' : '?csp=1') : ''));
    exit;
}

// 掲示板のリセット処理
if (isset($_GET['reset'])) {
    file_put_contents($storageFile, json_encode([
        ['name' => 'Alice', 'comment' => 'こんにちは！'],
    ], JSON_UNESCAPED_UNICODE));
    header('Location: 2-1_xss_lab.php');
    exit;
}

$searchQuery = $_GET['q'] ?? '';
$comments = json_decode((string)file_get_contents($storageFile), true) ?: [];

// 安全なエスケープ用ヘルパー関数
function h(string $str): string {
    // =========================================================================
    // TODO 1: 正確な htmlspecialchars によるエスケープ関数を完成させてください
    // 要件:
    //   - シングルクォート・ダブルクォートの両方をエスケープすること (ENT_QUOTES)
    //   - 不正な文字コードを置換すること (ENT_SUBSTITUTE)
    //   - 文字コードは 'UTF-8'
    // =========================================================================
    return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 2-1: XSS（クロスサイトスクリプティング）実験室</title>
    <style>
        body { font-family: sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }
        .box { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-danger { background: #fee2e2; color: #b91c1c; }
        .alert-success { background: #dcfce7; color: #15803d; }
        .btn { padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-danger { background: #dc2626; }
        .comment-item { border-bottom: 1px solid #e2e8f0; padding: 10px 0; }
        input[type="text"] { padding: 6px; border: 1px solid #cbd5e1; border-radius: 4px; width: 300px; }
    </style>
</head>
<body>
    <h1>Phase 2-1: XSS（クロスサイトスクリプティング）実験室</h1>

    <div class="box">
        <h2>現在の防御モード設定</h2>
        <p>
            エスケープ状態: 
            <?php if ($escapeMode): ?>
                <strong style="color: #15803d;">🛡️ 安全（htmlspecialchars 有効）</strong>
            <?php else: ?>
                <strong style="color: #dc2626;">⚠️ 脆弱（エスケープなし・生出力）</strong>
            <?php endif; ?>
             | 
            CSPヘッダー: 
            <?php if ($cspMode): ?>
                <strong style="color: #15803d;">🛡️ 有効 (default-src 'self')</strong>
            <?php else: ?>
                <span style="color: #64748b;">無効</span>
            <?php endif; ?>
        </p>
        <p>
            <a class="btn" href="?">1. 【危険】脆弱モード</a>
            <a class="btn" href="?escape=1">2. 【防御】エスケープ有効モード</a>
            <a class="btn" href="?csp=1">3. 【多層防御】エスケープなし + CSP有効モード</a>
        </p>
    </div>

    <!-- 1. 反射型XSS（Reflected XSS）実験エリア -->
    <div class="box">
        <h2>1. 反射型XSS（検索フォーム）</h2>
        <form method="GET" action="">
            <?php if ($escapeMode): ?><input type="hidden" name="escape" value="1"><?php endif; ?>
            <?php if ($cspMode): ?><input type="hidden" name="csp" value="1"><?php endif; ?>
            <input type="text" name="q" value="<?= $escapeMode ? h($searchQuery) : $searchQuery ?>" placeholder="検索キーワードを入力">
            <button type="submit" class="btn">検索</button>
        </form>

        <?php if ($searchQuery !== ''): ?>
            <p>検索結果: 
                <!-- ================================================================= -->
                <!-- TODO 2: $escapeMode に応じて安全に出力するか、生出力するか分岐してください -->
                <!-- ================================================================= -->
                <?php if ($escapeMode): ?>
                    「<span><?= h($searchQuery) ?></span>」の検索結果（0件）
                <?php else: ?>
                    「<span><?= $searchQuery /* 脆弱な生出力 */ ?></span>」の検索結果（0件）
                <?php endif; ?>
            </p>
        <?php endif; ?>
    </div>

    <!-- 2. 格納型XSS（Stored XSS）実験エリア -->
    <div class="box">
        <h2>2. 格納型XSS（一言掲示板）</h2>
        <form method="POST" action="">
            <p><input type="text" name="name" placeholder="お名前" required></p>
            <p><input type="text" name="comment" placeholder="コメント（攻撃コードを入力）" required></p>
            <button type="submit" class="btn">投稿する</button>
            <a href="?reset=1" class="btn btn-danger">掲示板を初期化</a>
        </form>

        <h3>投稿一覧</h3>
        <?php foreach ($comments as $c): ?>
            <div class="comment-item">
                <strong><?= $escapeMode ? h($c['name']) : $c['name'] ?></strong>: 
                <span><?= $escapeMode ? h($c['comment']) : $c['comment'] ?></span>
            </div>
        <?php endforeach; ?>
    </div>
</body>
</html>
