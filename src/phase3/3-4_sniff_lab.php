<?php
session_start();

// 防御モード（デフォルトOFFで脆弱性をまず確認）
if (!isset($_SESSION['defense_mode_sniff'])) {
    $_SESSION['defense_mode_sniff'] = false;
}
if (isset($_POST['toggle_sniff'])) {
    $_SESSION['defense_mode_sniff'] = !$_SESSION['defense_mode_sniff'];
    header('Location: 3-4_sniff_lab.php');
    exit;
}

$sniffDefense = $_SESSION['defense_mode_sniff'];

// =========================================================================
// 【ファイル配信エンドポイント (?serve_file=1)】
// ユーザーがアップロードしたテキストファイルを模したエンドポイント
// =========================================================================
if (isset($_GET['serve_file'])) {
    // サーバーは「これは普通のテキストファイルですよ」と宣言
    header('Content-Type: text/plain; charset=UTF-8');

    if ($sniffDefense) {
        // =========================================================================
        // 【TODO 2: MIMEスニッフィング防止ヘッダーの出力】
        // ブラウザが Content-Type (text/plain) を無視して
        // 勝手に JavaScript として推測・実行（スニッフィング）するのを防ぐヘッダーを出力してください。
        //
        // ヒント: X-Content-Type-Options ヘッダーに「スニッフィング禁止」を指定
        // =========================================================================
        // header('X-Content-Type-Options: ...');
        header('X-Content-Type-Options: nosniff');
    }

    // 中身にJavaScriptが書かれたテキストファイルを配信
    readfile(__DIR__ . '/fake_script.txt');
    exit;
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 3-4 (Part 2): MIMEスニッフィングと X-Content-Type-Options</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 20px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-warning { background: #fef9c3; color: #854d0e; }
        .alert-danger { background: #fee2e2; color: #991b1b; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-on { background: #22c55e; color: white; }
        .badge-off { background: #ef4444; color: white; }
        button { cursor: pointer; padding: 8px 16px; border-radius: 4px; border: none; font-weight: bold; }
        .btn-secondary { background: #64748b; color: white; }
        code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; }
        pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>

    <h1>Phase 3-4 (Part 2): MIMEスニッフィング演習</h1>

    <!-- コントロールパネル -->
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <strong>MIMEスニッフィング防御 (X-Content-Type-Options):</strong>
                <?php if ($sniffDefense): ?>
                    <span class="badge badge-on">ON (nosniff 有効)</span>
                <?php else: ?>
                    <span class="badge badge-off">OFF (脆弱: ヘッダー未設定)</span>
                <?php endif; ?>
            </div>
            <form method="POST" style="margin: 0;">
                <button type="submit" name="toggle_sniff" class="btn-secondary">
                    防御切替 (現在: <?= $sniffDefense ? 'ON' : 'OFF' ?>)
                </button>
            </form>
        </div>
    </div>

    <!-- 攻撃実証エリア -->
    <div class="card">
        <h2>📜 配信されるファイル (fake_script.txt) の情報</h2>
        <ul>
            <li>サーバーが返却する Content-Type: <code>text/plain; charset=UTF-8</code></li>
            <li>ファイルの実際の中身: <code>alert('⚠️ XSS成立！...');</code></li>
        </ul>

        <div class="alert alert-warning">
            <strong>実験内容:</strong><br>
            このページは、テキストファイルとして配信される <code>?serve_file=1</code> を <code>&lt;script src="..."&gt;</code> タグで読み込んでいます。<br>
            F12キーでブラウザの「デベロッパーツール（Consoleタブ）」を開いて挙動を確認してください。
        </div>

        <?php if (!$sniffDefense): ?>
            <p style="color: #dc2626; font-weight: bold;">
                ⚠️ 現在防御OFFです。ページを読み込むとブラウザがスニッフィングを行い、テキストファイルをJavaScriptとして実行してアラートが表示されます。
            </p>
        <?php else: ?>
            <p style="color: #16a34a; font-weight: bold;">
                🛡️ 現在防御ONです。ブラウザは Content-Type が text/plain であるためスクリプト実行を拒絶し、Consoleにエラーを出力します。
            </p>
        <?php endif; ?>

        <!-- 攻撃の再現: Content-Type: text/plain のファイルを script タグで読み込む -->
        <script src="3-4_sniff_lab.php?serve_file=1"></script>
    </div>

    <!-- 生ヘッダー確認用ガイド -->
    <div class="card">
        <h3>ターミナルからの生HTTPレスポンスヘッダー確認</h3>
        <pre>curl -i "http://localhost:8080/phase3/3-4_sniff_lab.php?serve_file=1" | head -n 10</pre>
    </div>

</body>
</html>
