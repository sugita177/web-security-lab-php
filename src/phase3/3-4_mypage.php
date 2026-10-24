<?php
session_start();

// 未ログインならログイン画面へリダイレクト
if (empty($_SESSION['logged_in_user'])) {
    header('Location: 3-4_login.php');
    exit;
}

// 防御モード管理（デフォルトOFF）
if (!isset($_SESSION['defense_mode_cache'])) {
    $_SESSION['defense_mode_cache'] = false;
}
if (isset($_POST['toggle_cache'])) {
    $_SESSION['defense_mode_cache'] = !$_SESSION['defense_mode_cache'];
    header('Location: 3-4_mypage.php');
    exit;
}

$cacheDefense = $_SESSION['defense_mode_cache'];

// =========================================================================
// 【機微情報のキャッシュ制御ヘッダー】（ユーザー実装反映）
// =========================================================================
if ($cacheDefense) {
    // 防御ON: 一切のキャッシュを禁止し、履歴からの復元を防ぐ
    header('Cache-Control: no-store, private');
    header('Pragma: no-cache');
    header('Expires: 0');
} else {
    // 防御OFF: キャッシュを許可（共有端末のディスクに保存されてしまう）
    header('Cache-Control: public, max-age=3600');
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 3-4: 会員マイページ（機微情報）</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 30px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-warning { background: #fef9c3; color: #854d0e; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-on { background: #22c55e; color: white; }
        .badge-off { background: #ef4444; color: white; }
        button { cursor: pointer; padding: 8px 16px; border-radius: 4px; border: none; font-weight: bold; }
        .btn-secondary { background: #64748b; color: white; }
        .btn-danger { background: #dc2626; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #e2e8f0; padding: 12px; text-align: left; }
        th { background: #f1f5f9; width: 30%; }
        code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; }
        pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>

    <!-- コントロールパネル -->
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <strong>キャッシュ防御モード (Cache-Control):</strong>
                <?php if ($cacheDefense): ?>
                    <span class="badge badge-on">ON (no-store, private 出力中)</span>
                <?php else: ?>
                    <span class="badge badge-off">OFF (脆弱: public, max-age=3600)</span>
                <?php endif; ?>
            </div>
            <div style="display: flex; gap: 8px;">
                <a href="3-4_mypage.php" class="btn-secondary" style="text-decoration: none; padding: 8px 16px; border-radius: 4px; display: inline-block;">
                    🔄 リンククリックで再表示
                </a>
                <form method="POST" style="margin: 0;">
                    <button type="submit" name="toggle_cache" class="btn-secondary">
                        防御モード切替 (現在: <?= $cacheDefense ? 'ON' : 'OFF' ?>)
                    </button>
                </form>
            </div>
        </div>
    </div>

    <!-- マイページカード -->
    <div class="card" style="border-top: 4px solid #2563eb;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h2>👤 会員マイページ（機微情報）</h2>
            <a href="3-4_login.php?action=logout" class="btn-danger">ログアウト</a>
        </div>

        <div class="alert alert-warning" style="margin-top: 15px;">
            ⚠️ <strong>検証手順:</strong><br>
            1. 右上の赤い「ログアウト」ボタンを押します。<br>
            2. ログイン画面に遷移したら、<strong>ブラウザの「戻る（←）」ボタン</strong>を押してください！<br>
            ・防御OFF: ブラウザキャッシュから、この個人情報画面がそのまま表示されてしまいます。<br>
            ・防御ON: `no-store` のためキャッシュが残らず、未ログインとしてログイン画面へ押し戻されます。
        </div>

        <div style="display: flex; align-items: center; gap: 15px; margin: 15px 0;">
            <img src="3-4_avatar.php" alt="アバター画像" style="border: 2px solid #cbd5e1; border-radius: 50%; padding: 4px; background: #f8fafc;">
            <div>
                <strong style="font-size: 1.1em;">山田 太郎（yamada_taro）様</strong><br>
                <small style="color: #64748b;">※ このアイコン画像 (<code>3-4_avatar.php</code>) の Network タブ Size 列を観察してください</small>
            </div>
        </div>

        <table>
            <tr><th>会員氏名</th><td>山田 太郎（yamada_taro）様</td></tr>
            <tr><th>登録メールアドレス</th><td>taro.yamada@example.com</td></tr>
            <tr><th>クレジットカード番号</th><td><strong>4532-XXXX-XXXX-8899</strong> (有効期限: 12/28)</td></tr>
            <tr><th>預金残高</th><td><strong style="color: #16a34a; font-size: 1.2em;">¥1,250,000</strong></td></tr>
            <tr><th>ご登録住所</th><td>東京都千代田区千代田1-1</td></tr>
        </table>
    </div>

    <!-- 生ヘッダー確認ガイド -->
    <div class="card">
        <h3>ターミナルからの生HTTPヘッダー確認</h3>
        <pre>curl -i http://localhost:8080/phase3/3-4_mypage.php | grep -iE "(HTTP/|Cache-Control|Pragma|Expires)"</pre>
    </div>

    <?php if ($cacheDefense): ?>
        <!-- 【防御ON時のみ動作】現代ブラウザのbfcache（メモリ復元）を検知し、強制再検証を実行 -->
        <script>
            window.addEventListener('pageshow', function(event) {
                // event.persisted が true の場合、または navigation.type が back_forward の場合、
                // ブラウザが通信を行わずにメモリから画面を復元したことを意味する
                const nav = window.performance.getEntriesByType ? window.performance.getEntriesByType('navigation') : [];
                const isBackForward = nav.length > 0 && nav[0].type === 'back_forward';

                if (event.persisted || isBackForward) {
                    // キャッシュ復元を検知したら、強制的にサーバーへ最新状態を問い合わせる
                    window.location.reload();
                }
            });
        </script>
    <?php endif; ?>

</body>
</html>
