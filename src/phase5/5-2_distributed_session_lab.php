<?php
declare(strict_types=1);

// モード管理（デフォルト: files）
$storageMode = $_GET['storage'] ?? 'files';
if (!in_array($storageMode, ['files', 'redis'], true)) {
    $storageMode = 'files';
}

$message = '';
$messageType = '';

// =============================================================================
// 【課題 1: SessionHandlerInterface を用いた Redis セッションハンドラーの自作実装】
// =============================================================================

/**
 * Redis を利用したカスタムセッションハンドラー
 *
 * PHPの標準インターフェース SessionHandlerInterface を実装し、
 * session_start() 時の読み書き先をローカルファイルから Redis に切り替えます。
 */
class RedisSessionHandler implements SessionHandlerInterface {
    private ?Redis $redis = null;
    private string $host;
    private int $port;
    private int $ttl;
    private string $prefix;

    public function __construct(string $host = 'redis', int $port = 6379, int $ttl = 3600, string $prefix = 'sess:') {
        $this->host = $host;
        $this->port = $port;
        $this->ttl = $ttl;
        $this->prefix = $prefix;
    }

    /**
     * セッションの初期化処理
     * session_start() 呼び出し時に最初に実行されます。
     */
    public function open(string $path, string $name): bool {
        try {
            $this->redis = new Redis();
            return $this->redis->connect($this->host, $this->port);
        } catch (Throwable $e) {
            error_log("Redis connection error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * セッションのクローズ処理
     */
    public function close(): bool {
        if ($this->redis) {
            $this->redis->close();
            $this->redis = null;
        }
        return true;
    }

    /**
     * 【TODO 1-A: read メソッドを実装してください】
     *
     * 【要件】
     * 1. セッションID ($id) にプレフィックス ($this->prefix) を付与したキーで Redis から値を取得してください。
     * 2. キーが存在しない場合は、必ず空文字列 ("") を返してください（nullやfalseを返してはなりません）。
     *    ※ PHPの仕様上、データが存在しないときは空文字 "" を返す必要があります。
     */
    public function read(string $id): string|false {
        if (!$this->redis) return '';

        // =====================================================================
        // ここに Redis からセッション文字列を取得するロジックを実装してください
        // =====================================================================

        $key = $this->prefix . $id;
        $data = $this->redis->get($key);
        // false または null の場合は空文字 "" を返す
        return ($data === false || $data === null) ? '' : (string)$data;
    }

    /**
     * 【TODO 1-B: write メソッドを実装してください】
     *
     * 【要件】
     * 1. セッションID ($id) にプレフィックス ($this->prefix) を付与したキーで、
     *    シリアライズされたセッションデータ ($data) を Redis に保存してください。
     * 2. 保存時には有効期限 ($this->ttl) を設定してください（SETEX コマンド）。
     *    例: $this->redis->setex($key, $this->ttl, $data);
     */
    public function write(string $id, string $data): bool {
        if (!$this->redis) return false;

        // =====================================================================
        // ここに Redis へTTL付きでセッションデータを保存するロジックを実装してください
        // =====================================================================

        $key = $this->prefix . $id;
        $this->redis->setex($key, $this->ttl, $data);
        return true;
    }

    /**
     * 【TODO 1-C: destroy メソッドを実装してください】
     *
     * 【要件】
     * 1. ユーザーがログアウト（session_destroy()）した際に呼び出されます。
     * 2. 対象のセッションキー（$this->prefix . $id）を Redis から削除（DEL コマンド）してください。
     */
    public function destroy(string $id): bool {
        if (!$this->redis) return false;

        // =====================================================================
        // ここに Redis からキーを削除するロジックを実装してください
        // =====================================================================

        $key = $this->prefix . $id;
        $this->redis->del($key);
        return true;
    }

    /**
     * ガベージコレクション（古いセッションのお掃除）
     * Redis では SETEX により TTL が切れたキーは自動消去されるため、PHP側でのお掃除は不要です。
     */
    public function gc(int $max_lifetime): int|false {
        return 0; // Redis の自動消去（TTL）に任せるため 0 を返す
    }
}

// モードに応じたセッションハンドラーの登録
if ($storageMode === 'redis') {
    $customHandler = new RedisSessionHandler('redis', 6379, 1800, 'sess:');
    // PHP標準のセッションハンドラーとして登録
    session_set_save_handler($customHandler, true);
}

// セッションの開始
session_start();

// セッション操作アクション
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ① ログイン・データ書き込みアクション
    if (isset($_POST['login'])) {
        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $_POST['username'] ?? 'guest';
        $_SESSION['login_time'] = date('Y-m-d H:i:s');
        $_SESSION['access_count'] = ($_SESSION['access_count'] ?? 0) + 1;
        $message = "セッションにユーザーデータを書き込みました！（ログイン成功）";
        $messageType = "success";
    }

    // ② カウンターインクリメント
    if (isset($_POST['increment'])) {
        $_SESSION['access_count'] = ($_SESSION['access_count'] ?? 0) + 1;
        $message = "アクセス回数を更新しました！（現在のカウント: {$_SESSION['access_count']}）";
        $messageType = "success";
    }

    // ③ ログアウト（session_destroy 実行）
    if (isset($_POST['logout'])) {
        $_SESSION = [];
        session_destroy();
        header("Location: 5-2_distributed_session_lab.php?storage={$storageMode}");
        exit;
    }

    // ④ 【セキュリティ機能】管理者によるセッション強制破棄（集中無効化）
    if (isset($_POST['revoke_from_redis'])) {
        try {
            $r = new Redis();
            $r->connect('redis', 6379);
            $key = 'sess:' . session_id();
            $r->del($key);
            // 【ポイント】スクリプト終了時に再度 write() されてキーが復活するのを防ぐため、
            // メモリ上のセッションを空にし、セッションを破棄します
            $_SESSION = [];
            session_destroy();
            $message = "Redis上のセッションキー（{$key}）を外部から強制削除しました！次回アクセス時に即座にログアウトされます。";
            $messageType = "danger";
        } catch (Throwable $e) {
            $message = "Redisエラー: " . $e->getMessage();
            $messageType = "danger";
        }
    }
}

// =====================================================================
// 表示用のストレージ生データを取得する前に、最新の $_SESSION を
// ストレージに即座に書き込んで確定させます
// =====================================================================
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}
// 現在のストレージ情報の取得（可視化用）
$currentSessionId = session_id();
$storageDetails = [];

if ($storageMode === 'files') {
    $savePath = session_save_path() ?: sys_get_temp_dir();
    $filePath = $savePath . '/sess_' . $currentSessionId;
    $exists = file_exists($filePath);
    $content = $exists ? file_get_contents($filePath) : false;

    $storageDetails['type'] = 'ローカルファイルシステム (単一サーバー依存)';
    $storageDetails['location'] = $filePath;
    $storageDetails['exists'] = $exists;
    if (!$exists) {
        $storageDetails['raw_content'] = '(未作成 / ファイルなし)';
    } elseif ($content === '' || $content === false) {
        $storageDetails['raw_content'] = '(空 / セッションデータなし)';
    } else {
        $storageDetails['raw_content'] = $content;
    }
    $storageDetails['ttl'] = 'PHPのgc_probabilityによる確率的掃除';
} else {
    try {
        $r = new Redis();
        $r->connect('redis', 6379);
        $key = 'sess:' . $currentSessionId;
        $exists = (bool)$r->exists($key);
        $ttl = $r->ttl($key);
        $raw = $r->get($key);

        $storageDetails['type'] = '分散インメモリKVS (Redis: 複数サーバー間で共有可能)';
        $storageDetails['location'] = "Redis key [ {$key} ]";
        $storageDetails['exists'] = $exists;
        if (!$exists || $raw === false || $raw === null) {
            $storageDetails['raw_content'] = '(未作成 / キーなし)';
        } elseif ($raw === '') {
            $storageDetails['raw_content'] = '(空 / セッションデータなし)';
        } else {
            $storageDetails['raw_content'] = $raw;
        }
        $storageDetails['ttl'] = $exists ? "{$ttl} 秒 (自動消去)" : '未設定';
    } catch (Throwable $e) {
        $storageDetails['type'] = 'Redis接続エラー';
        $storageDetails['error'] = $e->getMessage();
    }
}

?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 5-2: 分散環境でのセッション外部ストア化（Redis）演習</title>
    <style>
        body { font-family: sans-serif; max-width: 950px; margin: 30px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 22px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-files { background: #f59e0b; color: white; }
        .badge-redis { background: #dc2626; color: white; }
        .alert { padding: 14px; border-radius: 6px; margin-bottom: 15px; }
        .alert-success { background: #dcfce7; border-left: 5px solid #16a34a; color: #166534; }
        .alert-danger { background: #fee2e2; border-left: 5px solid #dc2626; color: #991b1b; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.95em; }
        th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }
        th { background: #f1f5f9; width: 30%; }
        pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; }
        .btn { display: inline-block; padding: 8px 16px; border-radius: 4px; text-decoration: none; font-weight: bold; font-size: 0.9em; cursor: pointer; border: none; }
        .btn-primary { background: #2563eb; color: white; }
        .btn-danger { background: #dc2626; color: white; }
        .btn-secondary { background: #64748b; color: white; }
        .btn-success { background: #16a34a; color: white; }
    </style>
</head>
<body>

    <h1>Phase 5-2: 分散環境でのセッション外部ストア化（Redis）演習</h1>
    <p>PHP標準の <code>SessionHandlerInterface</code> を自作実装し、複数サーバーでセッションを共有＆集中強制破棄できる仕組みを検証します。</p>

    <!-- モード切り替え -->
    <div class="card">
        <h3>現在のセッション保存先ストレージ:
            <?php if ($storageMode === 'files'): ?>
                <span class="badge badge-files">モード A: ローカルファイル (Files - 非分散)</span>
            <?php else: ?>
                <span class="badge badge-redis">モード B: 外部ストア (Redis - 分散対応)</span>
            <?php endif; ?>
        </h3>
        <p>
            ストレージ切り替え:
            <a href="?storage=files" class="btn <?= $storageMode === 'files' ? 'btn-secondary' : 'btn-primary' ?>" style="<?= $storageMode === 'files' ? 'opacity:0.6; pointer-events:none;' : '' ?>">モード A (ローカルファイル) に切替</a>
            <a href="?storage=redis" class="btn <?= $storageMode === 'redis' ? 'btn-secondary' : 'btn-danger' ?>" style="<?= $storageMode === 'redis' ? 'opacity:0.6; pointer-events:none;' : '' ?>">モード B (自作 Redis ハンドラー) に切替</a>
        </p>
    </div>

    <!-- 通知メッセージ -->
    <?php if (!empty($message)): ?>
        <div class="alert alert-<?= $messageType ?>">
            <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <!-- セッションの内部状態・ストレージ可視化エリア -->
    <div class="card">
        <h3>🔍 セッションの内部状態とストレージ実体</h3>
        <table>
            <tr>
                <th>セッションID (<code>session_id()</code>)</th>
                <td><code><?= htmlspecialchars($currentSessionId, ENT_QUOTES, 'UTF-8') ?></code></td>
            </tr>
            <tr>
                <th>ストレージ種別</th>
                <td><strong><?= htmlspecialchars($storageDetails['type'] ?? '', ENT_QUOTES, 'UTF-8') ?></strong></td>
            </tr>
            <tr>
                <th>データの物理保存場所</th>
                <td><code><?= htmlspecialchars($storageDetails['location'] ?? '', ENT_QUOTES, 'UTF-8') ?></code></td>
            </tr>
            <tr>
                <th>ストレージ上の存在</th>
                <td>
                    <?php if (!empty($storageDetails['exists'])): ?>
                        <span style="color: #16a34a; font-weight: bold;">🟢 存在します (データ保存中)</span>
                    <?php else: ?>
                        <span style="color: #94a3b8;">⚪ 未作成 / 破棄済み</span>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th>有効期限 (TTL)</th>
                <td><?= htmlspecialchars((string)($storageDetails['ttl'] ?? ''), ENT_QUOTES, 'UTF-8') ?></td>
            </tr>
            <tr>
                <th>ストレージ内の生データ (Raw Payload)</th>
                <td><pre style="margin: 0;"><?= htmlspecialchars((string)($storageDetails['raw_content'] ?? ''), ENT_QUOTES, 'UTF-8') ?></pre></td>
            </tr>
        </table>
    </div>

    <!-- セッション操作パネル -->
    <div class="card">
        <h3>🎮 セッション操作パネル</h3>
        <p>現在の <code>$_SESSION</code> の内容:</p>
        <pre><?= htmlspecialchars(print_r($_SESSION, true), ENT_QUOTES, 'UTF-8') ?></pre>

        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-top: 15px;">
            <!-- ログインフォーム -->
            <form method="POST" style="margin: 0; display: flex; gap: 5px;">
                <input type="hidden" name="username" value="alice_session_user">
                <button type="submit" name="login" class="btn btn-primary">
                    🔑 ログイン（データ書き込み）
                </button>
            </form>

            <!-- カウント更新フォーム -->
            <form method="POST" style="margin: 0;">
                <button type="submit" name="increment" class="btn btn-success">
                    ➕ アクセスカウント更新
                </button>
            </form>

            <!-- ログアウトフォーム -->
            <form method="POST" style="margin: 0;">
                <button type="submit" name="logout" class="btn btn-secondary">
                    🚪 ログアウト (session_destroy)
                </button>
            </form>

            <?php if ($storageMode === 'redis'): ?>
                <!-- Redis 外部強制削除（集中無効化） -->
                <form method="POST" style="margin: 0;">
                    <button type="submit" name="revoke_from_redis" class="btn btn-danger" onclick="return confirm('Redisからキーを直接強制削除しますか？');">
                        ⚡ 【集中管理】Redisからセッションを強制剥奪 (Revoke)
                    </button>
                </form>
            <?php endif; ?>
        </div>
    </div>

</body>
</html>

