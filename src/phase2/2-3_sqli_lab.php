<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');

// データベース接続（PDO）
$dbHost = 'mysql';
$dbName = 'security_lab';
$dbUser = 'lab_user';
$dbPass = 'lab_password';

try {
    $pdo = new PDO(
        "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
        $dbUser,
        $dbPass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false, // ネイティブプリペア強制
        ]
    );
} catch (PDOException $e) {
    die("DB接続エラー (MySQL起動待ちの可能性があります。数秒後にリロードしてください): " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
}

$section = $_GET['section'] ?? 'login'; // 'login', 'search', 'sort'
$protectMode = isset($_GET['protect']); // 防御モード（プリペア・ホワイトリスト）のトグル

// =============================================================================
// 1. 認証機能（SQLi による認証回避の実験）
// =============================================================================
$loginMessage = '';
$loggedInUser = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $section === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if ($protectMode) {
        // =====================================================================
        // TODO 1: プリペアドステートメントを使って安全にログイン照合を行ってください
        // 要件:
        //   - $pdo->prepare() と プレースホルダー（:username, :password）を使用
        //   - $stmt->execute() でパラメータをバインド
        //   - $stmt->fetch() で一致するユーザーを取得
        // =====================================================================
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
        $stmt->execute([
            ':username' => $username,
            ':password' => $password,
        ]);
        $loggedInUser = $stmt->fetch();

    } else {
        // 【危険な実装】文字列結合によるSQL構築（SQLインジェクション脆弱性あり）
        $sql = "SELECT * FROM users WHERE username = '{$username}' AND password = '{$password}'";
        try {
            $stmt = $pdo->query($sql);
            $loggedInUser = $stmt->fetch();
        } catch (PDOException $e) {
            $loginMessage = "SQLエラー発生: " . $e->getMessage();
        }
    }

    if ($loggedInUser) {
        $loginMessage = "【ログイン成功！】ようこそ {$loggedInUser['username']} 様 (権限: {$loggedInUser['role']})<br>秘密情報: {$loggedInUser['secret_api_key']}";
    } elseif (!$loginMessage) {
        $loginMessage = "ユーザー名またはパスワードが違います。";
    }
}

// =============================================================================
// 2. 商品検索（UNION ベースの秘密情報漏洩実験）
// =============================================================================
$searchResults = [];
$searchQuery = $_GET['q'] ?? '';

if ($searchQuery !== '' && $section === 'search') {
    if ($protectMode) {
        // =====================================================================
        // TODO 2: プリペアドステートメントを使って安全に LIKE 検索を行ってください
        // 要件:
        //   - カラム: id, name, price, stock, category
        //   - LIKE 検索のワイルドカード `%` は SQL文ではなく「パラメータ値」側で結合すること！
        //     ヒント: $stmt->execute([':keyword' => "%{$searchQuery}%"])
        // =====================================================================
        $stmt = $pdo->prepare("SELECT id, name, price, stock, category FROM products WHERE name LIKE :keyword");
        $stmt->execute([
            ':keyword' => "%{$searchQuery}%",
        ]);
        $searchResults = $stmt->fetchAll();

    } else {
        // 【危険な実装】文字列結合によるLIKE検索（UNION SQLi 脆弱性あり）
        $sql = "SELECT id, name, price, stock, category FROM products WHERE name LIKE '%{$searchQuery}%'";
        try {
            $stmt = $pdo->query($sql);
            $searchResults = $stmt->fetchAll();
        } catch (PDOException $e) {
            $searchError = "SQLエラー: " . $e->getMessage();
        }
    }
}

// =============================================================================
// 3. 商品ソート（プレースホルダーが使えない箇所のホワイトリスト検証実験）
// =============================================================================
$sortColumn = $_GET['sort'] ?? 'price';
$sortOrder = $_GET['order'] ?? 'ASC';

if ($section === 'sort') {
    if ($protectMode) {
        // =====================================================================
        // TODO 3: ホワイトリスト検証を行い、安全に動的ソートを実装してください
        // 要件:
        //   - 許可するカラム名: 'price', 'stock', 'name'
        //   - 許可する並び順: 'ASC', 'DESC'
        //   - 許可リスト外の値が渡された場合は、デフォルト値（'price', 'ASC'）に安全にフォールバックすること
        // =====================================================================
        $permittedColumns = ['price', 'stock', 'name'];
        $permittedOrders = ['ASC', 'DESC'];

        $sortColumn = in_array($sortColumn, $permittedColumns) ? $sortColumn : 'price';
        $sortOrder = in_array($sortOrder, $permittedOrders) ? $sortOrder : 'ASC';

        $stmt = $pdo->prepare("SELECT * FROM products ORDER BY {$sortColumn} {$sortOrder}");
        $stmt->execute();
        $sortResults = $stmt->fetchAll();

    } else {
        // 【危険な実装】ユーザー入力をそのまま ORDER BY に直接結合
        $sql = "SELECT * FROM products ORDER BY {$sortColumn} {$sortOrder}";
        try {
            $stmt = $pdo->query($sql);
            $sortResults = $stmt->fetchAll();
        } catch (PDOException $e) {
            $sortError = "SQLエラー: " . $e->getMessage();
        }
    }
}

function h(string $str): string {
    return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 2-3: SQLインジェクション（SQLi）実験室</title>
    <style>
        body { font-family: sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }
        .box { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 15px; font-weight: bold; }
        .alert-success { background: #dcfce7; color: #15803d; }
        .alert-danger { background: #fee2e2; color: #b91c1c; }
        .btn { padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-danger { background: #dc2626; }
        .nav a { margin-right: 15px; font-weight: bold; text-decoration: none; color: #2563eb; }
        .nav a.active { text-decoration: underline; color: #0f172a; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; }
        th { background: #f1f5f9; }
        code { background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
        input[type="text"], input[type="password"] { padding: 6px; border: 1px solid #cbd5e1; border-radius: 4px; width: 300px; }
    </style>
</head>
<body>
    <h1>Phase 2-3: SQLインジェクション（SQLi）実験室</h1>

    <div class="box">
        <h2>ナビゲーション & 防御モード設定</h2>
        <p class="nav">
            <a href="?section=login<?= $protectMode ? '&protect=1' : '' ?>" class="<?= $section === 'login' ? 'active' : '' ?>">1. 認証回避（ログイン）</a>
            <a href="?section=search<?= $protectMode ? '&protect=1' : '' ?>" class="<?= $section === 'search' ? 'active' : '' ?>">2. 情報漏洩（UNION 検索）</a>
            <a href="?section=sort<?= $protectMode ? '&protect=1' : '' ?>" class="<?= $section === 'sort' ? 'active' : '' ?>">3. ORDER BY ソート（ホワイトリスト）</a>
        </p>
        <hr style="border: none; border-top: 1px solid #cbd5e1; margin: 15px 0;">
        <p>
            現在の状態: 
            <?php if ($protectMode): ?>
                <strong style="color: #15803d;">🛡️ 防御モード（プリペアドステートメント / ホワイトリスト）</strong>
                <a class="btn btn-danger" style="margin-left: 15px;" href="?section=<?= h($section) ?>">脆弱モードに切り替え</a>
            <?php else: ?>
                <strong style="color: #dc2626;">⚠️ 脆弱モード（文字列結合による直接組み立て）</strong>
                <a class="btn" style="margin-left: 15px;" href="?section=<?= h($section) ?>&protect=1">防御モードに切り替え</a>
            <?php endif; ?>
        </p>
    </div>

    <?php if ($section === 'login'): ?>
        <!-- 1. 認証回避実験 -->
        <div class="box">
            <h2>1. ログイン画面（認証回避の実験）</h2>
            <?php if ($loginMessage): ?>
                <div class="alert <?= $loggedInUser ? 'alert-success' : 'alert-danger' ?>"><?= $loginMessage ?></div>
            <?php endif; ?>

            <form method="POST" action="?section=login<?= $protectMode ? '&protect=1' : '' ?>">
                <p>ユーザー名: <input type="text" name="username" value="<?= h($_POST['username'] ?? '') ?>" required></p>
                <p>パスワード: <input type="password" name="password" value="" placeholder="パスワード"></p>
                <button type="submit" class="btn">ログイン</button>
            </form>

            <div style="margin-top: 20px; font-size: 0.9em; color: #64748b; background: #f8fafc; padding: 10px; border-left: 4px solid #3b82f6;">
                <strong>💡 攻撃のヒント（認証回避ペイロード）:</strong><br>
                ・<strong>方法 A（コメントアウト）</strong>: ユーザー名に <code>admin' -- </code>（※末尾に半角スペース必須）と入力し、パスワード空欄でログイン！<br>
                　（後ろの <code>AND password = ...</code> が無効化され、管理者認証を突破できます）<br>
                ・<strong>方法 B（OR条件の注入）</strong>: パスワード欄に <code>' OR '1'='1</code> と入力してログイン！<br>
                　（SQLの演算子順位により <code>AND</code> が優先されるため、パスワード側に入れることで全体を <code>true</code> にできます）
            </div>

        </div>
    <?php elseif ($section === 'search'): ?>
        <!-- 2. UNION 攻撃実験 -->
        <div class="box">
            <h2>2. 商品検索（UNION ベースの情報漏洩実験）</h2>
            <form method="GET" action="">
                <input type="hidden" name="section" value="search">
                <?php if ($protectMode): ?><input type="hidden" name="protect" value="1"><?php endif; ?>
                <input type="text" name="q" value="<?= h($searchQuery) ?>" placeholder="商品名を入力 (例: 本)">
                <button type="submit" class="btn">検索</button>
            </form>

            <?php if (isset($searchError)): ?>
                <div class="alert alert-danger"><?= h($searchError) ?></div>
            <?php endif; ?>

            <?php if (!empty($searchResults)): ?>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>商品名</th>
                        <th>価格</th>
                        <th>在庫</th>
                        <th>カテゴリ</th>
                    </tr>
                    <?php foreach ($searchResults as $r): ?>
                        <tr>
                            <td><?= h((string)$r['id']) ?></td>
                            <td><?= h((string)$r['name']) ?></td>
                            <td><?= h((string)$r['price']) ?></td>
                            <td><?= h((string)$r['stock']) ?></td>
                            <td><?= h((string)$r['category']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            <?php endif; ?>

            <div style="margin-top: 20px; font-size: 0.9em; color: #64748b; background: #f8fafc; padding: 10px; border-left: 4px solid #3b82f6;">
                <strong>💡 攻撃のヒント（UNION情報漏洩ペイロード）:</strong><br>
                検索欄に以下を入力して検索してみてください：<br>
                <code>' UNION SELECT id, username, 0, 0, secret_api_key FROM users -- a</code><br>
                （※末尾の <code>-- a</code> は後ろの <code>%'</code> を確実にコメントアウトするための記述です）<br>
                商品一覧の画面に、本来見えてはいけない <strong>usersテーブルの管理者秘密APIキー</strong> が流出します！
            </div>

        </div>
    <?php elseif ($section === 'sort'): ?>
        <!-- 3. 動的ソート実験 -->
        <div class="box">
            <h2>3. 商品一覧（ORDER BY 動的ソート実験）</h2>
            <p>
                並び替え: 
                <a href="?section=sort&sort=price&order=ASC<?= $protectMode ? '&protect=1' : '' ?>">価格が安い順</a> | 
                <a href="?section=sort&sort=price&order=DESC<?= $protectMode ? '&protect=1' : '' ?>">価格が高い順</a> | 
                <a href="?section=sort&sort=stock&order=DESC<?= $protectMode ? '&protect=1' : '' ?>">在庫が多い順</a>
            </p>

            <?php if (isset($sortError)): ?>
                <div class="alert alert-danger"><?= h($sortError) ?></div>
            <?php endif; ?>

            <?php if (!empty($sortResults)): ?>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>商品名</th>
                        <th>価格</th>
                        <th>在庫</th>
                        <th>カテゴリ</th>
                    </tr>
                    <?php foreach ($sortResults as $r): ?>
                        <tr>
                            <td><?= h((string)$r['id']) ?></td>
                            <td><?= h((string)$r['name']) ?></td>
                            <td><?= number_format((int)$r['price']) ?> 円</td>
                            <td><?= h((string)$r['stock']) ?> 個</td>
                            <td><?= h((string)$r['category']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            <?php endif; ?>

            <div style="margin-top: 20px; font-size: 0.9em; color: #64748b; background: #f8fafc; padding: 10px; border-left: 4px solid #3b82f6;">
                <strong>💡 攻撃のヒント（SQL構文注入 / 条件分岐インジェクション）:</strong><br>
                URLの <code>sort</code> パラメータに以下を直接入力してみてください：<br>
                <code>?section=sort&sort=(CASE+WHEN+(SELECT+1)=1+THEN+price+ELSE+stock+END)&order=ASC</code><br>
                プレースホルダーが効かない箇所で任意のSQL式が実行される危険を体験できます。
            </div>
        </div>
    <?php endif; ?>
</body>
</html>
