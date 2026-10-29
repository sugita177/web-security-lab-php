# Phase 5-1: 認可制御の不備（BOLA / IDOR / 垂直昇格）

## 1. 背景と脅威シナリオ

### ① 「認証」と「認可」の決定的な違い
Webアプリケーションのセキュリティにおいて、最も混同されやすく重大な事故を引き起こすのが「認証」と「認可」の境界です。

- **認証（Authentication: Who are you?）**:
  「あなたは誰か？」を確認するプロセス（ID/パスワード、多要素認証、セッション確認）。
- **認可（Authorization: What can you do?）**:
  「そのデータへのアクセスや操作が許可されているか？」を判定するプロセス（リソース所有権、ロール・権限の検証）。

### ② 水平権限昇格（IDOR / BOLA）
- **概要**:
  同等の権限を持つ一般ユーザー同士の間で、他人のリソースID（URLのパラメータやリクエスト本文）を書き換えるだけで他人の機密データを盗み見たり改ざんできてしまう脆弱性（Insecure Direct Object Reference / Broken Object Level Authorization）。
- **脅威シナリオ**:
  ユーザーAlice（ID: 1）がログインし、自分の領収書 `order_id=101` を閲覧した。ここでURLを `order_id=103`（ユーザーBobの注文）に書き換えた際、サーバー側が「Aliceはログイン済みだからOK」とだけ判定し、所有者確認を行わないと、Bobの機密医療データや配送先住所が丸見えになる。

### ③ 垂直権限昇格（Vertical Privilege Escalation）
- **概要**:
  一般ユーザーが、管理者（Admin）などの上位権限者専用の機能やAPIエンドポイントを不正に実行できてしまう脆弱性。
- **脅威シナリオ**:
  一般ユーザー向け画面にはリンクがなくても、管理画面のURL（`/admin/delete_order`）や管理者専用パラメータを直接リクエストすることで、一般ユーザーが他人のデータを一括削除したり、システム設定を書き換えてしまう。

---

## 2. 脆弱な実装と安全な実装の比較

### ① 水平権限昇格（IDOR）の防御パターン比較

#### ❌ 脆弱なパターン（認可の欠落）
```php
// 注文IDだけで検索し、所有権（user_id）を全く考慮しない
$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = :order_id");
$stmt->execute([':order_id' => $requestedOrderId]);
$order = $stmt->fetch();
```

#### ⚠️ パターンB（アプリ層での後チェック）
```php
$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = :order_id");
$stmt->execute([':order_id' => $requestedOrderId]);
$order = $stmt->fetch();

// 取得後にPHPのif文で比較
if ($order && $order['user_id'] === $currentUser['id']) {
    return $order;
}
```
*デメリット*: 開発者が後から `if` 文のチェックを書き忘れるヒューマンエラーが発生しやすい。また、403（権限なし）と404（存在しない）の差異で「その注文IDが実在するか」を攻撃者に特定されるリスクがある。

#### ⭕ パターンC（SQLレベルでの認可強制 ★推奨）
```php
// 検索条件自体に「ログイン中ユーザーID」を必ず含める
$stmt = $pdo->prepare(
    "SELECT * FROM orders WHERE id = :order_id AND user_id = :user_id"
);
$stmt->execute([
    ':order_id' => $requestedOrderId,
    ':user_id' => $currentUser['id'] // セッションから取得
]);
$order = $stmt->fetch();
```
*メリット*:
- DB層で他人のデータを1行も抽出しないため、チェック忘れの事故が構造的に起きない。
- LaravelなどのORMでも `Auth::user()->orders()->findOrFail($orderId)` として標準推奨されている設計思想。

---

### ② 垂直権限昇格の防御（ロールベース認可: RBAC）

```php
// ❌ 脆弱な実装（ログイン確認のみでロールを見ていない）
if (isset($_SESSION['user'])) {
    deleteOrder($targetId);
}

// ⭕ 安全な実装（ロールの厳格な検証）
$isAdmin = ($currentUser !== null && $currentUser['role'] === 'admin');
if ($isAdmin) {
    deleteOrder($targetId);
} else {
    http_response_code(403);
    die("管理者権限が必要です。");
}
```

---

## 3. 実験と検証結果

| 攻撃シナリオ | 操作内容 | モード A (脆弱) | モード B (安全) |
| :--- | :--- | :--- | :--- |
| **水平昇格 (IDOR)** | Aliceログイン中に Bobの極秘注文（#103）を閲覧 | 🚨 **他者データ漏洩**（Bobの機密医療データが丸見え） | 🛡️ **遮断成功**（「注文は存在しないか、閲覧権限がありません」として404/拒絶） |
| **垂直昇格** | 一般ユーザー（Alice/Bob）で管理者専用「注文削除API」を実行 | 🚨 **不正実行成功**（一般権限で注文が削除されてしまう） | 🛡️ **遮断成功**（HTTP 403 Forbidden「管理者権限が必要です」で遮断） |
| **正規管理者操作** | 管理者（Admin）で注文削除を実行 | ✅ 正常実行 | ✅ 正常実行（管理者権限が確認され削除完了） |

---

## 4. プロとして知っておくべき実務設計の原則

1. **URLやリクエストパラメータのユーザーIDを信用しない**:
   - `order_detail.php?order_id=101&user_id=1` のように、クライアントから `user_id` を渡させる設計は絶対に避ける。
   - ユーザーIDは必ず **サーバー側のセッション（認証済みトークン）** から直接取得する。
2. **IDのランダム化（UUID v4 / ULIDの採用）**:
   - 連番のID（`101`, `102`, `103`）は攻撃者に「104, 105もあるのでは？」と総当たり探索（クローリング）を許す。
   - パブリックに露出するIDには予測困難な `UUID v4`（例: `f47ac10b-58cc-4372-a567-0e02b2c3d479`）を採用することで、探索攻撃の難易度を大幅に引き上げる（※ただしUUID化しても認可チェック自体は必須）。

