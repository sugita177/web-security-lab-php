# Phase 3-3: クリックジャッキングとオープンリダイレクト

## 1. 背景と脅威シナリオ

### ① クリックジャッキング（UI Redressing: 画面着せ替え攻撃）
- **概要**:
  攻撃者が用意した罠ページ上に、被害者のログイン中サイト（例: 送金画面、重要設定変更、SNSのフォローボタン）を `<iframe>` で透明（`opacity: 0`）に重ね合わせる攻撃。
- **脅威**:
  ユーザーは「ゲームのボタン」や「ギフト券を受け取る」をクリックしているつもりで、実際には背後に隠された本物サイトの「全ポイント寄付」「アカウント削除」ボタンをクリックさせられてしまう。
- **防御策**:
  - レガシーヘッダー: `X-Frame-Options: DENY` または `SAMEORIGIN`
  - 現代的標準: CSP `Content-Security-Policy: frame-ancestors 'none';` または `'self'`
  ※ 複数ドメインや提携先のみを許可したい場合、`X-Frame-Options: ALLOW-FROM` は非推奨・廃止されたため、W3C標準の CSP `frame-ancestors` の使用が強く推奨される。

### ② オープンリダイレクト（Open Redirect）
- **概要**:
  「ログイン後に元のページに戻す」などの目的で、URLパラメータ（例: `?return_to=https://evil.com`）でリダイレクト先を受け取り、検証なしに `header("Location: " . $url)` で外部サイトへ転送してしまう脆弱性。
- **脅威**:
  攻撃者は `https://target.com/login?return_to=https://evil-phishing.com` という、ドメイン自体は完全な正規サイトのリンクを作成し、フィッシングメール等で被害者に踏ませる。
  被害者は正規サイトで安心してログインするが、ログイン完了直後に自動的に攻撃者の偽サイトへ飛ばされ、更なる機微情報（クレジットカード情報や二段階認証コードなど）を詐取される。
- **防御策**:
  - **相対パス限定**: `/` で始まり、かつ `//` で始まらないことの厳格な検証。
  - **ホワイトリスト検証**: 外部ドメインを許可する場合は、`parse_url($url, PHP_URL_HOST)` でホスト名を抽出し、許可ドメインと完全一致するか判定する。

---

## 2. 実装の要点

### ① クリックジャッキング防御ヘッダー
`src/phase3/3-3_clickjacking_lab.php`:
```php
if ($cjDefense) {
    // 現代標準ヘッダー（一切のiframe埋め込みを拒絶）
    header("Content-Security-Policy: frame-ancestors 'none';");
    // レガシーブラウザ向け互換ヘッダー
    header("X-Frame-Options: DENY");
}
```
- **`frame-ancestors 'none'`**: 自サイトも含め、世界中のあらゆるサイトでの iframe 埋め込みを禁止（最も安全）。
- **`frame-ancestors 'self'`**: 自サイト内の iframe 埋め込み（モーダル表示など）のみ許可し、クロスオリジン（別ドメイン・別ポート）からの埋め込みを禁止。

### ② オープンリダイレクト防御ロジック
`src/phase3/3-3_clickjacking_lab.php`:
```php
// 自サイト内の安全な相対パスのみを許可
$isValidUrl = str_starts_with($returnTo, "/") && !str_starts_with($returnTo, "//");

if ($isValidUrl) {
    header("Location: " . $returnTo);
    exit; // ★ 超重要: リダイレクト直後のスクリプト実行中断
} else {
    // 外部URLやプロトコル相対URLは安全に拒絶
    $redirectError = "不正なリダイレクト先URLが検出されたため、外部への転送をブロックしました: " . htmlspecialchars($returnTo, ENT_QUOTES, 'UTF-8');
}
```

---

## 3. 実験と検証結果

### 実験 ①: クリックジャッキング攻撃の再現と防御
- **攻撃者サイト**: `http://localhost:8081/clickjacking_trap.html`
- **標的サイト**: `http://localhost:8080/phase3/3-3_clickjacking_lab.php`
- **結果**:
  - **防御OFF時**:
    罠サイトのスライダーで透明度を上げると、「🎁 ギフト券を受け取る！」の真上に本物の「💸 全10,000ptを寄付する」がピッタリ重なっていることを確認。
    ボタンをクリックすると、裏で意図しない10,000ptの寄付が実行され、所持ポイントが0ptに減少した。
  - **防御ON時**:
    標的側で `frame-ancestors 'none'` を出力すると、ブラウザが iframe の読み込みを即座にブロック。
    コンソールに `Refused to frame 'http://localhost:8080/' because an ancestor violates the following Content Security Policy directive: "frame-ancestors 'none'"` とエラーが表示され、クリックジャッキングが完全に防がれることを実証。

### 実験 ②: オープンリダイレクトの再現と防御
- **結果**:
  - **防御OFF時**:
    `?return_to=https://google.com` や `?return_to=//google.com` を送信すると、検証なしで即座に外部サイトへブラウザが自動転送された。
  - **防御ON時**:
    外部URL（`https://...`）およびプロトコル相対URL（`//...`）が `str_starts_with` の判定でブロックされ、「不正なリダイレクト先URLが検出されたため、外部への転送をブロックしました」と安全に拒絶されることを確認。
    自サイト内の相対パス（`/phase3/3-3_clickjacking_lab.php?success=1`）のみが正常にリダイレクトされた。

---

## 4. セキュリティ設計上の重要原則

### 1. `header("Location: ...")` と `exit;`（EAR: Execution After Redirect 脆弱性）
- PHPの `header("Location: ...")` はリダイレクトヘッダーを送信するだけであり、**スクリプトの実行を停止させない**。
- `exit;` を書き忘れると、サーバー側で後続のDB更新やデータ削除が実行されてしまう。
- さらに、ブラウザではなく `curl` 等のリダイレクトに従わないクライアントからアクセスされた場合、未認証ユーザーに後続の機密HTMLデータが丸見えになってしまう。
- **鉄則**: `Location` ヘッダーを書いたら、直後に必ず `exit;` を呼ぶ。

### 2. URL前方一致チェックの甘さとバイパス手口
- `str_starts_with($url, 'https://example.com')` のような単純な先頭一致は以下の方法で容易に突破される：
  1. **サブドメイン型**: `https://example.com.evil.com`
  2. **認証情報構文型**: `https://example.com@evil.com`
  3. **プロトコル相対型**: `//evil.com`（`/` で始まるが外部ドメインへ飛ぶ）
- 外部URLを許可する場合は必ず `parse_url()` でホスト名を切り出して厳格にホワイトリスト検証を行う。
