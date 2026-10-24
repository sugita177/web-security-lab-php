# Phase 3-4: 機微情報のキャッシュ制御とMIMEスニッフィング防御

## 1. 背景と脅威シナリオ

### ① HTTPキャッシュと機微情報の漏洩（Cache-Control）
- **概要**:
  ブラウザや途中のプロキシサーバー（CDN、社内プロキシなど）は、通信パフォーマンス向上のためにレスポンスをローカルストレージやメモリにキャッシュ（保存）する。
- **脅威シナリオ**:
  - **共有端末での情報漏洩**: ネットカフェ、学校、会社の共有PCで個人情報（マイページ、クレジットカード番号、健康診断結果など）を閲覧し、ログアウトしたとする。次の利用者が「ブラウザの『戻る』ボタン」を押した際、キャッシュから前の利用者の個人情報がそのまま画面に再表示されてしまう。
  - **中間プロキシでの共有漏洩**: `public` なキャッシュとして扱われると、CDNや社内プロキシに特定ユーザーの個人情報画面が保存され、別のユーザーにも配信されてしまう事故が起きる。
  - **PCディスク解析による漏洩**: キャッシュがローカルディスクに保存されると、ブラウザを終了した後でもストレージ解析によって個人情報HTMLが抽出されてしまう。
- **防御策**:
  - `Cache-Control: no-store, private`（一切の保存を禁止し、共有キャッシュを拒絶）
  - レガシー互換: `Pragma: no-cache`, `Expires: 0`

### ② MIMEスニッフィング（MIME Sniffing）と X-Content-Type-Options
- **概要**:
  ブラウザがサーバーから送られてきた `Content-Type` ヘッダー（例: `text/plain` や `image/png`）をそのまま信じず、「ファイルの中身（マジックバイトやタグ）を勝手に推測（スニッフィング）」して解釈してしまう挙動。
- **歴史的背景**:
  黎明期のWebサーバー管理者が `Content-Type` を設定し忘れて `text/plain` で返してしまうケースが多く、ブラウザ（特に旧IE）が親切心で「中身がHTMLっぽかったらHTMLとして描画してあげよう」と推測機能を導入した。
- **脅威シナリオ**:
  - 画像やテキストファイルのアップロード機能があるサイトで、攻撃者が「中身が `<script>alert(1)</script>` のテキストファイル（または画像）」をアップロードする。
  - サーバーが `Content-Type: text/plain` として配信しても、ブラウザが勝手に「これはHTML / JavaScriptだ！」と忖度して解釈・実行してしまうと、**XSS（クロスサイトスクリプティング）** が成立する。
- **防御策**:
  - `X-Content-Type-Options: nosniff`（ブラウザの推測を強制停止し、宣言された Content-Type を厳格に適用させる）

---

## 2. 実装の要点

### ① キャッシュ制御ヘッダーの実装
`src/phase3/3-4_mypage.php`, `src/phase3/3-4_avatar.php`:
```php
// 防御ON: 一切のキャッシュを禁止
header('Cache-Control: no-store, private');
header('Pragma: no-cache'); // HTTP/1.0 互換
header('Expires: 0');       // 過去日付で期限切れを明示
```

#### 💡 PHP固有の重要仕様: `session.cache_limiter`
PHPは `session_start()` を呼ぶと、デフォルトで以下のヘッダーを自動出力する安全設計になっている：
```http
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Cache-Control: no-store, no-cache, must-revalidate
```
※ PHP開発チームが「セッションを使う画面は機微情報のはずだから、開発者が設定を忘れても安全側（キャッシュ禁止）に倒そう」と配慮したもの。
画像やPDF等のサブリソースや静的ファイルでは `session_start()` を呼ばないことが多いため、明示的な `Cache-Control: no-store` の指定やインフラ設定（Nginx/CDN）が必須となる。

### ② 現代ブラウザの `bfcache`（Back/Forward Cache）対策
現代のブラウザ（Chrome 96以降やSafari）は、戻るボタンの体感速度向上のため、`no-store` があってもメモリ上に画面のスナップショットを保持（bfcache）してしまう場合がある。
実務では以下の2つの合わせ技で完全防御する：
1. **ログアウト時の `Clear-Site-Data`**:
   ```php
   header('Clear-Site-Data: "cache", "storage"');
   ```
2. **JavaScriptの `pageshow` イベント監視**:
   ```javascript
   window.addEventListener('pageshow', function(event) {
       if (event.persisted) {
           window.location.reload(); // キャッシュ復元を検知して強制再検証
       }
   });
   ```

### ③ MIMEスニッフィング防止ヘッダーの実装
`src/phase3/3-4_sniff_lab.php`:
```php
header('Content-Type: text/plain; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
```

---

## 3. 実験と検証結果

### 実験 ①: HTTPキャッシュと `(memory cache)` / `0.5 kB` の検証
- **検証対象**: `3-4_avatar.php`（アイコン画像）
- **結果**:
  - **防御OFF時 (`public, max-age=3600`)**:
    再読み込み時、Size列が **`(memory cache)`**、Timeが **`0 ms`** となった。
    ➔ ブラウザはサーバーへ通信を一切行わず、ローカルのキャッシュから読み出していることを物理確認。
  - **防御ON時 (`no-store, private`)**:
    ハード再読み込み後、Size列から `(memory cache)` が消え、**`0.5 kB`（実通信）** となった。
    ➔ 毎回必ずサーバーへネットワーク要求が発生し、ローカルへのキャッシュ保存が完全に拒絶されていることを実証。

### 実験 ②: ログアウト後のマイページ保護（302リダイレクト）
- **結果**:
  ログアウト後にマイページへアクセスすると、ネットワークログで以下を確認：
  ```text
  3-4_mypage.php   302  document / Redirect   0.3 kB
  3-4_login.php    200  document              1.8 kB
  ```
  ➔ キャッシュから古い個人情報画面が復元されることなく、サーバーで未ログインと判定されてログイン画面へ安全に弾き戻された。

### 実験 ③: MIMEスニッフィングによるXSSと `nosniff` による遮断
- **検証対象**: `src/phase3/3-4_sniff_lab.php`（`fake_script.txt` を `text/plain` で配信）
- **結果**:
  - **防御OFF時**:
    `<script src="?serve_file=1">` で読み込むと、ブラウザが勝手にJavaScriptとスニッフィングし、**「⚠️ XSS成立！」アラートが画面にポップアップ** した。
  - **防御ON時 (`nosniff`)**:
    アラートは一切表示されず、ブラウザのConsoleに以下のエラーが出力されてスクリプト実行が完全にブロックされた：
    `Refused to execute script from '...' because its MIME type ('text/plain') is not executable, and strict MIME type checking is enabled.`
