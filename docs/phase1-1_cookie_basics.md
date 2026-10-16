# Phase 1-1: HTTPプロトコル・Cookie属性・生HTTPヘッダーの観察

## 1. 概要
Webアプリケーションにおけるステート（状態）管理の最小単位である「Cookie」と「HTTPレスポンス/リクエストヘッダー」の関係を低レイヤーから紐解きます。
ブラウザは魔法でセッションを維持しているわけではなく、単純なテキストヘッダー（`Set-Cookie` と `Cookie`）の交換によって状態を保持しています。

---

## 2. 観察のキーポイント
- **サーバーからクライアントへ**: `Set-Cookie: <name>=<value>; Path=...; Domain=...; Expires=...`
- **クライアントからサーバーへ**: `Cookie: <name>=<value>; <name2>=<value2>`
- **Nginx ⇔ PHP-FPM 間の通信**:
  - ブラウザが送ったHTTPリクエストヘッダーは、NginxによってFastCGIパラメータ（`HTTP_COOKIE` 等）に変換されてPHP-FPMに渡されます。
  - PHPが出力したヘッダー（`setcookie()` や `header()` 関数）は、FastCGIレスポンスとしてNginxに送られ、NginxがHTTPレスポンスヘッダー（`Set-Cookie`）としてクライアントに返します。

---

## 3. 実験用スクリプト構成
- `src/phase1/1-1_cookie_basics.php`: Cookie発行（通常・Path制限・削除）と受信ヘッダー確認
- `src/admin/check.php`: `/admin` 配下でのCookie受信確認（Pathスコープの検証用）

---

## 4. 観察と実験結果のまとめ

### (1) ヘッダーの非対称性
- **サーバーからの発行（HTTPレスポンス）**:
  ```http
  Set-Cookie: lab_user=alice; expires=Fri, 16 Oct 2026 16:22:24 GMT; Max-Age=3600; path=/
  Set-Cookie: admin_token=secret_admin_value_999; path=/admin
  ```
  属性（`Path`, `Expires`, `Max-Age` 等）はブラウザに対する「保管・送信条件の指示（メタデータ）」として付与される。
- **ブラウザからの送信（HTTPリクエスト）**:
  ```http
  Cookie: lab_user=alice
  ```
  ブラウザが送信条件を判定した後は、**「名前と値のペア」のみ** が送信される。属性情報は削ぎ落とされる。

### (2) Cookieの削除メカニズム
HTTPプロトコルに「Cookie削除」という独立したコマンドは存在しない。
過去の有効期限（`Expires=Thu, 01 Jan 1970 ...` や `Max-Age=0`）を指定した `Set-Cookie` を発行することで、ブラウザに削除を強制する。

```php
setcookie('lab_user', '', [
    'expires' => time() - 3600,
    'path' => '/',
]);
```

### (3) Path属性の挙動とスコープ制御
| アクセスしたURL | パス | 送信されたCookie | ブラウザの判断 |
| :--- | :--- | :--- | :--- |
| `/admin/check.php` | `/admin` 配下 | `lab_user`<br>`admin_token` | 両方のPath条件（`/` と `/admin`）に合致するため両方送信 |
| `/phase1/1-1_cookie_basics.php` | `/phase1` 配下 | `lab_user` のみ | `/admin` 配下ではないため、ブラウザが `admin_token` の送信を自粛 |

---

## 5. セキュリティ上の超重要原則

### ① Path属性は「セキュリティ境界」ではない
- ブラウザのセキュリティ境界は **同一オリジンポリシー（SOP: スキーム・ホスト・ポート）** であり、Pathは境界に含まれない。
- `Path=/admin` を指定しても、同一オリジンの別パス（例: `/public`）にXSS脆弱性があれば、JavaScriptからの `fetch('/admin/...')` 実行等により、Cookie付きでリクエストを送信させることが可能。
- `Path` はあくまで「不要なリクエストへのCookie送出を減らすトラフィック整理機能」であり、アクセス制御や機密保護を委ねてはならない。

### ② クライアント送信データ（`$_COOKIE`）は改変可能
- リクエストヘッダー `Cookie: key=value` にはメタデータが乗らないため、サーバー（PHP）は「もともとどのPath向けに発行されたCookieなのか」を検証できない。
- `curl` や悪意あるクライアントは、Path指定を無視して任意のCookieを任意のURLへ送信できる。
- したがって、クライアントから届くCookie値のみを盲信した権限判定を行ってはならず、サーバーサイドセッションや署名付きトークンを用いる必要がある。
