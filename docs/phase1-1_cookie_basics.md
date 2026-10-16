# Phase 1-1: HTTPプロトコル・Cookie属性・生HTTPヘッダーの観察

## 1. 概要
Webアプリケーションにおけるステート（状態）管理の最小単位である「Cookie」と「HTTPレスポンス/リクエストヘッダー」の関係を低レイヤーから紐解きます。
ブラウザは魔法でセッションを維持しているわけではなく、単純なテキストヘッダー（`Set-Cookie` と `Cookie`）の交換によって状態を保持しています。

## 2. 観察のキーポイント
- **サーバーからクライアントへ**: `Set-Cookie: <name>=<value>; Path=...; Domain=...; Expires=...`
- **クライアントからサーバーへ**: `Cookie: <name>=<value>; <name2>=<value2>`
- **Nginx ⇔ PHP-FPM 間の通信**:
  - ブラウザが送ったHTTPヘッダーは、NginxによってFastCGIパラメータ（`HTTP_COOKIE` 等）に変換されてPHP-FPMに渡されます。
  - PHPが出力したヘッダー（`header()` 関数）は、FastCGIレスポンスとしてNginxに送られ、NginxがHTTPレスポンスヘッダーとしてクライアントに返します。

## 3. 実験用スクリプト構成予定
- `src/phase1/1-1_cookie_basics.php`
  - 様々な属性（`Path`, `Domain`, `Expires`, `Max-Age`）を付与したCookieを発行
  - `curl -i` やブラウザの開発者ツール（Network / Applicationタブ）で生ヘッダーを確認
