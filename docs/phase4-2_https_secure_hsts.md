# Phase 4-2: ローカルHTTPS化、Secure属性、HSTS

## 1. 背景と脅威シナリオ

### ① 平文HTTP通信と盗聴・改ざん（Man-in-the-Middle: 中間者攻撃）
- **概要**:
  暗号化されていないHTTP（ポート80/8080）通信は、Wi-Fi（カフェや公共ネットワーク）やネットワーク経路上のルーター等でパケット盗聴（Sniffing）されると、パスワードやセッションCookie（`PHPSESSID`）が平文のまま丸見えになる。
- **TLS/HTTPSの役割**:
  ブラウザとサーバー間の通信を暗号化（TLSハンドシェイク）し、盗聴・改ざん・なりすましを防止する。

### ② Cookieの `Secure` 属性
- **概要**:
  Cookieを発行する際に `Secure` 属性を付与することで、ブラウザに対して**「HTTPS接続のときだけこのCookieを送信し、暗号化されていない平文HTTP接続のときは絶対にCookieを送信するな」** と命じる属性。
- **脅威シナリオ**:
  もし `Secure` 属性がないと、HTTPSで運用されている安全なサイトであっても、攻撃者が被害者を `http://` のリンクへ誘導した瞬間に、ブラウザが平文のHTTPリクエストにCookieを載せてネットワークに送出してしまい、セッションハイジャックが成立する。

### ③ HSTS（HTTP Strict Transport Security）と SSL Stripping（ダウングレード攻撃）
- **SSL Stripping（SSL剥ぎ取り攻撃）**:
  ユーザーがブラウザのURL欄に `example.com` とだけ入力した際、ブラウザはまず平文の `http://example.com` にアクセスし、サーバーから `301/302` で `https://` へリダイレクトされるのが一般的である。
  攻撃者はこの「最初の平文HTTPリクエスト」に割り込み、リダイレクトを書き換えてユーザーをずっと平文HTTPのまま通信させ続ける（SSL Stripping）。
- **HSTSによる防御**:
  サーバーが `Strict-Transport-Security: max-age=31536000; includeSubDomains` ヘッダーを返すことで、ブラウザは**「今後1年間、ユーザーが http:// と入力しても、ネットワークに通信を出す前にブラウザ内部で強制的に https:// に変換（内部リダイレクト: 307 Internal Redirect）せよ」** と記憶する。
  これにより、初回の平文リクエストすらネットワークに一切流さなくなる。

---

## 2. 実装の要点

### ① NginxのSSL設定（`docker/nginx/default.conf`）
自己署名証明書（RSA 2048bit）を生成し、ポート443（ホスト側: 8443）でTLSv1.2 / TLSv1.3を有効化：
```nginx
server {
    listen 443 ssl;
    server_name localhost 127.0.0.1;

    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location ~ \.php$ {
        fastcgi_pass php:9000;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTPS on;  # PHP側にHTTPS接続であることを伝達
        include fastcgi_params;
    }
}
```

### ② HSTSヘッダーの送出（RFC 6797 仕様の遵守）
平文HTTPでHSTSヘッダーを送出してはならない（ブラウザは無視する仕様）。必ずHTTPS接続時のみ送出する：
```php
if ($isHttps && $hstsEnabled) {
    header('Strict-Transport-Security: max-age=31536000;');
}
```

### ③ Secure属性付きCookieの発行と消去
```php
// 発行時
setcookie('session_secure', 'SECURE_' . $dummyToken, [
    'expires' => time() + 3600,
    'path' => '/',
    'secure' => true,       // ★ Secure属性
    'httponly' => true,
    'samesite' => 'Lax'
]);

// 消去時（発行時と同じパス・Secure属性を指定して上書き消去）
setcookie('session_secure', '', [
    'expires' => time() - 3600,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax'
]);
```

---

## 3. 実験と検証結果

### 実験 ①: 平文HTTP（8080）と暗号化HTTPS（8443）の生ヘッダー確認
`curl` コマンドでそれぞれの生HTTPヘッダーを比較：
```bash
# ① 平文HTTP (8080)
curl -I http://localhost:8080/phase4/4-2_https_lab.php
# => Strict-Transport-Security は出力されない

# ② 暗号化HTTPS (8443)（HSTS ON時）
curl -k -I https://localhost:8443/phase4/4-2_https_lab.php
# => Strict-Transport-Security: max-age=31536000; が出力される！
```

### 実験 ②: Cookieの送信挙動比較
1. **HTTPS（8443）でCookieを発行**:
   - `session_insecure`（Secureなし）: サーバーが暗号化受信
   - `session_secure`（Secureあり）: サーバーが暗号化受信
2. **平文HTTP（8080）へ切り替えてアクセス**:
   - `session_insecure`: 🚨 平文HTTPでそのまま送信され、サーバーに届いてしまう（盗聴可能）。
   - `session_secure`: 🛡️ ブラウザが平文送信を拒絶するため、サーバーには一切届かない（平文漏洩を防御）。

---

## 4. プロとして押さえるべき重要知見

### ① W3C Secure Contexts による `localhost` 特例
Google Chromeなどのモダンブラウザでは、ローカル開発の便宜を図るため、`http://localhost` や `http://127.0.0.1` を「Potentially Trustworthy Origin（安全とみなされるコンテキスト）」として特別扱いする。
そのため、一般的な外部ドメインと異なり、`http://localhost` 上でも `Secure` Cookie が送信されてしまう特例挙動が存在する。

### ② Cookieのオリジン境界と消去の仕組み
- 人間にとっては `localhost` も `127.0.0.1` も同じ手元のPCであるが、**ブラウザにとっては完全に別オリジン（別ドメイン）** として厳密に分離される。
- サーバーはブラウザのCookieを直接削除することはできず、「有効期限を過去にした同じ属性（名前・ドメイン・パス・Secure属性）のCookie」を再送してブラウザに上書き破棄させる。
- Secure付きCookieは、平文HTTP通信からの削除・変更命令（`Set-Cookie`）がブラウザによって拒絶される（RFC 6265bis 規則）。
