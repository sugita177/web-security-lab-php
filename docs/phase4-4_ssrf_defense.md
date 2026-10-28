# Phase 4-4: SSRF（Server-Side Request Forgery）と境界防御

## 1. 背景と脅威シナリオ

### ① SSRF（Server-Side Request Forgery）とは
Webアプリケーションが「ユーザーが指定した任意のURL」に対して、**サーバー自身がHTTP/HTTPS通信を行ってデータを取得（フェッチ）する機能**（OGP画像プレビュー、Webhook通知、外部API連携など）において発生する脆弱性です。

### ② 脅威の本質：Webサーバーを踏み台にした内部ネットワーク侵入
通常、インターネット（外部）から企業の内部ネットワーク（イントラネット、社内DB、Docker内部ネットワーク、AWS VPC）にはファイアウォールがあるため直接アクセスできません。

しかし、攻撃者が「内部ネットワークのURL」を入力すると、**ファイアウォールの内側にいるWebサーバー自身がリクエストを代行送信（踏み台化）** してしまいます。

```text
[攻撃者 (インターネット)]
          │ ① 悪意あるURL送信 (例: http://169.254.169.254/latest/meta-data/)
          ▼
[Webサーバー (内部ネットワーク内)] ───(踏み台)───▶ [社内機密API / クラウドメタデータ]
          │                                                │
          │ ◀──────── ③ 機密データを取得 ───────────────────┘
          │
          ▼ ④ 攻撃者に画面表示 / レスポンス返却
[攻撃者 (インターネット)] ★ 社内データやクラウドIAMキーを奪取！
```

### ③ 主な攻撃ターゲット
1. **クラウドインスタンスメタデータ（`169.254.169.254`）**:
   AWS EC2、GCP、Azureのインスタンス内で稼働するサーバーからアクセスすると、インスタンスに付与されたIAMロールの認証情報（一時クレデンシャル）が平文で漏洩する（Capital One情報漏洩事件の主原因）。
2. **社内マイクロサービス・コンテナ間API**:
   外部非公開の社内API（認証が省略されていることが多い）への不正アクセス。
3. **ローカルファイル（`file:///etc/passwd`）**:
   プロトコル制限の不備を突いたOS設定ファイルやソースコードの窃取。

---

## 2. 脆弱な実装とバイパス手法

### ❌ 典型的な不十分な防御例（文字列ブラックリスト）
```php
// 「127.0.0.1」や「localhost」が含まれていたら拒絶する
if (str_contains($url, '127.0.0.1') || str_contains($url, 'localhost')) {
    die("不正なアクセスです！");
}
$data = file_get_contents($url);
```

#### 攻撃者によるバイパス手法：
- **IPアドレスの別表記**: 16進数（`http://0x7f000001`）、10進数（`http://2130706433`）、8進数（`http://0177.0.0.1`）。
- **DNS名前解決の悪用**: 自前ドメイン（`spoof.attacker.com`）のAレコードを `127.0.0.1` や内部IPに向ける。
- **HTTP 302リダイレクト迂回**: 外部の安全なURL（`http://attacker.com/redirect.php`）でバリデーションを通過させ、cURLが自動追従して内部IP（`http://127.0.0.1/...`）へ転送される。

---

## 3. 安全な多層防御の実装

### 3大防壁（完全防御ロジック）

```php
function fetchUrlSecure(string $url): array {
    // 防壁 1: プロトコル（スキーム）のホワイトリスト検証
    $permittedSchemes = ['http', 'https'];
    $scheme = parse_url($url, PHP_URL_SCHEME);
    if (!in_array($scheme, $permittedSchemes, true)) {
        throw new InvalidArgumentException("許可されていないスキームです。");
    }

    // 防壁 2: ホスト名からDNS名前解決（IPアドレスの特定）
    $hostname = parse_url($url, PHP_URL_HOST);
    $ip = gethostbyname($hostname);

    // 防壁 3: filter_var によるプライベートIP・予約済みIPの徹底排除
    $isValidGlobalIp = filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
    if (!$isValidGlobalIp) {
        throw new InvalidArgumentException("プライベートIPまたは予約済みIPへのアクセスは禁止されています。");
    }

    // 防壁 4: リダイレクト自動追従の無効化
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false, // ★ リダイレクトを無効化
        CURLOPT_TIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
    ]);

    $content = curl_exec($ch);
    // ...
}
```

---

## 4. 実験と検証結果

| 攻撃シナリオ | 入力URL | モード A (脆弱) | モード B (安全) |
| :--- | :--- | :--- | :--- |
| **社内極秘APIへのSSRF** | `http://nginx/phase4/internal_api.php` | 🚨 **漏洩成功**（DBパスワード、AWSキー取得） | 🛡️ **遮断成功**（DockerプライベートIP `192.168.107.5` を検知して拒絶） |
| **ループバックへのSSRF** | `http://127.0.0.1/phase4/internal_api.php` | 🚨 接続試行（内部パケット送信） | 🛡️ **遮断成功**（ループバック `127.0.0.1` を検知して拒絶） |
| **ローカルファイル窃取** | `file:///etc/passwd` | 🚨 **漏洩成功**（Linuxユーザー一覧取得） | 🛡️ **遮断成功**（スキーム `file` を検知して拒絶） |
| **正規外部Webアクセス** | `https://httpbin.org/get` | ✅ 取得成功 | ✅ **取得成功**（グローバルIPとして正常フェッチ） |

---

## 5. プロとして知っておくべき高度なSSRF対策

### ① DNS Rebinding（DNS再バインド攻撃）
- **手口**:
  バリデーション時のDNS解決では「正常なグローバルIP」を返し、cURL通信時のDNS解決（わずか数ミリ秒後）では TTL=0 を悪用して「127.0.0.1」を返す高度な攻撃（TOCTOU問題）。
- **根本対策**:
  バリデーションで解決したIPアドレスに対して直接cURLを接続させ、ホストヘッダーのみ元のドメイン名を指定する（`CURLOPT_RESOLVE` の利用）。

### ② IMDSv2（AWSインスタンスメタデータサービス v2）の強制
AWSでは、SSRF対策としてセッショントークンを要求する **IMDSv2** が導入されています。単純なGETリクエストだけではメタデータが取得できなくなるため、インフラレベルでもIMDSv2の強制設定が推奨されます。

