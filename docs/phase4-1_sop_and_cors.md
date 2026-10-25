# Phase 4-1: SOP（同一オリジンポリシー）と CORS（クロスオリジンリソース共有）

## 1. 背景と脅威シナリオ

### ① SOP（Same-Origin Policy: 同一オリジンポリシー）
- **概要**:
  ブラウザの最も根本的なセキュリティ境界。
  あるオリジン（スキーム・ホスト・ポートの組み合わせ）から読み込まれたスクリプトが、**異なるオリジンのリソースに対して `fetch` や `XMLHttpRequest` を行い、そのレスポンスデータを読み取ることをデフォルトで禁止** する。
- **オリジンの構成要素**:
  `スキーム (http/https)` + `ホスト名 (localhost / example.com)` + `ポート番号 (:8080 / :8081)`
  ※ ポートが `8080` と `8081` で異なれば、または `http` と `https` で異なれば、完全に別オリジン（クロスオリジン）とみなされる。
- **SOPの本質（プロが理解すべき重要事実）**:
  SOPは「データの読み取り（Read）」を防ぐものであり、**「リクエストの送信（Write）」そのものを防ぐものではない**。
  単純リクエストの場合、ブラウザはサーバーにリクエストを送信し、サーバー側では処理が実行される。ブラウザが手元でレスポンスを破棄してJavaScriptに渡さないだけである。

### ② CORS（Cross-Origin Resource Sharing）
- **概要**:
  SOPの制限を、サーバー側の明示的な許可ヘッダーによって緩和するWeb標準仕様。
- **3大セキュリティ原則**:
  1. **ワイルドカード (`*`) と認証情報 (Cookie) の両立禁止**:
     ブラウザは `Access-Control-Allow-Origin: *` の状態では、Cookieを伴うリクエスト（`credentials: 'include'`）のレスポンス読み取りを絶対に拒絶する。
     安全に許可するには、具体的なオリジン名（`http://localhost:8081`）と `Access-Control-Allow-Credentials: true` の両方が必須。
  2. **プリフライト（OPTIONS）リクエストによる水際防御**:
     単純リクエスト以外の通信（`Content-Type: application/json` やカスタムヘッダー `X-...`）では、ブラウザは本番リクエストを送る前に `OPTIONS` メソッドで事前伺いを立てる。サーバーが許可を返さない限り、本番の副作用を伴うリクエスト（POST/PUT/DELETE）はネットワークに流れない。
  3. **サーバー側での `Content-Type: application/json` 厳格検証**:
     攻撃者が昔ながらの HTML `<form method="POST">`（単純リクエスト）を使ってプリフライトをすり抜けるのを防ぐため、サーバー側で `application/json` 以外のリクエストを即座に拒絶（415 Unsupported Media Type）する設計が不可欠。

---

## 2. 実装の要点

### ① 安全なCORS許可ヘッダーの実装
`src/phase4/4-1_cors_api.php`:
```php
// 信頼できる具体的なオリジンを指定（* は使用しない）
header('Access-Control-Allow-Origin: http://localhost:8081');

// Cookie（セッション情報）の送受信を許可
header('Access-Control-Allow-Credentials: true');
```

### ② プリフライト（OPTIONS）リクエストへの応答
`src/phase4/4-1_cors_api.php`:
```php
if ($requestMethod === 'OPTIONS') {
    // 許可するHTTPメソッドを指定
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    // 許可するリクエストヘッダーを指定
    header('Access-Control-Allow-Headers: Content-Type, X-Custom-Header');
    // 204 No Content（本文なし成功）で即座に応答して終了
    header('HTTP/1.1 204 No Content');
    exit;
}
```

---

## 3. 実験と検証結果

### 実験 ①: モード 0（CORSヘッダーなし / SOPデフォルト）
- **クライアント側挙動**:
  - `fetch` 実行時にコンソールに `CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource` エラーが発生し、JavaScriptでデータを読み取れず例外（catch）となった。
- **サーバー側受信ログ（重要実証）**:
  - クライアント側でCORSエラーが表示されたにもかかわらず、サーバー側の受信ログには **`GET` リクエストが記録されていた**。
  - ➔ **「CORSエラーであっても、サーバーにはリクエストが届いて処理が実行されている」** ことを物理確認。

### 実験 ②: モード 1（安易なワイルドカード `*`）
- **単純GET (Cookieなし)**:
  - 正常に成功し、公開データがクライアント側で読み取り可能となった。
- **Cookie付きGET (`credentials: 'include'`)**:
  - `The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'` エラーが発生。
  - ➔ ブラウザがCookie保護のため、`*` のレスポンス受け取りを拒絶することを実証。

### 実験 ③: モード 2（具体的オリジン + Credentials + プリフライト対応）
- **Cookie付きGET**:
  - 正常に成功し、山田太郎さんの秘密データ（`user_data`）が取得できた。
- **プリフライトPOST (JSON + カスタムヘッダー)**:
  - サーバーログにまず **`OPTIONS`** が記録され、続いて本番 **`POST`** が記録された。
  - 本番POSTが正常に実行され、完全なクロスオリジン連携が成立することを確認。
- **モード 0 時のプリフライト遮断**:
  - モード 0 でプリフライトPOSTを送った際、サーバーログには **`OPTIONS` しか届かず、本番 `POST` は1通も送信されずにブラウザ側で完全に中止された** ことを実証。

---

## 4. セキュリティ設計上の重要原則
1. **SOPはCSRF対策ではない**:
   単純リクエストはサーバーに到達してしまうため、データ書き換え処理（送金・削除など）はSOPだけでは防げない。CSRFトークン検証やSameSite属性が必須。
2. **APIは `Content-Type: application/json` を強制する**:
   サーバー側で `application/json` を必須化することで、ブラウザに必ずプリフライトを強制させ、単純リクエストによる不正POSTを水際で遮断できる。
3. **設定の永続化**:
   CORSモードのようなサーバー全体のポリシーをCookie/セッションに頼ると、Cookieを送らないリクエストで意図しない挙動になるため、必ずサーバー側設定として管理する。
