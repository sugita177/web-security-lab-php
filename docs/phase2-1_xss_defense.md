# Phase 2-1: クロスサイトスクリプティング（XSS）の再現と多層防御

## 1. 概要
Webアプリケーション脆弱性の中で最も頻出かつ影響範囲の広い「クロスサイトスクリプティング（XSS: Cross-Site Scripting）」を取り上げます。
攻撃者が細工したスクリプト（JavaScript）を被害者のブラウザ上で実行させる手口をハンズオンで再現し、文脈に応じた適切なエスケープ処理と、多層防御としての **Content Security Policy (CSP)** を学びました。

---

## 2. XSSの主要分類
- **反射型XSS（Reflected XSS）**:
  検索キーワードやエラーメッセージなど、URLのクエリパラメータに含まれる攻撃文字列が、そのままレスポンスHTMLに埋め込まれて即座にブラウザで実行される形式。攻撃者は罠リンクをSNSやメールで踏ませる。
- **格納型XSS（Stored / Persistent XSS）**:
  掲示板の投稿やユーザープロフィールの入力欄など、攻撃ペイロードがサーバー側のデータベースやファイルに一度保存され、それを閲覧した不特定多数のユーザーのブラウザでスクリプトが実行される形式（極めて危険度が高い）。
- **DOM型XSS（DOM-based XSS）**:
  サーバーを介さず、フロントエンドのJavaScriptコード（`innerHTML` や `location.hash` の不適切な扱いなど）によってDOMが書き換えられることで実行される形式。

---

## 3. 防御の要点
1. **文脈（Context）に応じた適切なエスケープ**:
   - HTML本文や属性値: `htmlspecialchars($val, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8')`
   - JavaScript文脈: `json_encode($val, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP)`
2. **多層防御（CSP: Content Security Policy）**:
   - HTTPレスポンスヘッダー `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'` などを指定することで、万が一エスケープ漏れでインラインスクリプト（`<script>`）が埋め込まれても、ブラウザがその実行を強制ブロックする。

---

## 4. 実験と検証結果

### (1) 3つのモードにおけるブラウザ挙動の比較
同一のペイロード `<script>alert(1)</script>` に対する動作結果：

| モード | HTMLに出力されるコード | 画面上の見た目 | JavaScriptの動作 |
| :--- | :--- | :--- | :--- |
| **1. 脆弱モード** | `<span><script>...</span>` | 空白（非表示） | 🚨 **即座に実行される（アラート発火）** |
| **2. エスケープ有効モード** | `<span>&lt;script&gt;...</span>` | `<script>alert(1)</script>` と文字表示 | 🛡️ **実行されない（文字として安全に描画）** |
| **3. CSP有効モード** | `<span><script>...</span>` | 空白（非表示） | 🛡️ **ブラウザが実行を強制ブロック**（ConsoleにCSP違反エラー） |

### (2) CSP導入時の実務的課題とインラインCSS
`default-src 'self'` を指定すると、悪意あるスクリプトだけでなく `<style>` タグに書かれたインラインCSSまでブロックされ、デザインが崩れる現象が発生する。
実務では、`style-src 'self' 'unsafe-inline'` を追記してスタイルのみインラインを許可するか、CSSを外部ファイル（`.css`）に分離して読み込む運用が必要となる。

---

## 5. セキュリティ上の超重要原則

### ① 保存時ではなく「出力直前」にエスケープする（Late Escaping）
- DBやファイルへの保存時に `htmlspecialchars()` をかけてしまうと、二重エスケープ事故（`&amp;lt;`）や文字数カウントの狂い、スマホアプリやメールなどHTML以外の出力先での文字化けが発生する。
- データストアには「生データ」を保持し、HTMLへ流し込む最後の境界でエスケープを施すのが絶対の鉄則。

### ② JavaScript文脈に `htmlspecialchars` は通用しない
- `<script>` の中では、ブラウザはHTMLエンティティ（`&lt;` 等）を展開しないため構文エラーとなる。
- また、`\`（バックスラッシュ）によるクォート脱出（`\'`）を `htmlspecialchars` は無害化できない。
- JavaScript内にPHPから安全に変数を渡す場合は、必ず **`json_encode()`**（`JSON_HEX_*` オプション付き）を使用する。
