# Web Security Hands-on Lab (PHP 8.5)

Docker（Nginx + PHP 8.5-FPM）を活用した、実践的Webセキュリティ学習リポジトリです。
Webの低レイヤー（HTTPヘッダー、TCP/TLS、リバースプロキシ境界）からアプリケーション脆弱性（OWASP Top 10）、認証・認可基盤までをハンズオン形式で学習します。

---

## 環境要件
- Docker / Docker Compose

## クイックスタート
```bash
# コンテナのビルド・起動
docker compose up -d

# 起動確認
curl -I http://localhost:8080/
```

ブラウザで `http://localhost:8080` にアクセスできます。

## ディレクトリ構成
```text
.
├── compose.yaml              # Docker Compose構成（初期: Nginx + PHP-FPM）
├── docker/
│   ├── nginx/
│   │   └── default.conf      # Nginx設定（プロキシ、ヘッダー制御）
│   └── php/
│       └── php.ini           # PHP設定（セッション・セキュリティ設定）
├── docs/                     # 各フェーズの理論、攻撃・防御シナリオ、解説
│   └── roadmap.md            # 全体学習ロードマップ
└── src/                      # 実装・検証コード（課題ごとにディレクトリまたはスクリプトを作成）
```

## 学習の進め方
本ラボは「専属セキュリティメンター」との対話形式で進めます。
1. **要件提示**: メンターからセキュリティ要件や課題が提示されます。
2. **問いかけ / クイズ**: 実装方針や攻撃シナリオに関する問いが出題されます。
3. **実装**: あなた自身がスケルトンコードを元に実装します（核心部分は完全生成されません）。
4. **レビュー & 実証**: 攻撃リクエストの実証、セキュリティ観点でのコードレビューを行います。

詳細なカリキュラムは [docs/roadmap.md](file:///Users/moriaki/workspace/web-security-lab-php/docs/roadmap.md) を参照してください。
