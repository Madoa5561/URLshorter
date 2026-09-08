# URL Shortener (Cloudflare Workers 版)

[Madoa5561/URLshorter](https://github.com/Madoa5561/URLshorter) を **Cloudflare Workers** のみで完全に動作するようにモダンに再構築したURL短縮サービスです。

サーバー管理は一切不要で、世界中のエッジロケーション（Cloudflare Edge）から超低レイテンシで短縮URLのリダイレクトやAPI処理、管理画面の提供を行います。

---

## 🌟 主な特徴とアーキテクチャ

- **完全エッジネイティブ**: Cloudflare Workers + [Hono](https://hono.dev/) で構築。コールドスタートほぼゼロの超高速レスポンス。
- **サーバーレスSQLite (Cloudflare D1)**: 元のSQLiteスキーマをそのまま継承。アクセス数カウント、期限管理、ログ記録、集計クエリをエッジで高速実行。
- **HTMLRewriter による高速 OGP 抽出**: 短縮対象URLの `<title>` や `og:title`, `og:description`, `og:image` を Workers 組み込みの C++ ストリーミングパーサーで取得。
- **OGPカード付きリダイレクト**: SNS（X/Twitter、Discord、LINE、Slack等）でシェアした際にリッチなリンクプレビューカードが表示され、ユーザーアクセス時には自動リダイレクト。
- **フル機能の管理画面**:
  - URL統計グラフ表示（日別 / 週別 / 月別）
  - URL一覧の検索、ソート、フィルタリング（有効 / 期限切れ / 上限到達）
  - URL個別削除および一括削除
  - CSVエクスポート
  - アクセス・エラーログ確認
  - 手動クリーンアップ
- **自動クリーンアップ (Cron Triggers)**: 毎日午前0時に30日以上前のログおよび未使用URLを自動削除（サーバー常駐プロセス不要）。
- **ステートレス認証**: Web Crypto API（HMAC-SHA256）を用いた24時間有効な管理トークン発行。
- **四季自動切り替えテーマ (季節アニメーション)**:
  - 🌸 **春 (3〜5月)**: 桜の舞い散る花びらとピンクアクセント
  - 🌊 **夏 (6〜8月)**: 揺らめく海面・気泡とマリンブルーアクセント
  - 🍁 **秋 (9〜11月)**: 風に舞う紅葉（もみじ・イチョウ）と琥珀アンバーアクセント
  - ❄️ **冬 (12〜2月)**: 静かに降り積もる粉雪と白銀アイスブルーアクセント
  - 自動検出に加えて、ヘッダーの季節バッジから手動切り替えも可能。
- **動的ドメイン対応**: ホスト名を自動認識するため、ローカル開発（`localhost:8787`）、`*.workers.dev`、任意のカスタムドメインでも設定変更なしで即座に動作。

---

## 📁 ディレクトリ構成

```
urlshorter-cf/
├── package.json               # 依存関係とnpmスクリプト
├── tsconfig.json              # TypeScript 設定
├── wrangler.jsonc             # Cloudflare Workers / D1 / Assets / Cron 設定
├── schema.sql                 # Cloudflare D1 初期化用 SQL
├── .dev.vars.example          # ローカル開発用環境変数サンプル
├── README.md                  # 本ドキュメント
├── public/                    # 静的ページ (Workers Assets により高速CDN配信)
│   ├── index.html             # トップページ UI
│   ├── admin.html             # 管理画面 UI
│   └── api_document.html      # APIドキュメント UI
└── src/
    ├── index.ts               # Hono メインルーティング & Cron ハンドラ
    ├── types.ts               # 型定義と Cloudflare Bindings
    ├── ogp.ts                 # HTMLRewriter を用いた OGP 取得処理
    ├── auth.ts                # HMAC-SHA256 認証トークン処理
    └── templates/             # サーバーサイド動的生成テンプレート
        ├── redirect.ts        # OGPメタ付きリダイレクト画面
        ├── expired.ts         # 有効期限切れ・上限超過画面
        ├── error.ts           # エラー画面
        └── utils.ts           # XSS防止 HTMLエスケープ関数
```

---

## 🚀 ローカルでの開発・動作確認

### 1. 依存関係のインストール

```bash
npm install --ignore-scripts
```

### 2. 環境変数の設定

`.dev.vars.example` をコピーして `.dev.vars` を作成します：

```bash
# Windows PowerShell
Copy-Item .dev.vars.example .dev.vars
```

`.dev.vars` の中身：
```env
ADMIN_SECRET="admin12345"
```

### 3. ローカル D1 データベースの作成・初期化

Wrangler を使用して、ローカルエミュレーション環境にテーブルを作成します：

```bash
npm run d1:init:local
```

### 4. 開発サーバーの起動

```bash
npm run dev
```

起動後、ブラウザで以下のURLにアクセスできます：
- **トップページ**: [http://localhost:8787/](http://localhost:8787/)
- **管理画面**: [http://localhost:8787/admin](http://localhost:8787/admin) (パスワード: `.dev.vars` で設定した `ADMIN_SECRET`)
- **APIドキュメント**: [http://localhost:8787/api-document](http://localhost:8787/api-document)

---

## ☁️ Cloudflare Workers への本番デプロイ

### 1. Cloudflare にログイン

```bash
npx wrangler login
```

### 2. 本番用 Cloudflare D1 データベースの作成

```bash
npx wrangler d1 create urlshorter-db
```

コマンドの実行結果に以下のような出力が表示されます：
```
[[d1_databases]]
binding = "DB"
database_name = "urlshorter-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### 3. `wrangler.jsonc` の更新

`wrangler.jsonc` を開き、上記で取得した `database_id` を設定します：

```jsonc
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "urlshorter-db",
      "database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" // ← ここを書き換え
    }
  ],
```

### 4. 本番 D1 データベースにテーブルを作成

```bash
npm run d1:init:remote
```

### 5. 管理者パスワード (ADMIN_SECRET) の登録

本番環境の管理者シークレットキーを設定します：

```bash
npx wrangler secret put ADMIN_SECRET
```
（プロンプトが表示されたら、任意の強固なパスワードを入力してEnter）

### 6. デプロイ実行

```bash
npm run deploy
```

デプロイが完了すると、`https://urlshorter-cf.<あなたのサブドメイン>.workers.dev` のような公開URLが表示されます。

---

## ⚙️ カスタムドメインの設定 (オプション)

独自のドメイン（例: `s.example.com`）で運用したい場合：
1. [Cloudflare ダッシュボード](https://dash.cloudflare.com/) にログイン
2. **Workers & Pages** > **Overview** > 作成した Worker (`urlshorter-cf`) を選択
3. **Settings** > **Domains & Routes** > **Add** > **Custom Domain** を選択
4. 割り当てたいドメイン名（例: `s.example.com`）を入力して追加

ドメインが反映されると、自動的に短縮URLの発行やリダイレクトがそのカスタムドメインで動作します。

---

## 📖 API リファレンス

### 1. 短縮URL作成
- **URL**: `POST /shorten`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "url": "https://example.com/very/long/url",
    "access_limit": 100, // 省略可: 最大アクセス回数
    "expires_at": "2026-12-31T23:59:59Z" // 省略可: 有効期限(ISO形式)
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "shortened_url": "https://your-domain.com/abc123",
    "original_url": "https://example.com/very/long/url",
    "access_limit": 100,
    "expires_at": "2026-12-31 23:59:59",
    "og_data": {
      "title": "Example Domain",
      "description": "...",
      "image": "https://example.com/ogp.png"
    },
    "message": "URLを短縮しました"
  }
  ```

### 2. リダイレクト
- **URL**: `GET /:shortened` (例: `GET /abc123`)
- **動作**:
  - 有効な場合: OGPタグ付きのリダイレクト画面を返し、1秒後に元のURLへ自動遷移
  - 有効期限切れ・上限超過の場合: 専用のエラー画面（403 Forbidden）を表示
  - 存在しない場合: 404 Not Found エラー画面を表示

### 3. 管理者認証
- **URL**: `POST /admin/auth`
- **Body**: `{ "secret": "あなたのADMIN_SECRET" }`
- **Response**: `{ "message": "認証に成功しました", "token": "..." }`
- **認証付きAPI呼び出し**: 以降のリクエストの `Authorization` ヘッダーにこのトークン、または `ADMIN_SECRET` を付与します。
