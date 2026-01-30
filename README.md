# 🔒 セキュアオンライン3Dゲーム

セキュリティを強化したマルチプレイヤー3Dゲーム

## 🛡️ セキュリティ機能

### 認証・セッション
- **bcrypt** でパスワードハッシュ化（ソルト付き、12ラウンド）
- **HTTPOnly Cookie** - JavaScriptからアクセス不可
- **Secure Cookie** - HTTPS必須（本番環境）
- **SameSite=Strict** - CSRF対策
- **セッション再生成** - ログイン時にセッションIDを再生成（セッション固定攻撃対策）

### 攻撃対策
- **CSRFトークン** - 全ての POST リクエストで検証
- **レート制限** - ログイン試行は15分に10回まで
- **アカウントロック** - 5回失敗で30分ロック
- **Helmet** - セキュリティヘッダー設定
- **入力バリデーション** - サーバー側で厳密にチェック
- **SQLインジェクション対策** - プリペアドステートメント使用
- **XSS対策** - 出力のエスケープ処理

### パスワード要件
- 8文字以上
- 大文字・小文字・数字・特殊文字のうち3種類以上

## 🚀 デプロイ手順

### 1. GitHubにアップロード

```bash
cd online-game-secure
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/あなたの名前/secure-3d-game.git
git push -u origin main
```

### 2. Renderでデプロイ

1. [render.com](https://render.com) にログイン
2. **New +** → **Web Service**
3. GitHubリポジトリを選択
4. 設定:
   - **Name**: `secure-3d-game`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. **Environment Variables** を追加:
   - `SESSION_SECRET`: ランダムな長い文字列（64文字以上推奨）
   - `NODE_ENV`: `production`
6. **Create Web Service**

### 3. 完了！

`https://あなたのアプリ名.onrender.com` でアクセス

## 💻 ローカル実行

```bash
npm install
npm start
```

http://localhost:3000 でアクセス

## 📁 ファイル構成

```
online-game-secure/
├── server.js          # セキュアサーバー
├── package.json       # 依存関係
├── game_users.db      # SQLiteデータベース（自動生成）
└── public/
    └── index.html     # クライアント（ログイン画面含む）
```

## 🔧 環境変数

| 変数名 | 説明 | デフォルト |
|--------|------|------------|
| `PORT` | サーバーポート | 3000 |
| `SESSION_SECRET` | セッション暗号化キー | ランダム生成 |
| `NODE_ENV` | 環境（production/development） | development |

## ⚠️ 本番環境での注意

1. **SESSION_SECRET は必ず設定する**（環境変数で）
2. **HTTPS を使用する**（Renderは自動でHTTPS）
3. **データベースのバックアップ**を定期的に行う

## 🎮 機能

- ユーザー登録・ログイン
- リアルタイムマルチプレイヤー
- チャット機能
- スコア保存・ランキング
- セキュアなセッション管理

## 📝 API エンドポイント

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/csrf-token` | CSRFトークン取得 |
| POST | `/api/register` | 新規登録 |
| POST | `/api/login` | ログイン |
| POST | `/api/logout` | ログアウト |
| GET | `/api/me` | 現在のユーザー情報 |
| GET | `/api/leaderboard` | リーダーボード |

---

🔐 セキュリティを意識した設計で安心してプレイ！
