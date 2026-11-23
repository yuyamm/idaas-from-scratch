# IdaaS from Scratch

> [!WARNING]
> 学習目的の実装です。IDaaS の仕組みを理解するために作ったもので、本番環境での利用は想定していません。セキュリティ監査や OpenID Conformance Suite での認定は受けていません。

IDaaS の仕組みを理解するために、最小構成の IDaaS を Go でスクラッチ実装したもの。
ID 管理・認証・フェデレーションを扱い、OpenID Provider / OAuth 2.0 認可サーバー / SAML IdP / SCIM サーバーとして動く。

- 設計：[docs/](docs/README.md)（システムアーキテクチャ、主要フロー、ソフトウェアアーキテクチャ、DB 設計）
- API 仕様：[api/openapi/](api/openapi/README.md)（Admin API と OIDC / OAuth 2.0 の OpenAPI。実装の SSOT）

## 主な機能

| 分類 | 機能 |
|---|---|
| ID 管理 | マルチテナント、ユーザー・グループ・ロール（RBAC）、論理削除と物理削除、Admin API、SCIM 2.0 |
| 認証 | パスワード（Argon2id・再ハッシュ）、ロック、レート制限、HIBP による漏洩チェック、TOTP、リカバリーコード、パスキー（WebAuthn）、パスワードリセット、メール検証 |
| フェデレーション | OIDC OP（Authorization Code + PKCE、Refresh Token のローテーション）、Client Credentials、Introspection、Revocation、RP-Initiated / Back-Channel Logout、外部 OIDC IdP でのログイン、SAML 2.0 IdP |
| 運用 | 署名鍵のローテーション（JWKS）、Transactional Outbox による監査ログ（ハッシュ連鎖・追記のみ）と Webhook |

## 動かす

```sh
docker compose up -d postgres            # PostgreSQL
export ENCRYPTION_KEYS="k1:$(openssl rand -base64 32)"
go run ./cmd/idaas serve                  # http://localhost:8080
go run ./cmd/idaas bootstrap              # Admin API クライアントを発行
```

コンテナで動かす場合は `docker compose --profile app up --build`。

### 環境変数

| 変数 | 既定値 | 説明 |
|---|---|---|
| `DATABASE_URL` | `postgres://idaas:idaas@localhost:54329/idaas?sslmode=disable` | PostgreSQL |
| `BASE_URL` | `http://localhost:8080` | 公開 URL。テナントの issuer は `BASE_URL/t/{slug}` |
| `LISTEN_ADDR` | `:8080` | 待ち受けアドレス |
| `ENCRYPTION_KEYS` | （必須） | 秘密情報の暗号化鍵。`id:base64(32 bytes)` をカンマ区切りで複数指定できる |
| `ACTIVE_KEY_ID` | 先頭の鍵 | 新しく暗号化するときに使う鍵（鍵のローテーション用） |
| `SMTP_ADDR` / `SMTP_FROM` / `SMTP_USERNAME` / `SMTP_PASSWORD` | 未設定（ログ出力） | メール送信 |
| `HIBP_DISABLED` | 未設定 | 設定すると漏洩パスワードのチェックを無効化 |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | 未設定 | 指定すると HTTPS で待ち受ける |

### 使い方の例

```sh
# 管理トークン（bootstrap で表示された client_id / client_secret）
TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials \
  -d 'scope=admin:read admin:write admin:audit:read' http://localhost:8080/t/admin/token | jq -r .access_token)

# テナント・ユーザー・クライアントを作る
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug":"acme","name":"Acme"}' http://localhost:8080/admin/v1/tenants
```

テナントの Discovery は `http://localhost:8080/t/acme/.well-known/openid-configuration`。

## テスト

```sh
docker compose up -d postgres
go test ./...
```

`internal/e2e` が要件を表す E2E テスト。実在の RP ライブラリ（go-oidc・oauth2）、SAML SP（crewjam/saml）、仮想 WebAuthn 認証器を使って HTTPS 越しに検証する。

## ディレクトリ

```
cmd/idaas/            エントリポイント
api/openapi/          OpenAPI（Admin API、OIDC / OAuth 2.0）
internal/
  identity/           テナント・ユーザー・グループ・ロール
  authn/              パスワード・MFA・パスキー・セッション・ワンタイムトークン
  oidc/               OP（クライアント・認可・トークン・ログアウト）
  keys/               署名鍵と JWKS
  federation/         外部 IdP 連携（RP）・SAML IdP
  audit/              Outbox・監査ログ・Webhook
  adminapi/           Admin API（admin.yaml から生成）
  scim/               SCIM 2.0
  web/                ログイン UI と OIDC / OAuth 2.0 エンドポイント
  app/                組み立て
  platform/           DB・暗号・メールなどの基盤
  e2e/                E2E テスト
docs/                 設計ドキュメント
```
