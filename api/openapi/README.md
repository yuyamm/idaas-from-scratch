# API 仕様（OpenAPI）

IdaaS が外部に公開する API の仕様。ドキュメントであると同時に、実装が参照する唯一の定義（SSOT）として扱う。

| ファイル | 対象 | 利用者 |
|---|---|---|
| [admin.yaml](admin.yaml) | Admin API（テナント・ユーザー・グループ・ロール・クライアント・外部 IdP・署名鍵・Webhook 配信先・監査ログ）と Webhook イベント | 管理者・管理ツール・Webhook 受信側 |
| [oidc.yaml](oidc.yaml) | OpenID Connect / OAuth 2.0 のエンドポイント、トークンのクレーム、Back-Channel Logout | RP・Resource Server・M2M クライアント |

- 形式は OpenAPI 3.1
- `oidc.yaml` のリクエスト・レスポンス形式は各 RFC / OpenID 仕様に従う。この定義では本システムが対応する範囲（grant・クライアント認証方式・スコープ・クレーム・既定の有効期限）を確定させる
- SAML（`/t/{tenant}/saml/*`）と SCIM（`/t/{tenant}/scim/v2/*`）は対象外（それぞれの仕様に従う）

システム全体での位置付けは [システムアーキテクチャ](../../docs/architecture/system/README.md) を参照。
