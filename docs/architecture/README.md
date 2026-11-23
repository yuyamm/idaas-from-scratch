# アーキテクチャ

IdaaS from Scratch のアーキテクチャ図をまとめる。図はすべて `.drawio.svg` 形式（draw.io で直接編集でき、Markdown でもそのまま表示される）。

| ドキュメント | 内容 |
|---|---|
| [システムアーキテクチャ](system/README.md) | システムと利用者・外部システムの連携（全体像と主要フロー） |
| [ソフトウェアアーキテクチャ](software/README.md) | IdaaS Server 内部の構造（層・モジュール）と DB 設計 |
| [API 仕様（OpenAPI）](../../api/openapi/README.md) | 外部に公開する API の定義。実装が参照する SSOT として `api/` に置く |

## 図の編集

- VS Code の Draw.io Integration 拡張、または draw.io デスクトップアプリで `.drawio.svg` を直接開いて編集する
- 図は 1 ファイル 1 ページで管理する
