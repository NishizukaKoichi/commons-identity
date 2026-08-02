# Commons Identity 文書

このディレクトリは、設計、判断、脅威、運用手順の正規索引です。コードの挙動と文書が食い違う場合、現時点の実装についてはコードとテストを優先し、食い違いをIssueとして記録してください。プロトコル適合性については、公開された仕様と適合試験の両方が必要です。

## まず読む

1. [Commons Identity Protocol 1.0 日本語仕様](specification/commons-identity-1.0.ja.md)
2. [Context Snapshot](context-snapshot.md)
3. [Threat Model](threat-model.md)
4. [Governance and Operator Separation](governance.md)
5. [Security Policy](../SECURITY.md)
6. [Standards Status and Profile Boundary](standards-status.md)

Machine-readable vocabulary: [CI Context v1](contexts/v1.jsonld)（Developer Preview）

## 設計判断

- [ADR-0001: 実験的参照実装として範囲を固定する](adr/0001-project-scope.md)
- [ADR-0002: コードと文書を別ライセンスにする](adr/0002-licensing.md)
- [ADR-0003: CI-Coreを最初の相互運用プロファイルにする](adr/0003-ci-core-profile.md)
- [ADR-0004: Developer Previewの安全境界をfail closedにする](adr/0004-developer-preview-safety.md)

## Runbook

- [ローカルデモ](runbooks/local-demo.md)
- [リリース](runbooks/release.md)
- [第三者セキュリティ監査](runbooks/security-audit.md)

## プロジェクト文書

- [Contributing](../CONTRIBUTING.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [Changelog](../CHANGELOG.md)
- [License map](../LICENSES/README.md)

## 文書のステータス表記

- **Normative**: 適合性判断に使用する要求。
- **Informative**: 背景、例、実装上の助言。
- **Draft**: 変更され得る。安定版の互換性根拠に使わない。
- **Implemented**: リポジトリのテストで確認できる。
- **Planned**: 設計上は存在するが、実装済みとは限らない。

仕様の本文はNormativeとInformativeを分けます。仕様の存在は実装完了を意味しません。
