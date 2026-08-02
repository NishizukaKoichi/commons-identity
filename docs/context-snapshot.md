# Context Snapshot

## Header

- Date: 2026-08-02
- Scope: Commons Identity Protocol 1.0と実験的参照実装の初期公開
- Audience: 実装者、セキュリティ研究者、共同体運営者、相互運用試験参加者
- Canonical sources:
  - Repo: このGitリポジトリの`main`
  - Protocol: [`docs/specification/commons-identity-1.0.ja.md`](specification/commons-identity-1.0.ja.md)
  - Decisions: [`docs/adr/`](adr/)
  - Standards audit: [`docs/standards-status.md`](standards-status.md)
  - Current behavior: コード、テスト、リリース時の検証記録

## Goal and Success Criteria

- Goal: 共同体ごとに分離されたholder-controlled identityを、誰でも検査、実行、拡張できるOSSの仕様と参照実装として公開する。
- Success criteria:
  - 36節のプロトコル設計が版管理された仕様として読める。
  - CI-Coreのローカルデモが再現可能で、build／test／lint／typecheckが成功する。
  - 実装済み、planned、実験的な機能を区別できる。
  - AuthorityとOperatorの権限境界、脅威、復旧、移行をレビューできる。
  - Apache-2.0のコードとCC BY 4.0の文書を、第三者が再利用できる。
- Out of scope for the first milestone:
  - 本番配備、法的本人確認、認証認可製品としての保証
  - CI-Private-BBS、Guardian Recovery、Arcane Commons Mesh adapterの実装
  - Operator Migration bundleのlive activation
  - Rust Coreへ接続した配布可能なnative Wallet
  - 世界共通ID、汎用Reputation、暗号資産、決済

## Current State

- What exists today: CI-CoreのRust実装、限定OID4VCI／OID4VP flowを持つloopback専用の一時HTTPサービス、再現可能なCLI demo、架空データだけを扱うWallet UX shell、暗号化migration bundleの検証・stage、プロトコル仕様、ADR、脅威モデル、公開OSS運用文書。
- What is missing: 永続するAuthority／Issuer／Verifier鍵とservice state、Rust Coreへ接続したnative Wallet、migrationのlive activation、Guardian Recovery、CI-Private-BBS、完全な`did:webvh` resolver／履歴、独立した第三者監査、独立実装との相互運用結果、実ネットワークでの完了証拠、実環境の運用実績、正式な適合認証制度。
- Latest known status (2026-08-03): `0.1.0-preview.2` Developer Preview。本番利用や互換性の保証はない。具体的な実装可否はテスト結果とCHANGELOGを参照する。

## Constraints

- Tech: Rust Core、Tauri／Web UX shell、交換可能なHTTP Operator設計。参照HTTP serviceは永続backendができるまでloopback以外を拒否する。特定クラウドを必須にしない。
- Security/compliance: 未監査。実在人物の個人情報・本番鍵をデモへ投入しない。高リスク用途に使わない。
- Protocol: 世界共通個人ID、識別子の領域横断再利用、Root Secretの送信、汎用信用スコア、売買可能トークンは禁止。
- Reproducibility: ローカル手順、検証コマンド、リリース証跡を版管理する。

## Decisions (With Dates)

- 2026-08-02: 実験的かつ未監査の参照実装として公開する。Production-readyを名乗らない。Source: [ADR-0001](adr/0001-project-scope.md)
- 2026-08-02: コードはApache-2.0、文書はCC BY 4.0とする。Source: [ADR-0002](adr/0002-licensing.md)
- 2026-08-02: Developer Preview CI-CoreをVCDM 2.0 `application/vc`／`application/vp`と`eddsa-jcs-2022`へ固定し、`community` linkabilityだけを受理する。CI-Private-BBSは監査・相互運用後にopt-inで進める。Source: [ADR-0003](adr/0003-ci-core-profile.md)
- 2026-08-02: 脆弱なGuardian依存を削除し、Credential保存時検証、署名済み3-of-5 governance、暗号化migration、stage-only import、loopback-only serviceを公開安全境界として固定する。Source: [ADR-0004](adr/0004-developer-preview-safety.md)

## Open Questions

- Blocking for production: 第三者監査、プライバシー／法務レビュー、複数独立実装による相互運用、鍵管理とインシデント対応主体。
- Non-blocking for local research: BBSプロファイルの採用時期、Guardian UX、Operatorの具体的ホスティング先、Meshバックアップadapter。

## Next Actions

- Maintainers → CI-Core適合試験を自動化し、機能表をテストへ結びつける。
- Independent implementers → 同じfixtureを使った発行、提示、失効、Export／Importを独立実装する。
- Security reviewers → [監査runbook](runbooks/security-audit.md)に沿って設計・コード・依存関係・UXを評価する。

## Risks

- 仕様の網羅性が実装完成と誤認される。Mitigation: 全入口に未監査警告を置き、実装根拠をテストとCHANGELOGへ限定する。
- 暗号学的妥当性が社会的信頼性と混同される。Mitigation: Trust Policyをローカル判断とし、発行者の信頼を署名検証から分離する。
- Privacy機能の誤設定が相関可能性を増やす。Mitigation: Persona分離、最小開示、短期保持、明示的linkabilityを安全な既定値にする。
