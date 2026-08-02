# ADR-0001: 実験的参照実装として範囲を固定する

- Status: Accepted
- Date: 2026-08-02
- Decision owners: Commons Identity maintainers

## Context

Commons Identity Protocol 1.0は、鍵、資格、復旧、共同体統治、Operator移行を含む大きな設計である。仕様の網羅性だけでproduction identity infrastructureとして安全とは言えない。本人確認、雇用、入退室、行政等へ誤用されれば、誤拒否、追跡、資格喪失、account takeoverが現実の被害になる。

初期公開で検証できる価値は、CI-Coreのデータ境界、Persona分離、holder binding、端末単位失効、Recovery Kit、Authority／Operator分離を、ローカルかつ再現可能な形で議論できることである。

## Decision

本リポジトリを**実験的・未監査の参照実装**として公開する。最初の範囲は次に限定する。

- `commons-identity/1`の公開Draft仕様
- Rust共通Core、交換可能な参照HTTP service、CLI demo
- macOS向けTauri Walletの実験UI
- CI-CoreのMembership／Role Credential
- Recovery Kit、端末単位失効、Operator Migrationの検証可能な最小flow

CI-Private-BBS、production deployment、法的identity proofing、Guardianの実運用、特定cloud統合、正式なconformance certificationは初期完成条件に含めない。未実装機能をREADMEやUIで利用可能と表示しない。

Production利用のgateは、独立した第三者security audit、privacy／legal review、独立実装間interoperability、運用runbookとincident ownership、全適合試験の公開結果とする。

## Consequences

- 利用者はリポジトリを安全に研究・実験できるが、本番保証は得ない。
- 機能表にはImplemented／Planned／Experimentalを明記する必要がある。
- Demoへ実在人物の個人情報やproduction keyを投入してはならない。
- 早い段階でAPIを変更できる。破壊的変更はCHANGELOGへ記録する。

## Alternatives considered

- 仕様だけ公開する: 実行可能な検証と相互運用fixtureがなく、設計欠陥を発見しにくいため不採用。
- 最初からproduction-ready製品として公開する: 監査と運用証拠がなく、危険な保証になるため不採用。
- BBSを最初の必須profileにする: upstream仕様と実装の成熟度が不足するため延期。

## Risks and rollback

- Risk: 警告を無視して本番利用される。Mitigation: README、spec、UI、release notesへ未監査表示を置く。
- Risk: 範囲が狭すぎてprivacy目標を誤解される。Mitigation: CI-Coreのlinkability限界を仕様と脅威モデルへ明記する。
- Rollback: 重大な設計欠陥が見つかった場合は該当releaseをyank／非推奨化し、demoを停止してsecurity advisoryを公開する。既存tagや履歴は削除しない。
