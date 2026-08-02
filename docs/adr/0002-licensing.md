# ADR-0002: コードと文書を別ライセンスにする

- Status: Accepted
- Date: 2026-08-02
- Decision owners: Commons Identity maintainers

## Context

参照実装は企業・共同体・研究者が再利用しやすく、特許許諾を含むpermissive software licenseが必要である。Protocol specification、図、runbook等は、翻訳、引用、派生仕様を可能にしつつ出典と変更を追跡できるcontent licenseが適する。

## Decision

- Source code、tests、configuration、machine-readable examplesはApache License 2.0とする。
- `docs/`、`README.md`、`CONTRIBUTING.md`、`CODE_OF_CONDUCT.md`、`CHANGELOG.md`等の説明文書はCreative Commons Attribution 4.0 International（CC BY 4.0）とする。
- ファイル種別だけで判断しにくい場合は、最も近い`SPDX-License-Identifier`または[`LICENSES/README.md`](../../LICENSES/README.md)のmappingを正規とする。
- Third-party materialは各upstream licenseを維持し、`LICENSES/`またはNOTICEへ記録する。

Contributionを提出した人は、明示的に別指定しない限り、対象artifactの上記licenseでprojectへ提供する。別licenseのcodeやtextをcopyする前に互換性とattributionを確認する。

## Consequences

- Code利用者はApache-2.0のcopyright／patent licenseと再配布条件に従う。
- 文書利用者はCC BY 4.0に従い、creator、license、source、変更を合理的な形で表示する。
- Code snippetが説明文書中にある場合、単独で再利用可能なsnippetはApache-2.0として扱う旨をlicense mapへ記す。

## Alternatives considered

- 全体をApache-2.0: 可能だが、翻訳・改変時の文書帰属がcontent利用者に分かりにくい。
- 全体をCC BY 4.0: software patent licenseとsoftware ecosystemの慣行に適さない。
- Copyleft code license: Operator実装への採用障壁を初期段階で上げるため不採用。ただし公益保護はprotocol requirements、conformance、governanceで追求する。

## Risks and rollback

- Risk: dual-license境界が曖昧になる。Mitigation: license map、SPDX header、review checklistを維持する。
- Risk: incompatible third-party textが混入する。Mitigation: provenance reviewとNOTICE更新をrelease gateにする。
- Rollback: license変更は既に公開された版へ遡及できない。将来版だけを変更し、maintainerと主要contributorの明示的合意、ADR、legal reviewを必要とする。
