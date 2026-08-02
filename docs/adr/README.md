# Architecture Decision Records

ADRは、後から変更理由とrollbackを追跡できるようにするための決定記録です。

| ADR | 状態 | 決定 |
| --- | --- | --- |
| [0001](0001-project-scope.md) | Accepted | 実験的参照実装として範囲を固定する |
| [0002](0002-licensing.md) | Accepted | コードと文書を別ライセンスにする |
| [0003](0003-ci-core-profile.md) | Accepted | CI-Coreを最初の相互運用profileにする |
| [0004](0004-developer-preview-safety.md) | Accepted | Developer Previewの安全境界をfail closedにする |
| [0005](0005-release-immutability.md) | Accepted | 版タグと公開成果物をGitHub側でも不変にする |

新しいADRは`NNNN-short-title.md`とし、Context、Decision、Consequences、Alternatives、Risks and rollbackを含めます。Supersededになっても削除せず、置換先へリンクします。
