# ADR-0005: 版タグと公開成果物をGitHub側でも不変にする

- Status: Accepted
- Date: 2026-08-03
- Decision owners: Commons Identity maintainers

## Context

`v0.1.0-preview.1`の公開候補は、Rust、依存関係、Walletの全ゲートを通過した後、Linux上のTauri buildが生成する未追跡`linux-schema.json`を最終clean-tree gateが検出し、成果物組み立て前に停止した。追跡済みsourceに変更はなく、そのworkflow runでは配布assetもGitHub Releaseも作成されなかった。後から履歴を消さないため、同じtagに配布assetなしのwithdrawn Release recordだけを公開した。

この停止はfail closedとして正しい。一方、公開監査で、既存Release拒否がworkflow内の方針に留まり、`v*` tagのupdate／deleteと公開後assetの置換をGitHub側で強制していないこと、長いbuildと公開の間にremote tagが変わり得ることが分かった。「公開済みbytesを置換しない」という主張を実効性のある制約へ変える必要がある。

## Decision

- GitHub Immutable Releasesをrepositoryで有効化する。公開後のtagとassetはGitHub側で変更／削除不能とし、release attestationを生成させる。
- `Immutable version tags` rulesetを`refs/tags/v*`へactive適用する。tag作成は許可するがupdateとdeletionを禁止し、bypass actorは置かない。
- Release workflowは既存のannotated tagだけを受理し、tag object SHAとpeeled source commitをbuild前に記録する。draft作成前と公開直前にremoteの両値を再照合する。
- 標準`GITHUB_TOKEN`はImmutable Releases設定とrulesetのbypass actorを読めないため、release ownerがdispatch前に両方を管理画面または管理者APIで確認し、`PUBLICATION CONTROLS VERIFIED` confirmationを入力する。Workflowは公開可能なruleset条件を公開前に検査し、公開直後のRelease APIで`immutable: true`を必須検証する。管理者credentialはActionsへ保存しない。
- Releaseはdraftとして作成し、digestを記録した全assetをuploadして集合とsizeを検査してからpublishする。既存Releaseは上書きせず停止する。
- Release evidenceにはtag object、source commit、original workflow actor、current attempt actor、run attempt、workflow ref／SHAを記録する。
- Linux CIだけが生成する`apps/wallet/src-tauri/gen/schemas/linux-schema.json`のみを生成物としてignoreする。clean-tree gateは弱めず、未知のpathが残ればpathを表示して停止する。
- `v0.1.0-preview.1` tagは動かさず、配布assetなしのwithdrawn Release recordを残す。修正版は新しい`v0.1.0-preview.2`として公開する。

## Alternatives considered

- `preview.1` tagを修正版へ移動する: 既に公開されたsource identityを書き換え、監査可能性を失うため不採用。
- 「不変」という表現だけを弱め、GitHub設定を変えない: supply-chain境界を運用慣行だけへ依存させるため不採用。
- `git status`から全未追跡fileを除外する: 意図しないgenerator出力やsource追加を見逃すため不採用。
- Asset付きReleaseを一度に公開する: upload途中の失敗とImmutable Releasesの境界が不明瞭になるため、draft-firstへ変更した。

## Consequences

- Version tagは一度pushすると通常操作では更新／削除できない。修正は常に新しいversionで行う。
- 公開後assetは差し替えられない。誤りはRelease note／security advisoryで明示し、新版へ誘導する。
- Upload後・publish前にworkflowが失敗した場合、draftを監査してから、同じ不変tagと同じreview済みbytesで再開するか、draftを取り下げて新versionへ進む必要がある。
- Release workflowは公開可能なtag ruleset条件を公開前に検査する。Immutable Releasesとbypass不在はownerの事前確認で、前者は公開直後の`immutable`検査でも確認する。

## Risks and rollback

- Risk: Repository adminはrulesetやImmutable Releases設定を変更できる。Mitigation: workflowが公開可能なtag ruleset条件を検査し、ownerがImmutable Releasesとbypass不在をdispatch前に確認し、公開直前にremote tag identityを再確認する。公開直後に`immutable`でなければrunを失敗させる。正常な公開済みReleaseにはGitHubのimmutable lockとattestationが残る。
- Risk: 不完全なdraftが次回実行を止める。Mitigation: draft asset一覧とworkflow logを確認し、公開前であることを記録してから明示的に処理する。公開済みReleaseは削除や置換で直さない。
- Risk: 緊急時にもassetを除去できない。Mitigation: 利用停止をRelease noteとsecurity advisoryで告知し、新しいtag／Releaseで修正版を出す。
- Rollback: Workflow自体に欠陥があればRelease publish stepより前で停止し、新versionに修正版workflowを含める。公開済みtagやassetを戻す操作はrollbackとして扱わない。
