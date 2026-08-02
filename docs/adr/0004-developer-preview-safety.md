# ADR-0004: Developer Previewの安全境界をfail closedにする

- Status: Accepted
- Date: 2026-08-02
- Decision owners: Commons Identity maintainers

## Context

初期実装のsecurity reviewで、未修正のRUSTSEC-2024-0398を持つ`sharks 0.5.0`、署名ではないMigration quorum label、live stateを即時置換するImport、未検証CredentialのWallet保存、再起動で失われるHTTP service鍵／状態が見つかった。最終reviewでは、同一鍵を複数controller IDへ割り当てるquorum collapse、device ID／holder key衝突、未来時刻のStatus、`verificationMethod`のDID部分の未検証、秘密値の非zeroize中間bufferも見つかった。これらをDeveloper Previewという表示だけで残せば、実装利用者が安全境界を誤る。

## Decision

- Guardian Recovery実装と`sharks`依存を配布物から削除する。仕様上の将来設計と、未搭載を明示するWallet UIだけを残し、CI-Core適合をclaimしない。
- WalletはCredential保存前に、Authorityが許可したIssuer key、Data Integrity proof、期限、community、device holder binding、署名済みrevocation status参照を検証する。失効時の更新対象は呼出側の数値ではなくVC内の署名済みstatus entryから導出する。
- Operator Export／Importは、設定済み5 controller鍵のうち異なる3鍵によるEd25519署名を要求する。承認はaction hash、nonce、時刻へ束縛し、再利用を拒否する。
- 5 controllerはIDだけでなく公開鍵もすべて異ならなければならない。Community Profile、Audit Entry、Migration Bundleは期待するAuthority DIDと鍵を連結した完全な`verificationMethod`へ一致させる。
- 一つのpersona-scoped device IDはmemberとholder keyを変更できず、同じholder keyを別device IDへ再利用できない。deviceごと／service全体のcredential instance数を制限する。
- 未来時刻のStatus checkpointはactiveとせずunknownへ落とす。秘密値はredacted Debug、zeroize-on-drop型、zeroizing serde中間bufferを使う。
- member registry envelopeはX25519 shared secretからHKDF-SHA-256で鍵を導出し、community、source Operator、target OperatorをKDF infoとAEAD AADへ束縛する。
- Importは検証済みBundleをstageするだけで、live registry、status、auditを変更しない。activationはdid:webvh更新、monotonic checkpoint、旧委任失効を実装する別工程まで未実装とする。
- Durable protected stateがない参照HTTP serviceは`--demo`かつloopbackでのみ起動する。

## Alternatives considered

- 既知advisoryを「experimental」としてallowlistする: 暗号部品であり、利用可能APIが残るため不採用。
- Admin TokenだけでMigrationを許可する: Authority／Operator分離と3-of-5要件を破るため不採用。
- Import時に即時activationする: DID履歴とrollback防止が未実装のため不採用。
- 独自SHA-256連結KDFを維持する: domain separationの監査surfaceが増えるため、標準HKDFへ置換した。

## Consequences

- Guardian Recoveryは仕様に存在しても実装機能ではない。
- HTTP demoは研究用に再現できるが、再起動継続や外部公開はできない。
- Migrationは署名、暗号化、Bundle検証、stageまで試験できる。production activationをclaimできない。
- `hkdf`依存を追加し、`sharks`依存を削除した。
- Archive v1のRecovery Configurationから未実装Guardian状態を削除した。公開前のformatであり、旧形式互換はclaimしない。

## Risks and rollback

- Risk: 将来のGuardian実装が同じ問題を再導入する。Mitigation: 別profile、dependency audit、negative vector、専門家reviewを必須とする。
- Risk: loopback guardをforkが外す。Mitigation: 警告、test、release checklistでproduction非対応を明示する。
- Risk: lock／quota設計が大規模運用の性能要件を満たさない。Mitigation: Developer Previewでは小さい上限でfail closedとし、永続backend設計時に別ADRで置換する。
- Rollback: HKDF envelopeに欠陥が見つかった場合、`enc:v1`を再解釈せず新しいenvelope versionを発行する。重大な欠陥ではMigration endpointをfail closedで停止する。
