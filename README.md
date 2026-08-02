# Commons Identity Protocol

> [!WARNING]
> **実験的・未監査の参照実装です。** 本リポジトリはプロトコル設計と相互運用実験のためのものであり、本番の本人確認、入退室、雇用、医療、金融、行政その他の高リスク用途には使用できません。実運用には、独立したセキュリティ監査、プライバシー／法務レビュー、複数実装間の相互運用試験が必要です。

Commons Identityは、企業アカウントの代わりに、**本人が持つ鍵と、共同体ごとに分離された関係**で身分を表すための実験的プロトコルです。

学校では学生、会社では従業員、研究チームでは研究者として存在できますが、それらを外部から自動的に束ねる世界共通IDは作りません。すべての関係を束ねられるのは、本人のIdentity Vaultだけです。

[ライブUX Preview](https://nishizukakoichi.github.io/commons-identity/) · [English summary](#english) · [仕様書](docs/specification/commons-identity-1.0.ja.md) · [文書一覧](docs/README.md) · [セキュリティ報告](SECURITY.md)

## このリポジトリで目指すもの

- 共同体ごとに異なる鍵、識別子、人格領域を使う
- W3C Verifiable Credentials Data Model 2.0を基礎に、OpenID4VCI／OpenID4VPとの接続境界を明確にする
- Community Authority（権威）とOperator（運営受託者）を分離する
- 端末単位の鍵と資格失効、Recovery Kit、標準Exportを検証可能にする
- 最小開示、短い保持期間、Consent Receiptを既定値にする
- 特定企業、クラウド、ウォレット、暗号資産へ依存しない

## 目指さないもの

- 世界共通の個人番号、一人一人格の証明、中央Trust Registry
- 汎用信用スコア、共同体横断Reputation API
- 暗号資産、売買可能トークン、決済、広告識別
- 法的本人確認サービスの代替
- 暗号だけによる強要、端末マルウェア、悪意あるVerifierの完全な解決

## 現在の実装境界

`commons-identity/1`の36節仕様は設計目標です。リポジトリ内に存在するコードだけが実装済み範囲であり、仕様に記載された機能が動作することを意味しません。

初期マイルストーンはCI-Coreのローカルデモです。公開時点の境界は次のとおりです。

| 領域 | Developer Previewの状態 |
| --- | --- |
| Rust Core | Persona／端末鍵分離、Membership／Role VC、holder binding、提示・replay拒否、status、Recovery Kit／`.cia`、暗号化SQLiteを実装 |
| HTTP参照サービス | OID4VCI／OID4VPの限定profile、端末失効、署名済みAudit、移行bundleの検証とstageを実装。永続鍵／状態がないためloopback demo専用 |
| Commons Wallet | Tauri／WebのUX shell。公開Previewは架空のメモリ内データだけを使い、Rust Coreとはまだ接続していない |
| Operator Migration | 暗号化export、3-of-5署名承認、target側の検証・stageまで。DID更新後のlive activationは未実装 |
| CI-Private-BBS／Guardian Recovery／Mesh | 未搭載。仕様上の将来設計のみ |

実ネットワーク上のOpenID4VCI／OpenID4VP完全相互運用と`did:webvh` resolver／履歴実装も未達です。

Developer PreviewのCI-CoreはVCDM 2.0の`application/vc`／`application/vp`と`eddsa-jcs-2022`へ固定し、`community` linkabilityだけを受理します。選択的開示、Verifier間unlinkability、`none`／`verifier-domain`は提供しません。詳細は[Standards Status](docs/standards-status.md)を参照してください。

実装状況の根拠は、[Context Snapshot](docs/context-snapshot.md)、テスト、[CHANGELOG](CHANGELOG.md)です。

## すぐ試す

必要環境、正確な手順、期待結果は[ローカルデモrunbook](docs/runbooks/local-demo.md)を参照してください。最短経路は次のとおりです。

```sh
make check
make demo
```

生成物にはデモ用の鍵と資格情報が含まれる可能性があります。実在人物の情報や本番秘密鍵を入力しないでください。

HTTP flowを確認する参照サービスは、永続鍵／状態をまだ持たないためloopback限定です。

```sh
cargo run -p commons-identity-service -- --demo
```

表示されるEnrollment CodeとAdmin Tokenは、その一時プロセスだけに使用してください。

## 構成

```text
crates/
  commons-identity-core/       鍵・資格・復旧・検証のドメインCore
  commons-identity-service/    交換可能なHTTP参照サービス
  commons-identity-cli/        再現可能なローカルデモと検証CLI
apps/wallet/                   Tauri Wallet UX shell（Core未接続）
docs/specification/            プロトコル仕様
docs/adr/                      設計判断
docs/runbooks/                 再現可能な運用手順
```

## セキュリティとプライバシー

公開Issueへ脆弱性の詳細、秘密鍵、Recovery Kit、個人情報を投稿しないでください。[SECURITY.md](SECURITY.md)の非公開報告手順を利用してください。設計上の前提と残存リスクは[Threat Model](docs/threat-model.md)にあります。

## 参加する

IssueやPull Requestを歓迎します。先に[CONTRIBUTING.md](CONTRIBUTING.md)、[Governance](docs/governance.md)、[Code of Conduct](CODE_OF_CONDUCT.md)を確認してください。互換性を主張する変更には、仕様の該当節と再現可能な適合試験が必要です。

## ライセンス

- ソースコード、設定、テスト、実行可能な例: [Apache License 2.0](LICENSE)
- `docs/`、`README.md`、その他の説明文書: [Creative Commons Attribution 4.0 International](LICENSES/CC-BY-4.0.md)

詳細な境界と帰属方法は[LICENSES/README.md](LICENSES/README.md)を参照してください。

---

## English

Commons Identity is an experimental protocol and unaudited reference implementation for holder-controlled, community-scoped credentials. It intentionally does **not** create a universal person identifier or cross-community reputation score. Each community relationship uses a separate persona, keys, and identifiers; only the holder's local Identity Vault may bring them together.

This repository is for research, interoperability work, and local demonstrations—not production identity infrastructure. Before real-world use it requires an independent security audit, privacy and legal review, and interoperability testing with independently developed implementations.

The Developer Preview CI-Core profile uses VCDM 2.0 `application/vc` / `application/vp` with `eddsa-jcs-2022`. It supports community linkability only; selective disclosure and unlinkable or verifier-domain presentations are not CI-Core features.

Start with the [protocol specification (Japanese)](docs/specification/commons-identity-1.0.ja.md), [documentation index](docs/README.md), [contribution guide](CONTRIBUTING.md), and [security policy](SECURITY.md).

> **My identity is not an account borrowed from a company. It is the set of keys I hold and relationships I have formed.**
