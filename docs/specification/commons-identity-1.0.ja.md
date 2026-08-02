# Commons Identity Protocol 1.0

- **プロトコル識別子:** `commons-identity/1`
- **文書状態:** Developer Preview
- **実装状態:** 実験的・未監査の参照実装。CI-Coreも安定版ではない。
- **最終更新:** 2026-08-02
- **文書ライセンス:** CC BY 4.0

> [!CAUTION]
> 本仕様は、実運用可能な本人確認基盤であることを保証しない。Production利用には、独立した第三者セキュリティ監査、プライバシー／法務レビュー、複数の独立実装による相互運用試験、運用主体とインシデント対応体制が必要である。

## 文書の読み方

本文の「しなければならない」「禁止する」はNormative requirement（MUST／MUST NOT）、「推奨する」はSHOULD、「できる」はMAYを表す。例、背景説明、既定値の根拠はInformativeである。

仕様に記載された機能が参照実装に存在するとは限らない。実装状況はテストとCHANGELOGで判断する。公開時点でCI-Private-BBS、Digital Credentials API、Guardian Recoveryは参照実装に未搭載である。Operator Migrationは暗号化bundleのexport、署名承認、target側の検証・stageまでで、live activationは未実装である。

Commons Identityは「世界中で同じ人間であることを証明する万能ID」ではない。

本人は学校では学生、会社では従業員、研究チームでは研究者、地域では住民、家族では家族として存在する。それらを外部から自動的に結びつける共通番号は作らない。すべての関係を束ねられるのは、本人のIdentity Vaultだけである。

資格情報の表現には[W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)（W3C Recommendation、2025-05-15）を用いる。発行境界には[OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)（OpenID Final Specification、2025-09-16）、提示境界には[OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)（OpenID Final Specification、2025-07-09）を用いる。外部標準の成熟度はCommons Identity自身の完成度を意味しない。

## 1. 絶対に破ってはならない設計原則

Commons Identity準拠システムは、次の条件を満たさなければならない。

1. 世界共通の個人IDを作らない。
2. メールアドレス、電話番号、法的氏名を識別鍵として使用しない。
3. 本人のRoot Secretを、共同体、運営者、発行者、検証者へ渡さない。
4. 共同体ごとに異なる鍵、識別子、人格領域を使用する。
5. 資格証明は、目的、共同体、権限、期限を必ず持つ。
6. 資格証明は秘密鍵またはholder secretへ結びつけ、譲渡不能にする。
7. 評判を別の共同体へ自動移植しない。
8. 資金、ストレージ、労働量、保有資格の多さを投票権へ変換しない。
9. 運営会社と共同体の権威を分離する。
10. 運営者が消えても、本人の身分と共同体の証明履歴を移行できるようにする。
11. すべての秘密鍵、資格証明、履歴を、特定のウォレット企業から書き出せるようにする。
12. 暗号資産、売買可能なトークン、信用スコア、広告識別子を組み込まない。

一つでも反する実装は、Commons Identity互換を名乗ることができない。

## 2. システムを構成する主体

**Holder**は本人である。資格証明を受け取り、保存し、必要な情報だけを提示する。

**Commons Wallet**は本人が所有するアプリである。秘密鍵、資格証明、共同体ごとのPersona、提示履歴、Recovery Kitを管理する。

**Community Authority**は学校、会社、家族、研究チーム、地域組織などの共同体そのものを表す。Operatorとは別の存在として扱う。

**Issuer**はCommunity Authorityから限定された発行権限を委任され、会員資格、役割、技能、権限などを発行する。

**Verifier**は資格証明を確認するサービスまたは人物である。社内システム、研究資料庫、建物の入退室装置、地域サービスなどが該当する。

**Operator**はサーバーやデータベースを運用する主体である。共同体自身でも外部企業でもよい。ただし、運営しているという理由だけで共同体の所有者にはならない。

**Guardian**は本人が選んだ復旧協力者である。単独ではIdentity Vaultを復元できない。

**Witness**はCommunity Authorityの鍵変更やOperator交代を監視し、観測した変更へ共同署名する主体である。Witnessの署名は、社会的・法的正当性を自動的に保証しない。

## 3. 全体構造

```text
┌──────────────────────────────┐
│ 本人のCommons Wallet         │
│                              │
│ Identity Vault               │
│ ├─ Recovery Root             │
│ ├─ Device Keys               │
│ ├─ Community Persona A       │
│ ├─ Community Persona B       │
│ ├─ Credentials               │
│ └─ Consent Receipts          │
└──────────────┬───────────────┘
               │
       発行 OpenID4VCI
       提示 OpenID4VP
               │
┌──────────────▼───────────────┐
│ Community Authority          │
│ ├─ Governance Keys           │
│ ├─ Issuer Delegations        │
│ ├─ Policies                  │
│ ├─ Status Lists              │
│ └─ Signed Audit Log          │
└──────────────┬───────────────┘
               │ 限定された証明
┌──────────────▼───────────────┐
│ Verifier / Community Service │
└──────────────────────────────┘
```

サーバーは本人のIdentity Vaultを保持してはならない。

Issuerは、自分が発行した資格証明だけを知る。他の共同体から何を発行されているかを、プロトコル上知ることができてはならない。

Verifierは、本人がその取引で提示した情報だけを見る。Wallet内の資格一覧を取得できてはならない。

## 4. 本人側の鍵構造

### Recovery Root Secret

Identity Vaultを初めて作成するとき、WalletはCSPRNGから256ビットの`Recovery Root Secret`を生成する。

これは個人番号ではない。公開鍵に変換せず、ネットワーク上へ一度も送信せず、資格証明への署名にも使わない。役割はIdentity Vaultの復旧情報を守ることだけである。

### Vault Control Key

`Vault Control Key`は、新しい端末の追加と古い端末の失効に使う内部鍵である。その公開情報も原則としてIdentity Vaultの外へ出さない。複数の共同体を同一人物として結びつけられないようにするためである。

### Device Keys

各端末は個別の署名鍵と暗号化鍵を持つ。推奨構成は署名にEd25519、鍵共有にX25519を使う。秘密鍵はOSのSecure Enclave、Keychain、TPM等が利用できる場合にはそこへ保存する。ただし、特定メーカーのハードウェアを必須にはしない。

新しい端末は、既存端末、Recovery Kit、またはGuardian Recoveryによって承認される。

### Community Persona

本人が共同体へ参加するたび、Walletは新しい`Community Persona`を作る。

```text
community_id
local_subject_id
persona_signing_keys
persona_holder_secret
persona_nym_secret
device_credential_instances
credential_inventory
local_display_name
community_policy_hash
```

`local_subject_id`は128ビット以上のCSPRNG出力から生成する。同じ値を別の共同体で再利用してはならない。法的氏名、メールアドレス、電話番号、他の共同体の識別子から導出してはならない。

したがって、会社と学校がデータを持ち寄っても、Commons Identityの識別情報だけから同一人物だと判断できない設計にする。[VC Data Model 2.0のPrivacy Considerations](https://www.w3.org/TR/vc-data-model-2.0/#privacy-considerations)が警告するように、長期間または複数ドメインで使う識別子や署名情報は相関追跡に利用され得る。実装は、単一オリジン、選択的開示、使い捨て識別子等の適用可能な対策を選ぶ。

## 5. 共同体の身分

Community Authorityの識別には、原則として[DIF-hosted `did:webvh:1.0`](https://identity.foundation/didwebvh/v1.0/)を使用する。これはW3C Recommendationではないため、実装は仕様版を固定し、独立したリゾルバとの相互運用を確認しなければならない。

Release evidenceは使用した`did:webvh`仕様snapshotまたは実装commit、`portable`設定、hash algorithm、cryptosuite、公式／独立test vectorの結果を記録する。単に「did:webvh対応」とだけ表示してはならない。

`did:webvh`は、公開鍵とservice endpointの変更履歴を暗号学的に連結し、pre-rotation、Witness、ドメイン移行の仕組みを定義する。現在のサーバードメインと共同体そのものを分離できる。

```text
did:webvh:<SCID>:identity.example.org:communities:research-lab
```

識別の連続性は、初期状態から導出された`SCID`と検証可能な変更履歴に依存する。ドメイン名だけをAuthorityの根拠にしてはならない。

Community Authorityは最低でも、署名されたCommunity Profileとして次を公開する。

```json
{
  "protocol": "commons-identity/1",
  "community": "did:webvh:<SCID>:identity.example.org:communities:research-lab",
  "name": "Example Research Community",
  "credentialIssuer": "https://issuer.example.org",
  "supportedProfiles": ["ci-core-1", "ci-private-bbs-1"],
  "policyRegistry": "https://identity.example.org/policies/",
  "statusServices": ["https://identity.example.org/status/"],
  "auditCheckpoints": "https://identity.example.org/audit/",
  "mirrors": [
    "https://mirror-a.example.net",
    "https://mirror-b.example.net",
    "https://mirror-c.example.edu"
  ],
  "governance": {
    "controllerCount": 5,
    "updateThreshold": 3,
    "witnessThreshold": 2
  },
  "operator": {
    "id": "did:webvh:<OPERATOR_SCID>:operator.example.org",
    "validUntil": "2026-12-31T23:59:59Z"
  }
}
```

`supportedProfiles`には、そのdeploymentが適合試験を通過して実際に受理するprofileだけを載せる。上例の`ci-private-bbs-1`は構造説明用であり、Developer Previewの参照Operatorが広告してよいことを意味しない。

`did:webvh`自体は3-of-5 governanceを強制しない。`updateThreshold`はCommons Governance Layerの要件であり、DID update proofを作る前に、閾値を満たす署名済み承認記録をAudit Logへ固定しなければならない。Witness thresholdもAuthority controller thresholdとは別に評価する。

## 6. 権威と運営者を分離する

Community Authorityは共同体の憲法に相当する。Operatorは、その時点でサーバーを動かす委託先にすぎない。

Operatorには、たとえば次の限定資格を発行する。

```text
OperatorCredential
scope:
  - credential_issuance_hosting
  - status_list_publishing
  - encrypted_member_registry_storage
  - audit_log_relay
validUntil:
  90 days
```

Operator Credentialは自動更新してはならない。Community Authorityの定足数を満たす承認が必要である。

Operatorが倒産、買収、停止、敵対化した場合、共同体は委任を失効させ、新しいOperatorへ切り替えられる。OperatorはCommunity AuthorityのGovernance Keyを持ってはならない。運営者が単独で共同体を乗っ取れない構造にする。

## 7. 資格証明の種類

Commons Identity 1.0は次を定義する。

- **CommunityMembershipCredential:** ある共同体の会員であることだけを証明する。
- **CommunityRoleCredential:** 研究者、教師、管理者、従業員、保護者等、その共同体内の役割を証明する。
- **CommunityCapabilityCredential:** 特定操作を実行できることを証明する。「文書を閲覧」と「文書を削除」は別資格にする。
- **CommunityQualificationCredential:** 修了、技能、認定、研修受講等を証明する。
- **CommunityRelationshipCredential:** 特定人物、グループ、プロジェクトとの関係を証明する。
- **ContextualStandingCredential:** 共同体内で限定された実績や状態を証明する。ただし万能な信用スコアにしてはならない。

認められる例:

```text
2026年4月から6月まで、保存ノード監査に12回合格した
2026年8月31日まで、モデレーターとして活動できる
安全研修を2026年7月12日に修了した
```

禁止する例:

```text
信用スコア: 843
良い人間度: 91
全共同体総合ランク: A+
経済価値: 7280
```

## 8. 資格証明の共通構造

資格証明には、最低限次を含める。VC Data Model 2.0では`@context`が必須であり、先頭要素は`https://www.w3.org/ns/credentials/v2`でなければならない。Commons固有語彙のContext URLは安定版公開時に固定しなければならない。

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://nishizukakoichi.github.io/commons-identity/contexts/v1.jsonld"
  ],
  "type": [
    "VerifiableCredential",
    "CommunityMembershipCredential"
  ],
  "issuer": "did:webvh:<COMMUNITY_SCID>:identity.example.org",
  "validFrom": "2026-08-02T00:00:00Z",
  "validUntil": "2026-11-02T00:00:00Z",
  "credentialSubject": {
    "community": "did:webvh:<COMMUNITY_SCID>:identity.example.org",
    "membership": "active",
    "scope": ["community:enter"],
    "policyHash": "sha256-<POLICY_HASH>"
  },
  "holderBinding": {
    "type": "Multikey",
    "publicKeyMultibase": "z<PERSONA_DEVICE_HOLDER_PUBLIC_KEY>"
  },
  "credentialStatus": {
    "id": "https://identity.example.org/status/2026-08/revocation#48291",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "48291",
    "statusListCredential": "https://identity.example.org/status/2026-08/revocation"
  }
}
```

Commons固有termは上記のversioned Contextで定義する。CI-Coreは`eddsa-jcs-2022`の検証時にremote Contextを取得せず、許可された正確なContext URLをJCS対象bytesの一部として扱う。語彙の意味検証が必要な実装は同一versionのlocal snapshotと期待hashをbundleする。Context URLの応答によって署名検証の意味やbytesを実行時に変化させてはならない。

`holderBinding`はCommons IdentityのCI-Core拡張である。Issuerは発行時のproofが示したdevice holder keyをCredentialへ結びつけ、VerifierはPresentation proofの検証鍵と一致することを確認しなければならない。発行時proofだけをholder bindingとして扱ってはならない。

公開Credentialの`holderBinding`へ物理端末、OS、Vault全体のdevice identifierを含めてはならない。holder public key自体をCommunity Personaと端末の組合せごとに独立生成し、Walletは内部のVault device recordとの対応をlocal-only mappingで保持する。発行flowで使う`personaDeviceId`もPersonaごとのrandom値とし、Verifierへ開示しない。

通常、`credentialSubject.id`は含めない。継続的なローカル識別が必要な場合だけ、共同体限定のランダム識別子を入れる。その識別子は、使用するprofileが選択的開示を提供する場合には選択的開示可能にする。

一枚の資格証明へ氏名、住所、生年月日、役割、技能、評判を詰め込んではならない。用途ごとに資格証明を分割する。生年月日そのものではなく「一定年齢以上」のように、目的へ必要な結果を資格化する。

## 9. 二つのプライバシープロファイル

### CI-Core Profile

`ci-core-1`は、W3C VC Data Model 2.0、[Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)、[Data Integrity EdDSA Cryptosuites 1.0](https://www.w3.org/TR/vc-di-eddsa/)の`eddsa-jcs-2022`を用いるDeveloper Preview profileである。JSON Canonicalization Scheme（JCS）のbyte-level canonicalization fixtureを公開し、remote JSON-LD Contextを署名検証中に取得してはならない。

OpenID4VCI／OpenID4VP 1.0 Finalに組み込まれた`ldp_vc` profileはVCDM 1.1を参照しており、VCDM 2.0 profileではない。Commons CI-Coreはdeployment-defined formatとして、CredentialにVCDM 2.0のmedia type `application/vc`、Presentationに`application/vp`をformat identifierとして使い、v2 Contextと`eddsa-jcs-2022`を固定する。`ldp_vc`をVCDM 2.0 Credentialのformatとして広告せず、generic `ldp_vc` interoperabilityをclaimしてはならない。

端末ごとに異なるCredential instanceを発行する。選択的開示に依存せず、資格を用途ごとに細かく分割して情報量を抑える。

EdDSA cryptosuiteは、後からの選択的開示やunlinkable disclosureを提供しない。同じCredentialを繰り返し提示すれば、同じ共同体内および提示内容を共有するVerifier間で相関され得る。CI-Coreは、BBSのanonymous holder binding、`nym_domain` pseudonym、提示ごとのunlinkabilityを名乗ってはならない。

### CI-Private-BBS Profile

`ci-private-bbs-1`は、[Data Integrity BBS Cryptosuites v1.0](https://www.w3.org/TR/vc-di-bbs/)の`bbs-2023`を用い、元Credentialから必要属性だけを選択して提示ごとに異なるderived proofを作る実験profileである。

anonymous holder bindingと`nym_domain`を使う。同じVerifierには本人の明示的許可がある場合だけ安定したpseudonymを提示し、別Verifierには異なるpseudonymを生成する。図書館用と勤怠用のpseudonymは一致してはならない。

BBS仕様は、選択的開示、unlinkable derived proofs、anonymous holder binding、Verifier domainごとのpseudonymを定義するが、2026-08-02時点ではW3C Candidate Recommendation Draft（2026-04-07）であり、work in progressである。CI-Private-BBSはCI-Coreの必須適合範囲から除外し、相互運用試験を通過した実装でだけopt-inにする。

## 10. 端末ごとの資格証明

一つの秘密鍵をすべての端末へ無条件に複製してはならない。スマートフォン、macOS端末、Windows PCは、それぞれ異なるholder keyを持つ。

Issuerは同じ資格内容について、端末ごとに異なるholder bindingとstatus indexを持つCredential instanceを発行する。スマートフォンを紛失した場合、その端末用Credentialだけを失効し、他の端末用Credentialは維持できる。

OpenID4VCI 1.0のbatch credential endpointを使う場合も、各Credential requestに異なるproofとholder keyを結びつけ、各instanceを独立にstatus管理しなければならない。単一鍵への複製をbatch issuanceと呼んではならない。

## 11. 発行手順

1. Community Authorityが招待情報またはCredential Offerを発行する。
2. WalletがCommunity AuthorityのDID履歴、Witness、Operator委任、Policyを検証する。
3. Walletが新しいCommunity Personaを生成する。
4. Walletが、共同体の要求情報、目的、保持期間を本人へ表示する。
5. 共同体固有の本人確認を行う。
6. Walletが端末固有holder keyによるproofを作る。
7. OpenID4VCIを通してCredentialを受け取る。Credential endpointは固定パスを仮定せず、Credential Issuer Metadataの`credential_endpoint`から発見する。CI-CoreのCredential configurationはformat identifier `application/vc`を広告する。
8. Walletが内容、期限、VC issuer、status endpoint、policy hash、holder bindingを確認する。
9. WalletがCredentialをIdentity Vaultへ暗号化保存する。
10. Issuerが発行記録の署名済みReceiptを本人へ渡す。

OpenID4VCIのCredential Issuer identifierはHTTPS URLであり、VC内の`issuer`に用いるCommunity Authority DIDとは同一identifierではない。Commons profileでは、Issuer Metadata、Community Profile、OperatorCredential、VC issuer DIDの結び付きを検証し、不一致を拒否しなければならない。

Credential Issuer MetadataはCommons拡張として、次のAuthority署名済みbindingまたはそのcontent-addressed URLを示す。`credentialIssuer`はMetadataのIssuer identifierと正規化後に完全一致し、`community`はVC `issuer`と一致しなければならない。redirect、同形異字host、期限切れbindingを受理しない。

```json
{
  "type": "CIIssuerBinding",
  "protocol": "commons-identity/1",
  "community": "did:webvh:<COMMUNITY_SCID>:identity.example.org",
  "credentialIssuer": "https://issuer.example.org",
  "operatorCredentialHash": "sha256-<OPERATOR_CREDENTIAL_HASH>",
  "validUntil": "2026-11-02T00:00:00Z",
  "proof": "<COMMUNITY_AUTHORITY_PROOF>"
}
```

HTTPS transportの成功だけではこのbindingを代替できない。WalletはAuthority DID履歴からproof keyを解決し、Operator delegationのscopeと期限も検証する。

CI-CoreのAuthorization Code flowはPKCE `S256`を必須とする。Pre-Authorized Code flowを使う場合、共同体のrisk policyが要求する`tx_code`を招待とは別経路で本人へ渡し、bearer invitationだけで高権限Credentialを発行してはならない。Key proof用nonceはIssuer Metadataから発見したNonce Endpointで取得し、再利用、期限切れ、別Issuerの`c_nonce`を拒否する。

本人確認方法は共同体ごとに定義する。会社なら人事記録、学校なら学生登録、家族なら複数家族による承認、研究チームなら既存メンバーからの招待を利用できる。ただし本人確認資料をCredentialへそのまま埋め込んではならない。「この共同体が定めたPolicy Hashの条件を満たした」という結果だけを載せる。

## 12. 提示要求

VerifierはOpenID4VP Request ObjectへCommons Identity独自の`ci_request`を加える。

```json
{
  "version": "1",
  "purpose": {
    "code": "community_document_access",
    "display": "研究資料庫へアクセスするため"
  },
  "requestedClaims": ["community", "membership", "scope"],
  "retentionSeconds": 300,
  "onwardSharing": false,
  "linkability": "verifier-domain",
  "nymDomain": "archive.research.example",
  "humanReview": false
}
```

上の`verifier-domain`例はCI-Private-BBS等、要求を満たすprofile向けである。Developer Preview CI-CoreのRequestは`linkability: "community"`とし、`nymDomain`を含めない。

`purpose`、`requestedClaims`、`retentionSeconds`、`onwardSharing`は必須である。要求理由がない場合、Walletは拒否する。

`ci_request`はOpenID4VP標準パラメータではなく、一般のWalletは未知パラメータとして無視し得る。Commons Verifierは`ci_request`をJOSE header `typ: oauth-authz-req+jwt`の署名済みRequest Objectに含め、Commons Walletは欠落、署名対象外、改変、未知versionをfail closedで拒否しなければならない。要求CredentialはOpenID4VP 1.0のDCQLだけで表現し、DCQLと`ci_request.requestedClaims`の不一致も拒否する。CI-Coreのresponse modeは`direct_post`に固定し、deploymentのTrust Policyが認めたVerifier authentication methodだけを受理する。

`linkability`は次の三種類とする。

- `none`: 提示間で安定identifierを出さず、継続追跡を許可しない。
- `verifier-domain`: そのVerifier domain内だけで安定するpseudonymを使う。
- `community`: 共同体内で同じ人物として扱うことを明示的に許可する。

Protocol全体における要求側の安全な初期値は`none`である。ただしWalletは、選択したprofileとCredentialで要求された性質を暗号学的に満たせない場合、性質を弱めて送信してはならない。

Developer PreviewのCI-Coreは`community`だけを受理し、`none`と`verifier-domain`をfail closedで拒否する。Verifier別Credential等を将来定義する場合も別profile identifierと適合試験が必要である。BBS derived proofや`nym_domain`をCI-Coreの機能として表現してはならない。

`retentionSeconds`と`onwardSharing`はVerifierの署名済み宣言であり、開示後の保存・転送を暗号学的に強制するものではない。Walletはこの限界をUIで明示する。

## 13. 提示手順

1. Verifierは、要求ごとにCSPRNGで十分なentropyを持つ一意の`nonce`を生成する。
2. WalletはVerifierのidentifier、Request Object署名、要求目的、保持期間、DCQLと`ci_request`の整合を検証する。
3. Walletは条件を満たすCredentialをローカルで検索する。候補一覧をVerifierへ送信してはならない。
4. 必要最小限の属性だけを選ぶ。CI-Coreでは、要求を満たす最小単位のCredentialを選ぶ。
5. 本人へ「誰に、何を、なぜ、どれだけの期間渡すか」を表示する。
6. 本人が承認する。事前同意や包括同意で置き換えてはならない。
7. Walletはnonce、audience、Verifier、取引内容へ結びつけたpresentation proofを作る。
8. VerifierはIssuer、proof、holder binding、期限、status、Request Objectとのbindingを検証する。
9. WalletはConsent Receiptを保存する。
10. Verifierは宣言した保持期間を超えたPresentation Tokenを削除する。

OpenID4VPでは、提示を特定取引へ結びつけるため、要求ごとのnonceを用いる。Commons CI-Coreは署名済みRequest Object内の`ci_request`全体（`transaction_data`を含む）をJCS canonicalizeしてhashし、`ciRequestHash`としてData Integrity proof対象のPresentationへ含める。nonce、audience、expiry、要求claim、transaction dataのいずれかが変わればhashが一致せず、Presentationを拒否する。OpenID transportだけにこのcustom bindingを期待してはならない。

検証結果は少なくとも、cryptographic validity、holder binding、issuer trust、credential lifecycle、status freshness、request satisfactionを別々に扱う。「署名が正しい」を「アクセスを許可すべき」と同義にしてはならない。

## 14. Consent Receipt

Walletは提示のたびに、少なくとも次のReceiptを本人のIdentity Vaultへ残す。

```json
{
  "receiptVersion": "1",
  "verifier": "did:webvh:<VERIFIER_SCID>:service.example.org",
  "purpose": "community_document_access",
  "disclosedClaims": ["membership", "scope"],
  "linkability": "verifier-domain",
  "nymDomain": "archive.research.example",
  "retentionUntil": "2026-08-02T10:05:00Z",
  "onwardSharing": false,
  "requestHash": "sha256-<REQUEST_HASH>",
  "presentationHash": "sha256-<PRESENTATION_HASH>",
  "createdAt": "2026-08-02T10:00:00Z"
}
```

このReceipt例も`verifier-domain`を提供できるprofileの場合である。CI-Core Receiptは`community`を記録し、`nymDomain`を持たない。

本人は「いつ、誰へ、何を見せたか」を後から確認できる。Receiptは本人側へ暗号化保存し、共同体全体へ公開してはならない。Receipt自体が共同体横断の行動履歴になるため、Export、バックアップ、画面共有、telemetryで漏えいさせてはならない。

## 15. Commons Identityによるログイン

サービスはメールアドレスとパスワードの代わりに、次を要求できる。

```text
有効なCommunityMembershipCredential
必要なCommunityRoleCredential
そのサービス専用のpseudonymまたは共同体限定subject
```

Verifierは許可されたidentifierを自分のローカルアカウントへ対応させる。同じ本人を再認識する必要がある場合でも、そのidentifierを別Verifierへ共有してはならない。

CI-Private-BBSでは`nym_domain`によるVerifier別pseudonymを使用できる。Developer PreviewのCI-Coreは同等の分離を提供せず、`none`と`verifier-domain`の要求を拒否する。同一Credentialのholder keyを「サービス専用pseudonym」と見なしてはならない。

サービスは法的氏名やメールアドレスを知らなくてもアカウントを維持できる。ただしCommons Identityが移行するのは「誰がアクセスできるか」という身分関係であり、投稿、写真、購入履歴等のサービス内部データを自動移行するものではない。データ移行は別のPortable Data Protocolで扱う。

## 16. 有効期限

資格証明の推奨最大有効期間は次のとおりである。共同体は脅威モデルに応じて短くできるが、理由なく長くしてはならない。

- Community Membership: 90日。明示されたPolicyに基づき更新可能。
- Community Role: 30日。
- Capability: 数分から7日。破壊的操作を許すCapabilityは原則24時間以内。
- Contextual Standing: 180日。
- Qualification: 資格の性質に応じて長期化できるが、発行者鍵とstatus情報を持たせる。
- 高いunlinkabilityを必要とするCI-Private-BBS Credential: 原則7日以内。個別status indexをderived proofへ開示せずに済む設計を優先する。

「自動更新」は、holder binding、端末状態、Community Policy、Issuer委任を再検証した新しいCredentialの発行を意味する。Walletが期限を延長したり、古いCredentialを書き換えたりしてはならない。

## 17. 失効と停止

Commons Identityのlifecycle表示は次を区別する。

- `active`: 有効期間内で、必要なstatus確認が成功している。
- `suspended`: 一時停止。
- `revoked`: そのCredential instanceを永久に無効化。
- `superseded`: 新しいCredentialへ置換済みというCommons固有状態。
- `expired`: `validUntil`を過ぎたローカル評価結果。

IssuerはCredentialの内容を後から密かに書き換えてはならない。変更が必要なら新しいCredentialを発行し、古いものを失効またはCommons lifecycle記録で`superseded`にする。

Bitstring Status List標準のstatus purposeは`revocation`、`suspension`、`refresh`、`message`である。`active`、`superseded`、`expired`は標準status purposeではない。`expired`は`validUntil`から評価する。revocationとsuspensionを両方扱うCredentialは、それぞれ独立した`credentialStatus` entryとlistを使う。

公開statusへは必要な状態だけを載せ、「解雇」「不正行為」「退学」等の理由を書いてはならない。理由は本人向け暗号化通知と認可監査記録へ分離する。

## 18. Status List

長期Credentialのstatus確認には[W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)（W3C Recommendation、2025-05-15）を使用する。

VerifierはCredentialごとにIssuerへ問い合わせるのではなく、status list credential全体を取得してキャッシュする。これにより、Issuerが「誰が、いつ、どのサービスで資格を使ったか」を個別照会から観察しにくくする。

標準の131,072件は固定収容数ではなく、既定のminimum list sizeである。実装は少なくともこのprivacy-preserving lower boundを満たし、利用密度、更新頻度、list分割から個人を推測しにくくしなければならない。

Status indexは未使用位置からcryptographically randomに割り当てることを推奨し、加入順、社員番号、発行時刻から予測できる連番を避ける。`refresh` purposeは更新版Credentialが利用可能であることを示す不可逆flagであり、それだけで旧Credentialを無効化するものではない。

Status Listは、Community Authorityと異なる障害ドメインを含む最低三つのMirrorへ複製する。Verifierは取得元にかかわらずlist credentialの署名、purpose、識別子、発行時刻を検証する。

取得したStatus ListがCommunity Policyの最大鮮度を超える場合、単純な「有効」として扱ってはならない。

```text
Cryptographically valid
Current status unknown
Last status update: 36 hours ago
```

暗号学的正当性、Credential期限、現在のstatus、Issuerへのtrustを分離して表示する。高リスク操作はstatus unknownをfail closedにし、低リスクのoffline利用は明示されたPolicyに従う。

## 19. Reputationを世界通貨にしない

Commons Identityは、全共同体を横断するReputation APIを定義しない。

ある共同体での実績を別の共同体へ見せたい場合、本人がCredentialを明示的に選び、相関リスクを理解した上で提示しなければならない。Walletは発行元と無関係なVerifierからContextual Standingを要求された場合、強い警告を表示する。

```text
この資格は「Example Research Community」内での活動記録です。
要求元は別の共同体です。
この情報を共有すると、二つの人格領域が関連付けられる可能性があります。
```

実績は数値スコアではなく、期間と文脈を持つ事実として発行する。貢献は証明できるが、その貢献を永久的な階級へ変えてはならない。

## 20. Device Loss

端末を失った場合、本人は別の承認済み端末から`Device Revocation Request`を発行する。

失われた端末のDevice Keyと、その端末へ発行されたCredential instanceだけを失効させる。他端末、他のCommunity Persona、他Credentialは維持する。紛失端末は短期Credentialの更新も受けられなくなる。

端末が盗まれた可能性がある場合、Walletは影響を受けたCommunity Personaの`nym_secret`をローテーションできる。ただしpseudonymが変わるため、既存サービスとの関係を維持する場合はVerifier限定Continuity Credentialを使う。

Device Revocation Requestは、対象device identifier、要求時刻、理由code、代替device key、replay防止nonceを含み、承認済みdeviceまたはrecovery authorityで署名する。理由の詳細を公開statusへ含めてはならない。

## 21. Recovery Kit

Recovery Kitは、暗号化されたIdentity Vault復旧情報である。

```text
vault format version
encrypted Vault Control Key
encrypted Vault Encryption Key
encrypted Community Persona secrets
encrypted credential inventory
encrypted device authorization graph
latest vault snapshot or Arcane Commons Mesh CIDs
recovery configuration
KDF parameters
integrity checksum
```

Recovery KitはパスフレーズからArgon2idで鍵を導出し、XChaCha20-Poly1305で認証付き暗号化する。各Kitは少なくとも128ビットの一意なrandom saltと一意な24-byte nonceを用いる。暗号文にはformat version、KDF parameters、algorithm identifiersをAADとして結びつける。

Commons Identityの初期baselineは次とする。

```text
algorithm: Argon2id
version: 0x13
memoryKiB: 262144 (256 MiB)
passes: 3
parallelism: 1
output: 32 bytes
salt: 16 unique random bytes per kit
passphrase encoding: exact UTF-8 bytes
passphrase normalization: none
AEAD: XChaCha20-Poly1305-IETF
nonce: 24 unique random bytes per encryption
authentication tag: 16 bytes
```

これは[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)の既定値ではなく、Commons Identity独自の初期profileである。実装者は対象端末でbenchmarkし、利用可能メモリ、復旧時間、DoS耐性、パスフレーズ強度を評価しなければならない。parametersを下げる場合は本人へ警告し、Kitへ実値を記録する。将来の端末は再暗号化でparametersを上げられなければならない。

Recovery Kitは通常端末とは別のUSBメモリ、外付けストレージ、紙に記録した復旧情報、またはArcane Commons Meshへ保存できる。Recovery Kitとパスフレーズを同じ場所へ置いてはならない。クラウド同期を既定で有効にしてはならない。

## 22. Guardian Recovery

> **参照実装の境界:** 本節は将来設計である。Developer PreviewにはGuardian Recoveryを搭載しておらず、CI-Core適合機能としてclaimしない。

Recovery Kitの喪失に備え、本人はGuardian Recoveryを設定できる。推奨の通常policyは5人中3人である。

GuardianへRecovery Rootそのものを渡してはならない。Recovery Manifestを開く一時的な`Guardian Recovery Key`をShamir Secret Sharingで分割する。各shareはGuardian固有の暗号化鍵へ暗号化し、Kit version、Guardian set、threshold、expiry、integrity commitmentへ結びつける。

3人が協力すればRecovery Keyを再構築できるが、2人以下では情報を得られない。Shamir分割はshareの真正性、Guardian認証、rollback防止を単独では提供しないため、署名済みmanifestとauthenticated channelを併用する。

通常のGuardian Recoveryには72時間の待機期間を設ける。開始時にすべての既存端末とGuardianへ通知し、本人がまだ端末を持っていれば偽の要求を拒否できる。

緊急復旧は、たとえば5人中4人の承認を必要とし、待機期間を24時間へ短縮できる。policy変更は既存端末への通知、cooling-off期間、Audit Receiptを必要とする。

GuardianはIdentity Vaultの中身を閲覧できず、誰がどの共同体へ所属しているかも知る必要がない設計にする。

## 23. すべてを失った場合

全端末、Recovery Kit、パスフレーズ、Guardian Recoveryのすべてを失った場合、世界共通の「パスワードを忘れた」窓口は存在しない。

これは中央管理者による万能な乗っ取りを防ぐ境界である。その場合、本人は共同体ごとに再確認を受け、新しいCommunity PersonaとCredentialを発行してもらう。

会社は会社の記録で、学校は学校の記録で、家族は家族の合意で復旧する。一つの共同体が本人を再確認しても、他の共同体まで自動的に復元してはならない。

## 24. Continuity Credential

秘密鍵を失ったが以前のサービスアカウントとの関係を維持する必要がある場合、Community Authorityは`ContinuityCredential`を発行できる。

これは旧Personaと新Personaが同じ共同体会員として扱われることを、特定Verifierにだけ証明する。世界へ公開されるlinkではない。

```text
旧Persona
       │
       │ 特定Verifier向けContinuityCredential
       ▼
新Persona
```

Continuity Credentialは、対象Verifier identifier、purpose、旧関係のopaque reference、新Personaのholder binding、有効期限を必須とする。別サービスへ使い回してはならない。発行と利用は、旧新Personaの相関をCommunity Authorityと対象Verifierへ開示することを本人へ明示する。

## 25. Community Authorityの鍵更新

Community Authorityの更新鍵をOperatorのオンラインサーバーへ常駐させてはならない。

Commons Governance Layerの推奨構成は、Governance Controller 5名のうち3名の承認と、独立Witness 3者のうち2者の確認である。これは`did:webvh`が暗号学的に強制する閾値ではない。Commons実装は閾値承認を署名済みproposalとして収集し、そのhashをAudit Logへ固定した後で、許可されたDID update keyが更新を署名する。

次期update keyのhashをpre-rotation commitmentとして事前公開する。現在鍵が盗まれても、攻撃者が予定外の次期鍵を正当なものとして設定しにくくする。

通常のIssuer Keyは短期委任とし、最大90日でローテーションする。Issuer Keyが漏えいしても、Community AuthorityのGovernance Keyまで失われない構造にする。鍵更新runbookにはcompromise時の停止、影響期間、再発行、Mirror更新、Holder通知を含める。

## 26. Operator Migration

Operator交代時は`Community Migration Bundle`を生成する。

```text
Community Authority DID history
governance configuration
issuer delegations
credential schemas
policy versions
encrypted member registry
status lists
audit checkpoints
revocation history
mirror configuration
pending proposals
operator handover receipts
```

BundleにHolderの秘密鍵、holder secret、Recovery Kitを含めてはならない。

移行手順:

1. 共同体が新Operatorを提案する。
2. 定足数を満たす署名済み承認を収集する。
3. 新Operatorへ暗号化Migration Bundleを渡す。
4. 新旧OperatorとCommunity Controllerが、manifestと状態hashを確認する。
5. Community Authorityが新しいservice endpointをDID履歴へ追加する。
6. Witnessが更新を観測し、checkpointへ署名する。
7. 新Operatorがread-only検証を経てserviceを開始する。
8. 旧Operatorの委任Credentialを失効する。
9. 旧Operatorへ保存データ削除を要求し、可能な範囲で証跡を得る。
10. 移行ReceiptをAudit Logへ残す。

`did:webvh`のドメイン移行ではDID文字列のhost／path部分が変わり得る。新旧DID文字列を同一だと扱うのではなく、SCIDと全履歴を維持し、`moved`等の仕様上のpredecessor connectionを検証する。署名済み履歴を検証せず、文字列置換だけで移行してはならない。

## 27. 共同体の解散

共同体が解散する場合、Operatorが単にサーバーを削除してはならない。Governance quorumによる最終状態として次を公開する。

```text
communityState: dissolved
finalAuthorityVersion
finalStatusLists
archiveMirrors
credentialVerificationPolicy
dissolutionDate
governanceProof
```

長期Qualification等を残す場合は、最終DID履歴、Issuer Key、Status List、必要なContext／Schemaを、相互に独立した複数Mirrorと適切な公共archiveへ保存する。

現在状態を更新できなくなったCredentialについて、Verifierは「最終確認日時」と「共同体解散済み」を表示する。最終archiveが存在することを、現在もmembershipがactiveである証明として扱ってはならない。

## 28. Audit Log

管理操作は署名済みAudit Logへ記録する。対象は少なくとも次である。

- Issuer Keyの追加、更新、削除
- Operator委任と失効
- Policy／Schema／Contextの変更
- Status List更新
- Guardian Policy変更
- Migrationとdissolution
- 緊急停止
- 管理者によるCredential失効

Audit Logはhash chainまたはMerkle structureで連結し、sequence、時刻、操作種別、対象hash、承認者key reference、前entry hashを含む。定期checkpointをCommunity AuthorityとWitnessが署名し、複数Mirrorへ公開する。

公開Logへ個人情報、local subject identifier、status index、失効理由を直接書いてはならない。個人に関係する詳細理由は、本人または認可監査者だけが復号できる別記録へ保存する。

Audit Logは透明性を補助するが、正当性を自動的に証明しない。検証者は署名、chain continuity、quorum、Witness、時刻の不整合を別々に報告する。

## 29. Verifierの保存制限

Verifierは完全なCredentialまたはPresentation Tokenを、原則として検証直後に削除する。長期保存が必要なら、Request Objectで次を明示する。

```text
何を保存するか
なぜ保存するか
いつ削除するか
誰と共有するか
本人が削除を要求できるか
```

初期値:

```text
Presentation Token retention: 5 minutes
Derived claims retention: 0 seconds
Onward sharing: false
Analytics use: false
Advertising use: prohibited
```

サービス運営上、特定属性を維持する必要がある場合でも、元Credentialではなく必要な結果だけを保存する。「18歳以上」であれば、生年月日を保存しない。

暗号プロトコルだけでは、開示後に悪意あるVerifierが複製、転送、二次利用することを防げない。Receipt、監査、契約、法制度、データ最小化を併用し、この限界をWallet UIで誤魔化してはならない。

## 30. 信頼の判断

暗号署名が正しいことと、そのIssuerを信頼すべきことは別である。

VerifierはCommunity AuthorityをローカルTrust Policyで評価する。ある学校のQualificationを認めるか、ある研究組織の研修を認めるかは、検証する共同体が決める。世界共通の信用機関や中央Trust Registryを必須にしない。

共同体同士が互いを限定的に認める場合、`RecognitionCredential`を発行できる。

```text
Community A
  recognizes
Community B
  as issuer of
FoodSafetyQualificationCredential
  until
2027-01-01
```

Recognition Credentialは、認定するCredential type／Schema、用途、対象jurisdiction等のscope、期限、statusを持つ。ある分野で認めても、その組織が発行するすべてのCredentialを信頼してはならない。Recognition chainへ無制限のtransitive trustを与えてはならない。

## 31. 脅威と防御

| 脅威 | 主な防御 | 残る限界 |
| --- | --- | --- |
| プラットフォーム停止 | ローカルWallet、標準Export、DID履歴、Mirror | サービス内部データは別途移行が必要 |
| 端末盗難 | 端末別鍵、端末別Credential、短期期限、個別失効 | ロック解除済み端末上のmalwareには弱い |
| Credentialの売買 | holder binding、BBS holder secret | 本人が意図的に端末ごと貸す行為は完全には防げない |
| 提示の再送 | nonce、audience、短い有効期限、transaction binding | Verifier自身が不正なら開示後の利用を完全には制御できない |
| Issuer Key漏えい | 短期委任、pre-rotation、Witness、再発行 | 漏えい発覚前の影響は残る |
| Operator乗っ取り | Governance Key分離、閾値承認、DID履歴 | Controller閾値以上の共謀、online service妨害 |
| 複数共同体の追跡 | Persona分離、異なる鍵、BBS pseudonym | 氏名、顔、network metadata、固有属性による相関 |
| Guardian共謀 | 3-of-5、待機期間、既存端末通知 | 閾値以上のGuardian共謀、通知経路妨害 |
| Wallet企業の囲い込み | 完全Export、共通Schema、相互運用試験 | 悪質な独自拡張を利用者が選ぶ可能性 |
| Sybil攻撃 | 共同体ごとの本人確認Policy | 世界共通の「一人一人格」は意図的に保証しない |
| 強要 | 最小開示、領域分離 | 物理的・法的強要を暗号だけで完全には防げない |
| Supply-chain compromise | lockfile、provenance、review、reproducible release | build hostや依存元が同時に侵害される危険 |

詳細なasset、trust boundary、attacker capability、abuse caseは[Threat Model](../threat-model.md)を正規の補助文書とする。

## 32. 標準Export

Commons Walletは、本人の明示操作でいつでも`Commons Identity Archive`を書き出せなければならない。拡張子は`.cia`とする。

内容はversioned container内の暗号化CBORまたはJSON構造とし、最低限次を含める。

```text
archive_version
kdf_parameters
encrypted_identity_vault
credential_formats
community_personas
device_records
consent_receipts
recovery_configuration
schema_snapshots
resolver_cache
integrity_manifest
```

書き出しにOperatorまたはWallet企業の許可を必要としてはならない。Archiveは既定で暗号化し、平文metadataから所属共同体やCredential数を推測しにくくする。Import前にcontainer version、KDF limits、AEAD integrity、manifest、Schema／Contextを検証し、untrusted inputとして処理する。

別実装WalletがArchiveを読み込み、同じCredentialを検証・提示できなければならない。端末保護hardwareからexportできないprivate keyがある場合、portable software-wrapped keyまたはIssuerからの再発行手順を事前に明示し、成功したふりをしてはならない。

Export機能のないWalletはCommons Identity互換ではない。`.cia` binary layout、canonical encoding、test vectorは相互運用release前に別のversioned format specificationとして固定する。

## 33. API

標準protocolとの接続には、次のdiscoveryとmetadataを使う。

```text
GET  /.well-known/commons-identity
GET  {credential-issuer}/.well-known/openid-credential-issuer
     （正確なwell-known構成はOpenID4VCI 1.0のissuer identifier規則に従う）
POST {credential_endpoint discovered from issuer metadata}
OpenID4VP 1.0 Authorization Request / Response
```

`POST /credential`を固定pathとして仮定してはならない。例示実装が`/credential`を使うことはできるが、WalletはIssuer Metadataの`credential_endpoint`を使用する。

Commons固有serviceの推奨HTTP surfaceは次である。完全なbase URLは署名済みCommunity Profileから発見する。

```text
GET  /status/{status-list-id}
GET  /policies/{policy-hash}
GET  /schemas/{schema-id}
GET  /audit/checkpoints/{sequence}
POST /ci/v1/device/revoke
POST /ci/v1/continuity/request
POST /ci/v1/operator/export
POST /ci/v1/operator/import
```

状態変更endpointは、authentication、authorization、replay防止、request size limit、idempotency、署名済みReceiptを必要とする。Operator export／importは公開Internetからの汎用backup endpointとして提供してはならない。

対応環境では[W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)をブラウザadapterとして利用できる。ただし2026-08-02時点ではW3C Working Draft（2026-07-16）であるため必須要件にせず、通常のHTTPS、QR、app linkも維持する。

### CI-Coreのtransaction binding

OpenID4VPの`transaction_data` transportだけでは、Commons Data Integrity VP向けの暗号学的binding規則が完成しない。CI-Coreでは、署名済みRequest Objectに含まれる`ci_request`全体をJCS canonicalizeしてSHA-256でhashし、`ciRequestHash`をproof対象の`application/vp`へ含める。Verifierは受理したRequest Objectから再計算し、完全一致を確認する。versioned Contextと公開test vectorがない実装は、このDeveloper Previewのcustom bindingを破壊的操作へ使用してはならない。

## 34. UI要件

Walletは暗号方式より先に、人間へ意味を示さなければならない。

悪い表示:

```text
VC presentation request
Claims: scope, membership, nym
Accept / Reject
```

必要な表示:

```text
Example Research Archiveが、研究資料を開くために次を求めています。

・現在もExample Research Communityの会員であること
・資料閲覧の権限を持っていること

氏名、メールアドレス、他の所属先は共有されません。

このサービス内では、次回も同じ利用者として認識されます。
他のサービスとは関連付けられません。

提示情報の保持予定: 5分
第三者への共有: なし
```

ただし最後の二つのprivacy claimは、選択したprofileが実際に保証できる場合だけ表示する。CI-Coreで同一Credentialを使い回す場合に「他のサービスとは関連付けられません」と表示してはならない。

利用者がどのCommunity Personaを開こうとしているか、何が開示され、何が開示されず、相関可能性がどう変わるかを理解できる表示にする。screen reader、keyboard操作、色以外の警告表現、専門語を展開したplain-language説明を提供する。

## 35. 適合試験

Commons Identity 1.0の実装は、対象profileについて最低でも次を自動試験し、fixtureと結果を公開する。

1. 同一fixture holderが二つの共同体へ参加しても、公開protocol identifier、key、Credentialの再利用がなく、定義した観測モデル内で相関子が一致しない。
2. CI-Private-BBSでは異なる`nym_domain`に異なるpseudonymが生成される。
3. 同じ`nym_domain`には、本人が許可した場合だけ安定pseudonymが生成される。
4. 記録済みPresentationの再送がnonce不一致で拒否される。
5. 一台の端末を失効しても、他端末のCredentialが維持される。
6. Recovery Kitと正しいパスフレーズから新端末へ完全復元できる。
7. Experimental Guardian Recoveryでは、Guardianが閾値未満では復元できず、改変shareも拒否される。
8. Operator変更後も、SCIDとpredecessor接続を含むAuthority履歴と既存Credentialを検証できる。
9. Issuer停止中も、Mirrorと許容鮮度内cacheから署名を検証できる。
10. Status Listが古い場合、「有効」ではなく「現在状態不明」と表示される。
11. 必要以上の属性を要求するVerifierへWalletが警告を出す。
12. コピーされたCredentialでは、Credential内holder keyと一致するpresentation proofを作れない。
13. 一つのWalletからExportし、独立実装WalletへImportして同じCredentialを提示できる。
14. 管理操作が改ざん検出可能なAudit Logへ残る。
15. system内に送金、換金、利息、token売買、汎用信用スコアAPIが存在しない。
16. `ci_request`欠落、署名対象外、DCQLとのclaim不一致がfail closedになる。
17. revocationとsuspensionが別entry／listとして評価され、`expired`が`validUntil`から評価される。
18. CI-CoreがBBS由来のunlinkabilityまたはpseudonymを誤ってclaimしない。
19. 同じ物理端末でも、二つのCommunity Personaでholder keyが一致せず、公開`holderBinding`へVault-global device identifierが含まれない。

CI-Private-BBSの試験2、3とGuardian Recoveryの試験7はCI-Coreの適合要件ではない。CI-Coreは`none`／`verifier-domain`を拒否するnegative testを必要とする。未実装機能をskipして全体をpassと表示してはならない。profileごとにpass／fail／not implementedを分ける。

## 36. 最初に実装する範囲

最初のMVPは、macOS向けCommons Wallet、Community Authority、Issuer、Verifier SDK、Membership Credential、Role Credential、Recovery Kit、端末失効、Operator Migrationへ範囲を絞る。

暗号CredentialはCI-Coreで完成させる。その後、BBSによる選択的開示、anonymous holder binding、Verifier別pseudonymをCI-Private-BBSとして追加する。

Arcane Commons MeshはIdentity Vaultの暗号化backup先として利用できるが、Commons IdentityはMeshなしでも動作しなければならない。backup基盤とidentity基盤を相互依存させすぎれば、一方の障害が両方を止めるためである。

参照実装は、暗号とprotocol部分をRustの共通Core、desktop UIをTauri、local storageをSQLite上のrecord単位暗号化、共同体側を交換可能なHTTP serviceとして構成する。Cloudflare WorkersとD1を最初のOperatorとして使用できるが、仕様上の必須要件にはしない。

MVP completionは、機能の存在だけでなく、build、test、lint、typecheck、公開fixture、Export／Importの独立実装試験、脅威モデル更新を必要とする。これらが揃うまで「production-ready」「secure」「完全互換」と表示してはならない。

## 完成した定義

Commons Identityは、Internet全体で一人の人間を追跡するための身分証ではない。

**本人だけが束ねられる、文脈ごとに分離された関係の鍵束**である。

共同体は「この者が世界で誰なのか」を決めない。ただ、自分たちとの間にどのような関係があり、現在どの資格と権限を持つかだけを証明する。

企業は、その関係を保存し、通信し、検証するOperatorにはなれる。しかし本人の存在そのものを所有することはできない。

この仕様を一文へ縮めるなら、こうなる。

> **わしの身分は、企業から借りるアカウントではない。
>
> わし自身が持つ鍵と、わしが結んだ関係の集合である。**

## References

1. [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
2. [DIF `did:webvh` v1.0](https://identity.foundation/didwebvh/v1.0/)
3. [W3C Data Integrity BBS Cryptosuites v1.0](https://www.w3.org/TR/vc-di-bbs/)
4. [OpenID for Verifiable Credential Issuance 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
5. [OpenID for Verifiable Presentations 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
6. [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
7. [RFC 9106: Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106.html)
8. [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)
9. [W3C Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-eddsa/)
