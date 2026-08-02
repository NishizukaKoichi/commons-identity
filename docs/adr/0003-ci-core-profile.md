# ADR-0003: CI-Coreを最初の相互運用profileにする

- Status: Accepted
- Date: 2026-08-02
- Decision owners: Commons Identity maintainers

## Context

Commons Identityは最小開示と相関防止を目標にする。一方、Data Integrity BBS Cryptosuitesは2026-08-02時点でCandidate Recommendation Draftであり、相互運用と安全なUXの証拠が必要である。安定したW3C Recommendationだけで構成できるEdDSA profileは、選択的開示とunlinkable derived proofを提供しない。

OpenID4VCI／OpenID4VP 1.0 Finalのbuilt-in `ldp_vc` profileはVCDM 1.1を参照するため、VCDM 2.0を使うCommonsは独自format profileを明示する必要がある。

## Decision

最初の必須profileを`ci-core-1`とする。

- Credential model: W3C VC Data Model 2.0
- Proof: Data Integrity 1.0 + `eddsa-jcs-2022`
- OID4VCI format identifier: `application/vc`
- OID4VP format identifier: `application/vp`
- Canonicalization: JCSを固定し、署名検証中にremote JSON-LD Contextを取得しない
- Privacy strategy: 共同体別Persona、端末別鍵、端末別Credential instance、用途別に小さく分割したCredential、短期有効期限
- Holder binding: Credential内device holder keyとPresentation proof keyの一致を検証
- Status: Bitstring Status List。revocationとsuspensionは別entry／list
- Issuer binding: Metadataで発見したHTTPS Credential Issuer identifierとVCのCommunity Authority DIDを、Authority署名済み`CIIssuerBinding`で結ぶ

CI-Coreは、BBSの選択的開示、anonymous holder binding、`nym_domain`、Verifier間unlinkabilityをclaimしない。Developer Previewでは`linkability:none`と`verifier-domain`を常にfail closedで拒否し、`community`だけを受理する。

`ci-private-bbs-1`は別のexperimental opt-in profileとし、upstream仕様固定、複数library、test vector、side-channel review、独立相互運用が揃うまで必須適合から除外する。

## Consequences

- MVPは成熟したprimitivesへ集中できる。
- Credential分割と短期再発行によりIssuer負荷が増える。
- 同一CI-Core Credentialの繰り返し提示は相関可能であり、UIで明示する必要がある。
- JSON-LD Context、canonicalization fixture、OpenID deployment-defined formatの相互運用試験が必須になる。

## Alternatives considered

- `ldp_vc`をそのまま使う: VCDM 1.1参照をVCDM 2.0と誤認させるため不採用。
- `eddsa-rdfc-2022`: RDF Dataset CanonicalizationとJSON-LD processingの相互運用surfaceが増える。MVPではbyte-level JCS fixtureとremote Context非取得を固定するため不採用。将来は別profile ADRで評価する。
- BBSだけを実装: upstream maturityと実装多様性が不十分なため不採用。
- SD-JWT VC: 別credential formatとprivacy／holder binding modelになるため、1.0 MVPの範囲外。

## Risks and rollback

- Risk: 利用者がCI-Coreをunlinkableと誤解する。Mitigation: Walletの提示画面と全入口で相関可能性を表示する。
- Risk: custom OpenID formatを一般Walletが扱えない。Mitigation: metadata negotiation、明確なerror、interop fixtureを提供する。
- Rollback: security defectがあれば`ci-core-1`を停止し、新しいprofile identifierで置換する。同じidentifierの意味をsilentに変更しない。
