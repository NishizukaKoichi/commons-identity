# Standards Status and Profile Boundary

- Audited against primary sources: 2026-08-02
- Project profile status: Developer Preview

This page records the external specification versions used to design Commons Identity. It is not a certification statement. An external standard being final does not make the Commons profile or reference implementation production-ready.

## Pinned sources

| Specification | Status on 2026-08-02 | Commons use |
| --- | --- | --- |
| [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) | W3C Recommendation, 2025-05-15 | Required data model |
| [VC Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) | W3C Recommendation, 2025-05-15 | CI-Core proof framework |
| [Data Integrity EdDSA Cryptosuites 1.0](https://www.w3.org/TR/vc-di-eddsa/) | W3C Recommendation, 2025-05-15 | CI-Core pins `eddsa-jcs-2022` |
| [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html) | OpenID Final Specification, 2025-07-09 | Presentation transport boundary |
| [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html) | OpenID Final Specification, 2025-09-16 | Issuance transport boundary |
| [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/) | W3C Recommendation, 2025-05-15 | Revocation and suspension status |
| [`did:webvh:1.0`](https://identity.foundation/didwebvh/v1.0/) | DIF-hosted v1.0 specification; not a W3C Recommendation | Community Authority history, with Commons governance layered separately |
| [Data Integrity BBS Cryptosuites v1.0](https://www.w3.org/TR/vc-di-bbs/) | W3C Candidate Recommendation Draft, 2026-04-07 | Experimental CI-Private-BBS only |
| [Digital Credentials API](https://www.w3.org/TR/digital-credentials/) | W3C Working Draft, 2026-07-16 | Optional experimental browser adapter |
| [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) | IRTF Informational RFC, 2021-09 | Argon2id construction; Commons parameters are project-specific |

Use immutable Final URLs for OpenID conformance evidence. Latest errata pages may clarify defects, but a release record must state which document/version it used.

## Commons-specific constraints

### VCDM 2.0 over OpenID

The OpenID4VCI/VP Final documents' built-in `ldp_vc` profile references VCDM 1.1. Commons does not advertise VCDM 2.0 as generic `ldp_vc` interoperability. CI-Core defines deployment-specific format identifiers:

```text
Credential:   application/vc
Presentation: application/vp
Data model:   VCDM 2.0
Proof suite:  eddsa-jcs-2022
```

The v2 `@context` appears first, followed by the versioned Commons Context. CI-Core signs/verifies the exact Context URL with JCS and does not dereference arbitrary remote Contexts during proof verification. Implementations may bundle the published snapshot for separate semantic validation.

### Issuer binding

OpenID4VCI discovers an HTTPS Credential Issuer and its `credential_endpoint` from metadata. The VC issuer is a Community Authority DID. Commons requires an Authority-signed `CIIssuerBinding` that exactly connects those identifiers and the scoped Operator delegation. TLS or matching display names alone are insufficient.

### Presentation requests

Commons `ci_request` is not a standard OpenID4VP parameter. It must be inside a signed Request Object, match the DCQL request, and fail closed when absent, altered, unsupported, or inconsistent. Purpose, claim list, retention, onward sharing, nonce, audience, expiry, linkability, and transaction data are covered by the request binding.

Retention and onward-sharing fields are declarations for consent, policy, and audit; cryptography cannot force a Verifier to delete or not forward disclosed data.

### Privacy boundary

EdDSA does not provide selective or unlinkable disclosure. CI-Core minimizes data with small purpose-specific Credentials and separates keys/identifiers by community and device. Developer Preview CI-Core accepts `community` linkability only and rejects `none` and `verifier-domain`. BBS selective disclosure, anonymous holder binding, and `nym_domain` remain outside Core conformance.

### Status semantics

The Bitstring Status List minimum/default length is 131,072 entries, not a maximum capacity. Revocation and suspension use separate status entries/lists. `active` is a combined local evaluation; `expired` comes from `validUntil`; `superseded` is a Commons lifecycle concept.

### Authority governance

`did:webvh` verification does not enforce Commons 3-of-5 controller approval. Commons records that quorum in its signed governance proposal/Audit Log before an authorized DID update key signs. Witness threshold is separate. A domain migration may change host/path in the DID string while preserving SCID, full history, and predecessor connection.

### Recovery parameters

Argon2id at 256 MiB, 3 iterations, parallelism 1 is a Commons baseline—not an RFC 9106 default. Archives must self-describe the exact algorithm version, memory, passes, parallelism, salt, output, passphrase encoding, AEAD, nonce, and tag. Device benchmarks and denial-of-service bounds are required.

## Review triggers

Re-audit this page before a release and whenever an upstream status, erratum, media type, cryptosuite, OpenID profile, DID method version, or recovery primitive changes. Record meaningful changes in CHANGELOG and an ADR; never silently change the meaning of a stable profile identifier.
