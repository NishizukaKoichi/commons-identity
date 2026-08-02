# Commons Identity Threat Model

- Status: Draft for independent review
- Last reviewed: 2026-08-02
- Applies to: `commons-identity/1` and the experimental reference implementation

> [!WARNING]
> This threat model is design input, not proof of security. The reference implementation has not completed an independent security audit and must not protect production identity data.

## 1. Security and privacy objectives

Commons Identity must preserve:

- **Secret confidentiality:** Recovery Root, Vault Control Key, Device private keys, Persona secrets, Guardian shares, archive passphrases.
- **Credential integrity:** an attacker cannot mint, alter, backdate, extend, or transfer a Credential without detection.
- **Persona separation:** protocol-generated identifiers and keys from different communities do not provide a shared correlator.
- **Holder control:** an Issuer or Operator cannot silently impersonate a Holder or export a usable Vault.
- **Authority continuity:** an Operator failure or migration does not silently replace the Community Authority.
- **Minimum disclosure:** a Verifier learns only approved claims for the declared purpose.
- **Audit integrity:** privileged changes, delegation, status updates, and migrations are tamper-evident.
- **Recoverability:** loss of one device does not destroy unrelated Persona or Credential instances.
- **Availability with honest uncertainty:** stale status is reported as unknown, not converted to active.

## 2. Out of scope and non-goals

The protocol does not guarantee:

- a global one-person-one-identity property or Sybil resistance outside each community's policy;
- truth of an Issuer's claim merely because its signature verifies;
- prevention of physical or legal coercion;
- confidentiality after an authorized Verifier receives a disclosed claim;
- safety of an unlocked, fully compromised endpoint;
- migration of posts, media, purchase history, or other application data;
- anonymity against network-layer metadata, browser fingerprinting, cameras, or voluntarily disclosed names;
- protection from a quorum of malicious Governance Controllers or Guardians;
- production fitness of this unaudited reference implementation.

## 3. Assets and sensitivity

| Asset | Impact if disclosed | Impact if modified or lost |
| --- | --- | --- |
| Recovery Root / Vault keys | Full Vault recovery attack | Irrecoverable identity state or lockout |
| Device private keys | Impersonation from one device | Device-specific denial of access |
| Persona holder/nym secrets | Community correlation and impersonation | Account continuity break |
| Credentials and inventory | Membership and role disclosure | False authorization or loss of access |
| Consent Receipts | Cross-service behavior history | False audit trail for the Holder |
| Governance keys/proposals | Authority takeover preparation | Malicious delegation or migration |
| Issuer keys | Credential forgery | Ecosystem-wide reissuance event |
| Status lists | Membership-change inference | Revoked users accepted or active users denied |
| Member registry | Community graph disclosure | Enrollment and status corruption |
| Audit log/checkpoints | Operational intelligence | Hidden privileged actions |
| Export/Migration bundles | Bulk compromise | Rollback, fork, or operator takeover |

## 4. Trust boundaries and data flow

```text
Holder-controlled device
  [Identity Vault, Device keys, Persona secrets]
          │ OID4VCI: offer, proof, Credential
          ▼
Operator-hosted Issuer ── delegation proof ── Community Authority
          │                                  [offline governance]
          │ signed status/audit material             │
          ▼                                           ▼
Independent mirrors ◄────────────────────────── Witnesses
          │
          │ cached public verification material
          ▼
Verifier ◄──── OID4VP signed request / presentation ──── Wallet
```

Boundary assumptions:

1. The Wallet host, Issuer, Operator, Verifier, mirror, Guardian, and Witness are separate compromise domains unless deployment evidence proves otherwise.
2. TLS protects transport but does not make either endpoint trustworthy.
3. Public DID, Schema, Context, status, and audit material are untrusted until signatures, hashes, version, and policy are verified.
4. Credential and Archive inputs are attacker-controlled parsable data.
5. Operator authorization derives from a short-lived delegation; infrastructure ownership is not Authority ownership.

## 5. Attacker capabilities

We consider attackers who can:

- control a malicious Verifier and craft overbroad or misleading requests;
- operate or compromise an Issuer, Operator, mirror, Guardian, or Witness;
- steal a locked or unlocked Holder device;
- replay, reorder, delay, or block network messages;
- publish stale DID histories, Status Lists, Policies, Schemas, or Contexts;
- supply malformed JSON, JSON-LD, CBOR, SQLite, `.cia`, QR, URL, or compressed input;
- correlate timing, IP addresses, proof material, status indices, unique claims, and UI behavior;
- compromise a dependency, build runner, release artifact, or update channel;
- obtain fewer than or at least the configured recovery/governance threshold;
- socially engineer Holders into accepting misleading disclosure or recovery requests.

## 6. Threat analysis and required controls

### 6.1 Cross-community correlation

**Threat:** Issuers or Verifiers combine stable identifiers, keys, proof values, unique attribute combinations, network metadata, or Consent Receipts.

**Controls:** independent random Persona identifiers and keys; no public physical/Vault-global device identifier; local-only mapping from a physical device to each Persona-specific holder key and issuance binding identifier; no email/phone/name-derived identifiers; no global registry; purpose-specific small Credentials; BBS domain pseudonyms only in the experimental BBS profile; strong warning before cross-community Contextual Standing disclosure; local-only Receipts.

**Residual risk:** CI-Core presentations of the same Credential are correlatable. Names, faces, IP addresses, rare qualifications, and timing can correlate otherwise separate Personas. The UI must not promise unlinkability it cannot provide.

### 6.2 Credential theft and transfer

**Threat:** an attacker copies a Credential or buys it from its Holder.

**Controls:** per-device holder key in each Credential; Presentation proof by the same key; per-device status index; short validity; device revocation; optional hardware-backed key storage.

**Residual risk:** an unlocked compromised device or a Holder lending the whole device can act as the Holder. Hardware attestation is not mandatory and can itself be a correlator.

### 6.3 Replay and confused-deputy authorization

**Threat:** a valid Presentation is replayed or a benign disclosure is reused to authorize a destructive transaction.

**Controls:** fresh nonce, audience and response binding, short response lifetime, signed Request Object, fail-closed `ci_request`, DCQL consistency, explicit human-readable transaction data. CI-Core transaction approval additionally requires the Commons-defined hashes inside the signed `application/vp` and public test vectors.

**Residual risk:** OpenID transport alone does not define the Commons Data Integrity transaction binding. Until the custom Context and vectors are independently reviewed, it must not authorize destructive operations.

### 6.4 Malicious or compromised Issuer

**Threat:** an Issuer mints unauthorized Credentials, reuses Holder identifiers, or omits binding.

**Controls:** narrow short-lived delegation; Schema and Policy hash; Authority-bound Issuer metadata; audit log; issuance receipts; key rotation; status publication; Trust Policy.

**Residual risk:** Credentials forged before compromise detection may remain accepted. Cryptography cannot prove the Issuer performed correct real-world identity proofing.

### 6.5 Operator capture or failure

**Threat:** infrastructure ownership is treated as community ownership, or an Operator withholds data during migration.

**Controls:** offline Governance keys; quorum approval outside `did:webvh`; 90-day OperatorCredential; encrypted migration bundles; independent mirrors; state-hash handover; revocation of old delegation.

**Residual risk:** an Operator can deny service, delete data without a current backup, or leak plaintext it legitimately processed. Deletion attestations cannot prove every copy disappeared.

### 6.6 Authority key compromise and governance collusion

**Threat:** an update key or controller quorum changes Issuers, endpoints, or policy.

**Controls:** offline keys; proposal quorum; pre-rotation; independent Witness checkpoints; cooling-off for high-risk changes; visible audit chain; emergency stop and reissuance plan.

**Residual risk:** `did:webvh` itself does not enforce Commons 3-of-5 governance. A threshold of colluding controllers can authorize a malicious update; Witnesses detect but may not prevent it.

### 6.7 Status privacy, staleness, and rollback

**Threat:** individual status calls reveal use, small lists identify members, or stale lists accept revoked Credentials.

**Controls:** Bitstring Status List with at least 131,072 entries; cached whole-list fetches; separate revocation and suspension entries; signed issue time; Policy freshness limit; three independent mirrors; explicit unknown state.

**Residual risk:** list partitioning, sparse updates, timing, or targeted denial can leak information. Offline acceptance trades availability for current status assurance.

### 6.8 Recovery compromise

**Threat:** weak passphrases are brute-forced; Guardian shares are stolen; a fake recovery replaces device keys; old kits roll back the Vault.

**Implemented Developer Preview controls:** Argon2id baseline with per-kit salt; XChaCha20-Poly1305; authenticated versioned manifest; kit/passphrase separation; monotonic archive/version checks.

**Specification-only future Guardian controls:** encrypted Guardian shares; threshold approval; waiting period; all-device notification. These controls are not shipped and must not be included in current assurance claims.

**Residual risk:** the 256 MiB/t=3/p=1 baseline is not a universal safe value. Weak user passphrases remain dangerous. A future Guardian implementation would add threshold-collusion and ceremony risks. Losing every currently implemented recovery path is intentionally unrecoverable globally.

### 6.9 Parser and resource-exhaustion attacks

**Threat:** hostile JSON-LD Contexts, decompression bombs, huge Argon2 parameters, cyclic data, malformed archives, or oversized HTTP bodies cause code execution, SSRF, or denial of service.

**Controls:** input size/depth/time limits; no arbitrary remote Context loading during verification; pinned immutable Context hashes; KDF upper and lower bounds before allocation; streaming/decompression limits; schema validation; deny unknown critical fields; fuzzing.

**Residual risk:** language memory safety does not prevent logic or resource exhaustion bugs. Native and frontend dependencies remain in scope for review.

### 6.10 Supply-chain and release compromise

**Threat:** a dependency, build environment, updater, or GitHub account publishes malicious Wallet binaries.

**Controls:** locked dependencies; least-privilege automation; review protection; dependency and license scans; source-to-artifact provenance; signed tags/checksums; reproducibility checks; no production secrets in CI.

**Residual risk:** the initial project has not established a reproducible-build guarantee or external release witness.

### 6.11 Misleading consent and dark patterns

**Threat:** a Verifier asks for excess claims or hides retention, onward sharing, and linkability behind technical language.

**Controls:** signed mandatory `ci_request`; plain-language purpose; claim-by-claim disclosure; safe defaults; no preselected consent; accessibility; strong cross-community warning; local Receipt.

**Residual risk:** users can still be coerced or fatigued into consent. A malicious Verifier can violate a declared retention policy after receiving data.

## 7. Assurance status

| Control area | Specification | Reference implementation | External assurance |
| --- | --- | --- | --- |
| Persona and key separation | Defined | Experimental | Not audited |
| CI-Core `eddsa-jcs-2022` VC proof | Developer Preview | Experimental | Interop pending |
| Holder binding | Defined | Experimental | Negative tests pending independent review |
| Recovery Kit | Defined | Experimental | Parameter and parser audit pending |
| Device revocation | Defined | Experimental | Multi-device interop pending |
| Operator migration | Defined | Experimental | Failure-injection exercise pending |
| CI-Private-BBS | Experimental | Not a required MVP feature | Upstream CR + interop pending |
| Guardian Recovery | Experimental future design; outside CI-Core conformance | Not shipped | Implementation and ceremony audit pending |
| Supply-chain provenance | Runbook defined | Bootstrap stage | Reproducibility pending |

No row may be upgraded to “audited” without a report that identifies the commit, scope, exclusions, findings, remediation commits, and retest result.

## 8. Production gate

Before any real-person deployment, all of the following are required:

1. Frozen protocol/profile versions and immutable Contexts/Schemas.
2. Independent architecture, cryptography, application, privacy, and supply-chain audit.
3. Remediation and independent retest of all critical/high findings.
4. Two independently developed Wallet/Issuer/Verifier implementations passing shared vectors.
5. Device loss, status outage, Operator migration, key compromise, and recovery exercises.
6. Legal basis, data-retention policy, user support, incident owner, and breach notification plan.
7. Accessible UX research showing consent and linkability warnings are understood.
8. A deployment-specific threat model; this generic document is not enough.

Use the [security audit runbook](runbooks/security-audit.md) to create the evidence package.

## 9. Review triggers

Review this model whenever a cryptosuite/profile changes; remote Context loading is introduced; a production deployment is proposed; export/recovery format changes; a cloud, telemetry, updater, or biometric dependency is added; or a security incident changes an assumption.
